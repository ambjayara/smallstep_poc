// main.go
//
// Smallstep ACME device-attest-01 (TPM) POC — Challenge VALID + Finalize CSR match
//
// Fixes:
// 1) Challenge: uses real-ish TPM attestationObject
//    - authData includes COSE key for the credential key
//    - attStmt.pubArea is RAW TPMT_PUBLIC for credential key
//    - attStmt.certInfo + sig from Certify(credential <- AK)
//    - x5c contains AK certificate chain (AK public key inside leaf)
// 2) Finalize: CSR MUST match attested credential key AND CN must match identifier exactly
//    - CSR is signed with TPM credential key (TPM-backed crypto.Signer)
//    - CSR Subject CN = permanentIdentifier
//
// Dependencies:
//   go get github.com/fxamacker/cbor/v2
//   go get github.com/google/go-tpm
//
// Files required:
//   C:\Projects\certs\tpm-attest-root.crt
//   C:\Projects\certs\tpm-attest-int.crt
//   C:\Projects\certs\tpm-attest-int.key
//
// step-ca provisioner:
//   - attestationRoots must be a FILE PATH to a PEM bundle that validates x5c chain.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// ============================
// CONFIG
// ============================

const (
	acmeDirectoryURL = "https://localhost:9000/acme/acme-device-attest-tpm/directory"
	//acmeDirectoryURL    = "https://k8s-stepcans-acmeserv-80b68ccb17-ce6933e911ae6e02.elb.us-east-1.amazonaws.com/acme/win-acme-tpm/directory" //"https://localhost:9000/acme/acme-device-attest-tpm/directory"
	permanentIdentifier = "LAPTOP-FGSJG1FU"

	attestRootPath        = "C:\\Projects\\certs\\tpm-attest-root.crt"
	attestIntermediate    = "C:\\Projects\\certs\\tpm-attest-int.crt"
	attestIntermediateKey = "C:\\Projects\\certs\\tpm-attest-int.key"

	// WebAuthn rpId used for rpIdHash in authData
	webauthnRPID = "localcontext"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

// ============================
// ACME types
// ============================

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type orderReq struct {
	Identifiers []identifier `json:"identifiers"`
}

type orderResp struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate,omitempty"`
}

type authzResp struct {
	Identifier identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Challenges []challenge `json:"challenges"`
	Expires    string      `json:"expires"`
}

type challenge struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Token  string `json:"token"`
	URL    string `json:"url"`
}

type finalizeReq struct {
	CSR string `json:"csr"`
}

// ============================
// base64url + JSON
// ============================

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
}

// ============================
// JWS (ES256)
// ============================

func jwkFromKey(priv *ecdsa.PrivateKey) map[string]string {
	x := priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := priv.PublicKey.Y.FillBytes(make([]byte, 32))
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(x),
		"y":   b64url(y),
	}
}

func jwkThumbprintES256(priv *ecdsa.PrivateKey) string {
	jwk := jwkFromKey(priv)
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return b64url(sum[:])
}

func jwsSignES256(priv *ecdsa.PrivateKey, protected any, payload any) string {
	protectedJSON := mustJSON(protected)

	var payloadJSON []byte
	if payload == nil {
		payloadJSON = []byte{} // POST-as-GET
	} else {
		payloadJSON = mustJSON(payload)
	}

	signingInput := b64url(protectedJSON) + "." + b64url(payloadJSON)
	h := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	rb := r.FillBytes(make([]byte, 32))
	sb := s.FillBytes(make([]byte, 32))
	sig := append(rb, sb...)

	jwsObj := map[string]string{
		"protected": b64url(protectedJSON),
		"payload":   b64url(payloadJSON),
		"signature": b64url(sig),
	}
	return string(mustJSON(jwsObj))
}

// ============================
// HTTP helpers
// ============================

func httpGetJSON(ctx context.Context, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s -> %d: %s", u, resp.StatusCode, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func httpHeadNonce(ctx context.Context, u string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "HEAD", u, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no Replay-Nonce from %s", u)
	}
	return nonce, nil
}

type postResult struct {
	Status   int
	Body     []byte
	Location string
}

func acmePOST(ctx context.Context, urlStr string, jws string) (*postResult, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader([]byte(jws)))
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return &postResult{
		Status:   resp.StatusCode,
		Body:     body,
		Location: resp.Header.Get("Location"),
	}, nil
}

// ============================
// PEM readers (STATIC CA MATERIAL)
// ============================

func readPEMCertToDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block in %s", path)
	}
	return block.Bytes, nil
}

func readPEMECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	// step keys can be PKCS8
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key in %s is not ECDSA", path)
		}
		return ec, nil
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// ============================
// TPM key templates (RSA)
// ============================

// Parent key (EK-like): RESTRICTED DECRYPT
func ekLikeRSAPublicTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt |
			tpm2.FlagRestricted |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgNull, Hash: tpm2.AlgNull},
			KeyBits: 2048,
		},
	}
}

// AK: RESTRICTED SIGNING (correct for TPM attestation)
func akRSAPublicTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign |
			tpm2.FlagRestricted |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgNull},
			Sign:      &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits:   2048,
		},
	}
}

// Credential key: UNRESTRICTED SIGNING (this is the WebAuthn credential key)
func credentialRSAPublicTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | // ✅ sign-capable
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgNull},
			Sign:      &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits:   2048,
		},
	}
}

// ============================
// WebAuthn helpers (authData + COSE key)
// ============================

// authData layout:
// rpIdHash(32) || flags(1) || signCount(4) || attestedCredData...
func buildAuthData(rpID string, credentialID []byte, coseKeyBytes []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))

	flags := byte(0)
	flags |= 0x01 // UP
	flags |= 0x40 // AT

	signCount := uint32(1)

	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, signCount)

	// AAGUID (16) zeros
	buf.Write(make([]byte, 16))

	_ = binary.Write(&buf, binary.BigEndian, uint16(len(credentialID)))
	buf.Write(credentialID)

	// COSE_Key bytes (CBOR)
	buf.Write(coseKeyBytes)

	return buf.Bytes()
}

// COSE key for RSA (kty=3). alg=-257 (RS256).
func coseKeyRSA(pub *rsa.PublicKey) ([]byte, error) {
	m := map[int]any{
		1:  3,    // kty RSA
		3:  -257, // alg RS256
		-1: pub.N.Bytes(),
		-2: big.NewInt(int64(pub.E)).Bytes(),
	}
	return cbor.Marshal(m)
}

// ============================
// AK certificate leaf signed by your intermediate
// ============================

var (
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

func buildSANWithTPMAttrs(manufacturer, model, version string) ([]pkix.Extension, error) {
	rdn := pkix.RDNSequence{
		{
			pkix.AttributeTypeAndValue{Type: oidTPMManufacturer, Value: manufacturer},
			pkix.AttributeTypeAndValue{Type: oidTPMModel, Value: model},
			pkix.AttributeTypeAndValue{Type: oidTPMVersion, Value: version},
		},
	}

	dirNameDER, err := asn1.Marshal(rdn)
	if err != nil {
		return nil, err
	}

	// directoryName [4] EXPLICIT Name
	generalNameDirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      dirNameDER,
	}

	sanValue, err := asn1.Marshal([]asn1.RawValue{generalNameDirName})
	if err != nil {
		return nil, err
	}

	oidSubjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}
	ext := pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: false,
		Value:    sanValue,
	}
	return []pkix.Extension{ext}, nil
}

func makeAKLeafSignedByIntermediate(intCertDER []byte, intKey *ecdsa.PrivateKey, akPub crypto.PublicKey) ([]byte, error) {
	intCert, err := x509.ParseCertificate(intCertDER)
	if err != nil {
		return nil, err
	}

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{}, // MUST be empty for AK cert (step-ca check)

		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),

		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,

		// tcg-kp-AIKCertificate (2.23.133.8.3)
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}},
	}

	// If step-ca requires these, set correct values
	sanExts, err := buildSANWithTPMAttrs("id:54534700", "id:00000000", "id:00010000")
	if err != nil {
		return nil, err
	}
	leafTpl.ExtraExtensions = append(leafTpl.ExtraExtensions, sanExts...)

	return x509.CreateCertificate(rand.Reader, leafTpl, intCert, akPub, intKey)
}

// ============================
// TPM-backed crypto.Signer for CSR
// ============================

type tpmRSASigner struct {
	rw        io.ReadWriter
	handle    tpmutil.Handle
	auth      string
	pub       *rsa.PublicKey
	sigScheme *tpm2.SigScheme
}

func (s *tpmRSASigner) Public() crypto.PublicKey { return s.pub }

func (s *tpmRSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Force RSASSA+SHA256 for this POC.
	// x509 CSR wants the raw PKCS#1 v1.5 signature bytes.
	sig, err := tpm2.Sign(s.rw, s.handle, s.auth, digest, nil, s.sigScheme)
	if err != nil {
		return nil, err
	}
	if sig == nil || sig.RSA == nil {
		return nil, fmt.Errorf("TPM returned non-RSA signature")
	}
	return sig.RSA.Signature, nil
}

// CSR using TPM credential key (CN must match identifier exactly)
func buildTPMCSR(commonName string, signer crypto.Signer) (string, error) {
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName, // ✅ must match permanentIdentifier
		},
		// Keep SAN empty unless your CA requires something else.
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, signer)
	if err != nil {
		return "", err
	}
	return b64url(csrDER), nil
}

// ============================
// TPM session context we keep alive across Challenge+Finalize
// ============================

type tpmSession struct {
	rwc io.ReadWriteCloser
	rw  io.ReadWriter

	ekHandle   tpmutil.Handle
	akHandle   tpmutil.Handle
	credHandle tpmutil.Handle

	akCryptoPub   *rsa.PublicKey
	credCryptoPub *rsa.PublicKey

	credPubAreaTPMTPublic []byte // RAW TPMT_PUBLIC for attStmt.pubArea
}

func openTPMSession() (*tpmSession, error) {
	rwc, err := tpm2.OpenTPM() // your windows wrapper (no args)
	if err != nil {
		return nil, fmt.Errorf("OpenTPM: %w", err)
	}
	s := &tpmSession{rwc: rwc, rw: rwc}

	// Create primary (parent)
	ekHandle, _, err := tpm2.CreatePrimary(
		s.rw,
		tpm2.HandleEndorsement,
		tpm2.PCRSelection{},
		"",
		"",
		ekLikeRSAPublicTemplate(),
	)
	if err != nil {
		_ = rwc.Close()
		return nil, fmt.Errorf("CreatePrimary: %w", err)
	}
	s.ekHandle = ekHandle

	// Create + Load AK (restricted signing)
	akPriv, akPubBlob, _, _, _, err := tpm2.CreateKey(s.rw, s.ekHandle, tpm2.PCRSelection{}, "", "", akRSAPublicTemplate())
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("CreateKey(AK): %w", err)
	}
	akHandle, _, err := tpm2.Load(s.rw, s.ekHandle, "", akPubBlob, akPriv)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("Load(AK): %w", err)
	}
	s.akHandle = akHandle

	akPub, _, _, err := tpm2.ReadPublic(s.rw, s.akHandle)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ReadPublic(AK): %w", err)
	}
	if akPub.RSAParameters == nil {
		s.Close()
		return nil, fmt.Errorf("AK is not RSA")
	}
	akMod := akPub.RSAParameters.Modulus().Bytes()
	if len(akMod) == 0 {
		s.Close()
		return nil, fmt.Errorf("AK modulus empty")
	}
	s.akCryptoPub = &rsa.PublicKey{N: new(big.Int).SetBytes(akMod), E: 65537}

	// Create + Load credential key (UNRESTRICTED signing)
	credPriv, credPubBlob, _, _, _, err := tpm2.CreateKey(s.rw, s.ekHandle, tpm2.PCRSelection{}, "", "", credentialRSAPublicTemplate())
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("CreateKey(cred): %w", err)
	}
	credHandle, _, err := tpm2.Load(s.rw, s.ekHandle, "", credPubBlob, credPriv)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("Load(cred): %w", err)
	}
	s.credHandle = credHandle

	credPubFromTPM, _, _, err := tpm2.ReadPublic(s.rw, s.credHandle)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ReadPublic(cred): %w", err)
	}
	credTPMTPublic, err := credPubFromTPM.Encode()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("Encode(cred TPMT_PUBLIC): %w", err)
	}
	s.credPubAreaTPMTPublic = credTPMTPublic

	if credPubFromTPM.RSAParameters == nil {
		s.Close()
		return nil, fmt.Errorf("credential key not RSA")
	}
	credMod := credPubFromTPM.RSAParameters.Modulus().Bytes()
	if len(credMod) == 0 {
		s.Close()
		return nil, fmt.Errorf("credential modulus empty")
	}
	s.credCryptoPub = &rsa.PublicKey{N: new(big.Int).SetBytes(credMod), E: 65537}

	return s, nil
}

func (s *tpmSession) Close() {
	if s == nil {
		return
	}
	// Best-effort flush
	if s.credHandle != 0 {
		_ = tpm2.FlushContext(s.rw, s.credHandle)
	}
	if s.akHandle != 0 {
		_ = tpm2.FlushContext(s.rw, s.akHandle)
	}
	if s.ekHandle != 0 {
		_ = tpm2.FlushContext(s.rw, s.ekHandle)
	}
	if s.rwc != nil {
		_ = s.rwc.Close()
	}
}

// ============================
// Build TPM-backed attestationObject (fmt=tpm)
// ============================

func buildTPMAttObjCBOR_SmallstepTPM(sess *tpmSession, keyAuthorization string, rpID string) (string, error) {
	// COSE key for credential key
	coseKeyBytes, err := coseKeyRSA(sess.credCryptoPub)
	if err != nil {
		return "", fmt.Errorf("COSE key: %w", err)
	}

	// authData
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return "", err
	}
	authData := buildAuthData(rpID, credID, coseKeyBytes)

	// qualifyingData binding (simple PoC)
	clientDataHash := sha256.Sum256([]byte(keyAuthorization))

	// IMPORTANT: legacy Certify signature:
	// Certify(rw, objectAuth, signerAuth, objectHandle, signerHandle, qualifyingData)
	certInfo, sigBytes, err := tpm2.Certify(
		sess.rw,
		"",                // objectAuth (cred)
		"",                // signerAuth (ak)
		sess.credHandle,   // object being certified ✅
		sess.akHandle,     // signer ✅
		clientDataHash[:], // qualifyingData
	)
	if err != nil {
		return "", fmt.Errorf("Certify(cred<-ak): %w", err)
	}

	// Build x5c chain (AK cert chain)
	rootDER, err := readPEMCertToDER(attestRootPath)
	if err != nil {
		return "", fmt.Errorf("read root cert: %w", err)
	}
	intDER, err := readPEMCertToDER(attestIntermediate)
	if err != nil {
		return "", fmt.Errorf("read intermediate cert: %w", err)
	}
	intKey, err := readPEMECDSAKey(attestIntermediateKey)
	if err != nil {
		return "", fmt.Errorf("read intermediate key: %w", err)
	}
	leafDER, err := makeAKLeafSignedByIntermediate(intDER, intKey, sess.akCryptoPub)
	if err != nil {
		return "", fmt.Errorf("make AK leaf cert: %w", err)
	}
	x5cChain := []any{leafDER, intDER, rootDER}

	attObj := map[string]any{
		"fmt":      "tpm",
		"authData": authData,
		"attStmt": map[string]any{
			"ver":      "2.0",
			"alg":      int64(-257),                // RS256
			"x5c":      x5cChain,                   // AK chain
			"sig":      sigBytes,                   // by AK
			"certInfo": certInfo,                   // TPMS_ATTEST (RAW)
			"pubArea":  sess.credPubAreaTPMTPublic, // RAW TPMT_PUBLIC for credential key
		},
	}

	b, err := cbor.Marshal(attObj)
	if err != nil {
		return "", err
	}
	return b64url(b), nil
}

// ============================
// MAIN
// ============================

func main() {
	ctx := context.Background()

	// ACME directory
	var dir directory
	if err := httpGetJSON(ctx, acmeDirectoryURL, &dir); err != nil {
		panic(err)
	}
	fmt.Println("ACME directory loaded")
	fmt.Println("  newNonce:", dir.NewNonce)
	fmt.Println("  newAccount:", dir.NewAccount)
	fmt.Println("  newOrder:", dir.NewOrder)

	// Account key
	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	thumb := jwkThumbprintES256(acctKey)

	// newAccount
	nonce, err := httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	protected := map[string]any{
		"alg":   "ES256",
		"jwk":   jwkFromKey(acctKey),
		"nonce": nonce,
		"url":   dir.NewAccount,
	}
	payload := map[string]any{"termsOfServiceAgreed": true}

	jws := jwsSignES256(acctKey, protected, payload)
	accRes, err := acmePOST(ctx, dir.NewAccount, jws)
	if err != nil {
		panic(err)
	}
	if accRes.Status >= 400 {
		panic(fmt.Errorf("newAccount failed: %d %s", accRes.Status, string(accRes.Body)))
	}
	kid := accRes.Location
	fmt.Println("Account created/exists. KID:", kid)

	// newOrder
	nonce, err = httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	orderBody := orderReq{Identifiers: []identifier{{Type: "permanent-identifier", Value: permanentIdentifier}}}
	protected = map[string]any{
		"alg":   "ES256",
		"kid":   kid,
		"nonce": nonce,
		"url":   dir.NewOrder,
	}
	jws = jwsSignES256(acctKey, protected, orderBody)
	orderRaw, err := acmePOST(ctx, dir.NewOrder, jws)
	if err != nil {
		panic(err)
	}
	if orderRaw.Status >= 400 {
		panic(fmt.Errorf("newOrder failed: %d %s", orderRaw.Status, string(orderRaw.Body)))
	}

	var order orderResp
	if err := json.Unmarshal(orderRaw.Body, &order); err != nil {
		panic(err)
	}
	fmt.Println("Order status:", order.Status)
	fmt.Println("Authz URLs:", order.Authorizations)
	fmt.Println("Finalize URL:", order.Finalize)

	// authz (POST-as-GET)
	authzURL := order.Authorizations[0]
	nonce, err = httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	protected = map[string]any{
		"alg":   "ES256",
		"kid":   kid,
		"nonce": nonce,
		"url":   authzURL,
	}
	jws = jwsSignES256(acctKey, protected, nil)
	authzRaw, err := acmePOST(ctx, authzURL, jws)
	if err != nil {
		panic(err)
	}
	if authzRaw.Status >= 400 {
		panic(fmt.Errorf("authz fetch failed: %d %s", authzRaw.Status, string(authzRaw.Body)))
	}

	var authz authzResp
	if err := json.Unmarshal(authzRaw.Body, &authz); err != nil {
		panic(err)
	}
	fmt.Println("Authz status:", authz.Status, "Identifier:", authz.Identifier.Type, authz.Identifier.Value)

	// find device-attest-01
	var ch *challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "device-attest-01" {
			ch = &authz.Challenges[i]
			break
		}
	}
	if ch == nil {
		panic("device-attest-01 challenge not found")
	}

	fmt.Println("Found challenge:")
	fmt.Println("  URL:", ch.URL)
	fmt.Println("  Token:", ch.Token)

	keyAuth := ch.Token + "." + thumb
	fmt.Println("keyAuthorization:", keyAuth)

	// ===== TPM session MUST live across challenge + finalize (CSR signing) =====
	sess, err := openTPMSession()
	if err != nil {
		panic(err)
	}
	defer sess.Close()

	// Build attObj (TPM-backed)
	attObjB64, err := buildTPMAttObjCBOR_SmallstepTPM(sess, keyAuth, webauthnRPID)
	if err != nil {
		panic(err)
	}

	// Respond to challenge
	nonce, err = httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	protected = map[string]any{
		"alg":   "ES256",
		"kid":   kid,
		"nonce": nonce,
		"url":   ch.URL,
	}
	payload = map[string]any{"attObj": attObjB64}

	jws = jwsSignES256(acctKey, protected, payload)
	chRes, err := acmePOST(ctx, ch.URL, jws)
	if err != nil {
		panic(err)
	}
	fmt.Println("Challenge POST status:", chRes.Status)
	fmt.Println(string(chRes.Body))

	// ===== Finalize: CSR must match attested credential key + CN must match identifier =====
	credSigner := &tpmRSASigner{
		rw:        sess.rw,
		handle:    sess.credHandle,
		auth:      "",
		pub:       sess.credCryptoPub,
		sigScheme: &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
	}

	csrB64, err := buildTPMCSR(permanentIdentifier, credSigner)
	if err != nil {
		panic(err)
	}

	nonce, err = httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	protected = map[string]any{
		"alg":   "ES256",
		"kid":   kid,
		"nonce": nonce,
		"url":   order.Finalize,
	}
	jws = jwsSignES256(acctKey, protected, finalizeReq{CSR: csrB64})
	finRes, err := acmePOST(ctx, order.Finalize, jws)
	if err != nil {
		panic(err)
	}
	fmt.Println("Finalize status:", finRes.Status)
	fmt.Println(string(finRes.Body))

	// Parse finalize response to get certificate URL
	var order2 orderResp
	if err := json.Unmarshal(finRes.Body, &order2); err != nil {
		fmt.Println("Finalize response not JSON order? still continuing. err:", err)
		return
	}
	if order2.Certificate == "" {
		fmt.Println("No certificate URL in finalize response (order2.certificate empty).")
		return
	}

	// Fetch certificate (POST-as-GET)
	nonce, err = httpHeadNonce(ctx, dir.NewNonce)
	if err != nil {
		panic(err)
	}
	protected = map[string]any{
		"alg":   "ES256",
		"kid":   kid,
		"nonce": nonce,
		"url":   order2.Certificate,
	}
	jws = jwsSignES256(acctKey, protected, nil) // POST-as-GET

	certRes, err := acmePOST(ctx, order2.Certificate, jws)
	if err != nil {
		panic(err)
	}
	fmt.Println("Certificate fetch status:", certRes.Status)

	// Usually PEM chain
	certPEM := certRes.Body
	fmt.Println(string(certPEM))

	_ = os.WriteFile("issued-cert.pem", certPEM, 0600)
	fmt.Println("Saved certificate to issued-cert.pem")
}

// compile-time sanity
var _ crypto.PublicKey
