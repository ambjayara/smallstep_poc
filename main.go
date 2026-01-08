package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================
// CONFIG
// ============================

const acmeDirectoryURL = "https://localhost:9000/acme/acme-device-attest-tpm/directory"
const permanentIdentifier = "LAPTOP-FGSJG1FU"

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

func acmePOST(ctx context.Context, urlStr, jws string) (*postResult, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", urlStr, io.NopCloser(stringsNewReader(jws)))
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

// minimal string reader without importing strings
type stringReader struct {
	s string
	i int
}

func stringsNewReader(s string) *stringReader { return &stringReader{s: s} }

func (r *stringReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
func (r *stringReader) Close() error { return nil }

// ============================
// Debug: decode attestationObject
// ============================

func dumpAttObj(attObj []byte) {
	var m map[string]any
	if err := cbor.Unmarshal(attObj, &m); err != nil {
		fmt.Println("CBOR decode failed:", err)
		return
	}
	fmt.Println("---- AttestationObject decoded ----")
	fmt.Printf("attObj.fmt = %v\n", m["fmt"])

	attStmt, ok := m["attStmt"].(map[string]any)
	if !ok {
		fmt.Println("attStmt missing or not a map")
		return
	}

	fmt.Print("attStmt keys: ")
	first := true
	for k := range attStmt {
		if !first {
			fmt.Print(", ")
		}
		fmt.Print(k)
		first = false
	}
	fmt.Println()
	fmt.Printf("attStmt.ver = %v\n", attStmt["ver"])
	fmt.Println("----------------------------------")
}

// ============================
// CSR placeholder (NOT TPM bound)
// ============================

func buildSoftwareCSR() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "win-device-poc"},
	}, key)
	if err != nil {
		return "", err
	}
	return b64url(csrDER), nil
}

// ============================
// MAIN
// ============================

func main() {
	ctx := context.Background()

	var dir directory
	if err := httpGetJSON(ctx, acmeDirectoryURL, &dir); err != nil {
		panic(err)
	}
	fmt.Println("ACME directory loaded")
	fmt.Println("  newNonce:", dir.NewNonce)
	fmt.Println("  newAccount:", dir.NewAccount)
	fmt.Println("  newOrder:", dir.NewOrder)

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

	// Fetch authz (POST-as-GET)
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

	// Find device-attest-01
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

	// ✅ Windows WebAuthn attestationObject (CBOR bytes)
	// attObjBytes, err := MakeWindowsAttestationObject(keyAuth)
	// if err != nil {
	// 	panic(err)
	// }
	// dumpAttObj(attObjBytes)

	attObjB64, err := buildTPMAttObjCBORMinimal()
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
	// payload = map[string]any{
	// 	"attObj": b64url(attObjBytes),
	// }
	payload = map[string]any{"attObj": attObjB64}

	jws = jwsSignES256(acctKey, protected, payload)
	chRes, err := acmePOST(ctx, ch.URL, jws)
	if err != nil {
		panic(err)
	}
	fmt.Println("Challenge POST status:", chRes.Status)
	fmt.Println(string(chRes.Body))

	// Finalize (will fail unless challenge becomes valid)
	csrB64, err := buildSoftwareCSR()
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
}

// buildTPMAttObjCBORMinimal returns a syntactically valid WebAuthn attestationObject (CBOR).
// It satisfies server "presence" checks for TPM fields step-by-step.
// NOTE: This is still NOT a valid TPM attestation, and will fail on later verification steps.
func buildTPMAttObjCBORMinimal() (string, error) {
	dummyCertDER, err := makeDummyX5CDER()
	if err != nil {
		return "", err
	}

	attObj := map[string]any{
		"fmt":      "tpm",
		"authData": []byte{}, // empty (still fake)
		"attStmt": map[string]any{
			"ver": "2.0",

			// x5c must be an array of DER cert bytes (CBOR byte strings).
			// We put a dummy self-signed cert to satisfy "x5c present".
			"x5c": []any{dummyCertDER},
		},
	}

	b, err := cbor.Marshal(attObj)
	if err != nil {
		return "", err
	}
	return b64url(b), nil
}

// makeDummyX5CDER creates a valid self-signed certificate (DER bytes).
// This is ONLY to satisfy the "x5c present" check on the server.
// It is NOT a real TPM attestation certificate, so verification will still fail later.
func makeDummyX5CDER() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dummy-x5c-for-poc"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		// Mark as CA so it's structurally valid (not required, but fine for POC)
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return der, nil
}
