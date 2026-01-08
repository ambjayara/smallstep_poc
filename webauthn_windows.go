//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	webauthn                = windows.NewLazySystemDLL("webauthn.dll")
	procMakeCredential      = webauthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procFreeCredAttestation = webauthn.NewProc("WebAuthNFreeCredentialAttestation")
)

// HRESULT success is 0 (S_OK).
func hresultOK(hr uintptr) bool { return hr == 0 }

// Converts HRESULT to a readable Windows message (best-effort).
func hresultMessage(hr uintptr) string {
	flags := uint32(windows.FORMAT_MESSAGE_FROM_SYSTEM | windows.FORMAT_MESSAGE_IGNORE_INSERTS)
	buf := make([]uint16, 1024)
	n, err := windows.FormatMessage(flags, 0, uint32(hr), 0, buf, nil)
	if err != nil || n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

type WEBAUTHN_RP_ENTITY_INFORMATION struct {
	DwVersion uint32
	PwszID    *uint16
	PwszName  *uint16
}

type WEBAUTHN_USER_ENTITY_INFORMATION struct {
	DwVersion       uint32
	CbID            uint32
	PbID            *byte
	PwszName        *uint16
	PwszDisplayName *uint16
}

type WEBAUTHN_COSE_CREDENTIAL_PARAMETER struct {
	DwVersion          uint32
	PwszCredentialType *uint16 // "public-key"
	LAlg               int32   // -7 ES256
}

type WEBAUTHN_COSE_CREDENTIAL_PARAMETERS struct {
	CParams uint32
	PParams *WEBAUTHN_COSE_CREDENTIAL_PARAMETER
}

type WEBAUTHN_CLIENT_DATA struct {
	DwVersion        uint32
	CbClientDataJSON uint32
	PbClientDataJSON *byte
}

type WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS struct {
	DwVersion uint32

	// "direct" or "none"
	PwszAttestationConveyancePreference *uint16

	// "platform" or "" (empty means don't force)
	PwszAuthenticatorAttachment *uint16

	// "preferred" / "required" / "discouraged"
	PwszUserVerificationRequirement *uint16

	DwTimeoutMilliseconds uint32
	DwFlags               uint32
}

type WEBAUTHN_CREDENTIAL_ATTESTATION struct {
	DwVersion uint32

	CbAttestationObject uint32
	PbAttestationObject *byte
}

func utf16Ptr(s string) *uint16 {
	if s == "" {
		return nil
	}
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// MakeWindowsAttestationObject tries to get a WebAuthn attestationObject (CBOR bytes).
// It will try multiple option profiles, because many Windows machines fail with
// attestation "direct" or when forcing "platform".
func MakeWindowsAttestationObject(keyAuthorization string) ([]byte, error) {
	if err := webauthn.Load(); err != nil {
		return nil, fmt.Errorf("webauthn.dll not available: %w", err)
	}

	// Bind ACME -> WebAuthn challenge
	chal := sha256.Sum256([]byte(keyAuthorization))
	chalB64 := base64.RawURLEncoding.EncodeToString(chal[:])

	clientData := map[string]any{
		"type":      "webauthn.create",
		"challenge": chalB64,
		"origin":    "https://localhost",
	}
	clientDataJSON, _ := json.Marshal(clientData)

	rp := WEBAUTHN_RP_ENTITY_INFORMATION{
		DwVersion: 1,
		PwszID:    utf16Ptr("localhost"),
		PwszName:  utf16Ptr("step-ca POC"),
	}

	userID := []byte("poc-user-1")
	user := WEBAUTHN_USER_ENTITY_INFORMATION{
		DwVersion:       1,
		CbID:            uint32(len(userID)),
		PbID:            &userID[0],
		PwszName:        utf16Ptr("poc-user"),
		PwszDisplayName: utf16Ptr("POC User"),
	}

	paramsArr := []WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
		{DwVersion: 1, PwszCredentialType: utf16Ptr("public-key"), LAlg: -7}, // ES256
	}
	params := WEBAUTHN_COSE_CREDENTIAL_PARAMETERS{
		CParams: uint32(len(paramsArr)),
		PParams: &paramsArr[0],
	}

	cd := WEBAUTHN_CLIENT_DATA{
		DwVersion:        1,
		CbClientDataJSON: uint32(len(clientDataJSON)),
		PbClientDataJSON: (*byte)(unsafe.Pointer(&clientDataJSON[0])),
	}

	// Try profiles from strict -> relaxed
	profiles := []struct {
		name        string
		attestation string
		attachment  string
		userVerify  string
		timeoutMs   uint32
	}{
		{"platform+direct+preferred", "direct", "platform", "preferred", 60000},
		{"platform+none+preferred", "none", "platform", "preferred", 60000},
		{"any+none+preferred", "none", "", "preferred", 60000},
		{"any+none+discouraged", "none", "", "discouraged", 60000},
	}

	var lastErr error

	for _, p := range profiles {
		opts := WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS{
			DwVersion:                           1,
			PwszAttestationConveyancePreference: utf16Ptr(p.attestation),
			PwszAuthenticatorAttachment:         utf16Ptr(p.attachment),
			PwszUserVerificationRequirement:     utf16Ptr(p.userVerify),
			DwTimeoutMilliseconds:               p.timeoutMs,
			DwFlags:                             0,
		}

		var att *WEBAUTHN_CREDENTIAL_ATTESTATION

		hr, _, _ := procMakeCredential.Call(
			0, // HWND
			uintptr(unsafe.Pointer(&rp)),
			uintptr(unsafe.Pointer(&user)),
			uintptr(unsafe.Pointer(&params)),
			uintptr(unsafe.Pointer(&cd)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&att)), // out param (**)
		)

		if !hresultOK(hr) {
			msg := hresultMessage(hr)
			if msg != "" {
				lastErr = fmt.Errorf("[%s] HRESULT=0x%08X: %s", p.name, uint32(hr), msg)
			} else {
				lastErr = fmt.Errorf("[%s] HRESULT=0x%08X", p.name, uint32(hr))
			}
			continue
		}

		if att == nil || att.PbAttestationObject == nil || att.CbAttestationObject == 0 {
			lastErr = fmt.Errorf("[%s] success but empty attestationObject", p.name)
			continue
		}

		defer procFreeCredAttestation.Call(uintptr(unsafe.Pointer(att)))

		raw := unsafe.Slice(att.PbAttestationObject, att.CbAttestationObject)
		out := make([]byte, len(raw))
		copy(out, raw)

		fmt.Println("WebAuthn profile succeeded:", p.name)
		return out, nil
	}

	return nil, lastErr
}
