# Windows TPM → step-ca (ACME device-attest-01) PoC (Go Client)

This repo contains a **minimal Go client PoC** that talks to a **Smallstep step-ca** ACME provisioner configured for **device-attest-01** with **TPM (fmt=tpm)**.

✅ What it does today
- Calls ACME directory (`/directory`)
- Creates/uses an ACME account (`newAccount`)
- Creates an order for a `permanent-identifier` (device ID)
- Fetches authorization (`authz`)
- Finds the `device-attest-01` challenge
- Computes `keyAuthorization`
- Posts an `attObj` in the challenge response (currently **PoC/placeholder** attestation object)

⚠️ Current status / limitation
- The PoC can complete ACME flow up to challenge submission, but **TPM attestation verification fails** because the client is not yet producing a real Windows TPM WebAuthn attestation object (or the `x5c` chain doesn’t match configured roots).
- Expected failures include:
  - `badAttestationStatement: ver not present`
  - `badAttestationStatement: x5c not present`
  - `x5c is not valid: x509: certificate signed by unknown authority`
  - server-side `no root CA bundle available to verify the attestation certificate` (when provisioner roots not configured)

---

## Repo structure (example)
- `main.go` – Go client (ACME + JWS + challenge flow)
- (optional) `go.mod`, `go.sum`

---

## Requirements

### Client machine (Windows)
- Windows 10/11
- Go installed (recommended Go 1.21+)
- step-ca running locally (or reachable URL)
- Network access to step-ca URL (default: `https://localhost:9000`)
- TPM present/enabled (optional for now; required for real attestation)
  - Run:
    ```powershell
    Get-Tpm
    ```

### Server (step-ca)
- step-ca running with an **ACME provisioner** that enables:
  - `challenges: ["device-attest-01"]`
  - `attestationFormats: ["tpm"]`
  - `attestationRoots` configured (TPM root CA bundle)

---

## Running step-ca locally (example)

> If you already have a step-ca authority created, you can just run it.

1) Start step-ca
```powershell
step-ca --password-file <path-to-password-file>
# or whatever you use to start it on your setup
