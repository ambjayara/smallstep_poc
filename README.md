# Windows TPM → step-ca (ACME device-attest-01) PoC (Go Client)

This repository contains a **Go-based proof of concept (PoC)** client that interacts with a **Smallstep step-ca** ACME provisioner configured for **device-attest-01** using **TPM attestation (fmt=tpm)** on **Windows**.

The goal of this PoC is to validate the **end-to-end ACME device-attestation flow** using TPM-backed keys and attestation objects.

---

## What the PoC Does

✅ Implements the ACME flow:
- Fetches the ACME directory (`/directory`)
- Creates or reuses an ACME account (`newAccount`)
- Creates an order using a `permanent-identifier` (device ID)
- Fetches authorization (`authz`)
- Locates the `device-attest-01` challenge
- Computes the `keyAuthorization`
- Submits an `attObj` (TPM attestation object) to the challenge endpoint
- Attempts order finalization using a CSR
- Certificate fetched and saved

---

## Current Status / Limitations

⚠️ **Expected PoC limitations**

- The ACME flow completes **up to challenge submission**
- Attestation verification may fail if:
  - The client does not generate a **fully valid TPM/WebAuthn attestation object**
  - The `x5c` certificate chain does not validate against the configured attestation roots

### Common Errors You May See
- `badAttestationStatement: ver not present`
- `badAttestationStatement: x5c not present`
- `x509: certificate signed by unknown authority`
- `no root CA bundle available to verify the attestation certificate`

These indicate **attestation root or object mismatches**, not ACME flow issues.

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
