# Cert Generator

A Windows desktop tool for creating Certificate Authorities and issuing self-signed certificates for posture demos. Built with Python, Flask, and pywebview.

## Features

- **Create Certificate Authorities** with configurable domain, name, algorithm, and lifetime
- **Intermediate CAs** — create subordinate CAs from any root CA; intermediates can issue their own certificates
- **Issue leaf certificates** signed by any CA (root or intermediate), with SAN (Subject Alternative Name) support including wildcards
- **Certificate templates** matching Windows CA templates — Web Server, Computer, Client Authentication, User (Smart Card Logon), Code Signing, Email (S/MIME) — each with the correct key usage and extended key usage extensions
- **Track all certificates** — view status (active/revoked/expired), details, and metadata
- **Export in multiple formats** — PEM, DER, CRT (.crt), PKCS12 (.pfx)
- **Export parts individually** — full bundle, certificate only, private key only, or full chain (cert + CA)
- **Password-protected exports** — optionally encrypt the private key (PEM) or the whole bundle (PKCS12) with a password (PKCS12 defaults to `changeit` for Windows compatibility)
- **Optional CA chain inclusion** — choose whether to bundle the issuing CA certificate when exporting issued certs
- **In-app import guide** — step-by-step instructions for importing certificates on Windows, macOS, and Linux for each template type
- **Modern crypto algorithms** — Ed25519, ECDSA P-256, ECDSA P-384, RSA-2048, RSA-4096
- **Revoke certificates** to mark them as no longer trusted
- **Offline CRL generation** — optionally embed a CRL Distribution Point in issued certificates and export a signed CRL file for manual import into Windows certificate stores, providing offline revocation status without a live server
- **SSH key generation** — generate Ed25519, ECDSA P-256/P-384, and RSA-2048/4096 SSH key pairs with optional passphrase protection
- **SSH key export** — download private keys in OpenSSH or PEM (PKCS#8) format, copy public keys, or copy private keys for Bitwarden SSH import
- **Database encryption** — encrypt all private keys at rest with AES-256-GCM using a master password derived via Scrypt; unlock screen on startup when enabled
- **Backup and restore** — export all data (CAs, certificates, SSH keys) to an AES-256 encrypted `.certbak` file; restore replaces all data from a backup
- **Native Windows app** — runs as a desktop window via pywebview, no browser needed
- **Standalone EXE** — package as a single-file Windows executable, no Python required to run it

## Requirements

- Python 3.10+
- Windows 10/11

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Standalone EXE (recommended)

Build a single-file Windows EXE:

```bash
pip install pyinstaller
python build.py
```

The EXE is written to `dist/CertGenerator.exe`. Double-click to run — no Python installation needed on the target machine.

### Desktop app (from source)

```bash
python -m app.main
```

This opens a native window with the full UI.

### Development server (browser)

```bash
flask --app app.server run --port 5174
```

Then open `http://localhost:5174` in your browser. The development server does not enforce app token authentication, so it is accessible from any browser. Do not use this mode in production.

## Server hardening

The embedded web server is hardened for desktop use:

- **Loopback only** — binds to `127.0.0.1`, never exposed to the network
- **Random port** — uses an ephemeral port each launch, not a fixed port
- **App token authentication** — a random token is generated at startup and set as an httpOnly cookie via the pywebview window; requests without the cookie are rejected with 403, preventing access from other browsers on the same machine
- **CSRF protection** — POST/DELETE/PUT requests must originate from the bound address
- **Auto-shutdown** — the server thread is daemonic and shuts down when the window closes
- **Clean exit** — `sys.exit(0)` after the UI closes ensures proper cleanup

### Quick start

1. Launch the app
2. Click **+ CA** and enter a domain name (e.g. `example.com`) and lifetime
3. Select your CA in the sidebar
4. Click **+ Issue Certificate** to generate leaf certs
5. Use **Export** to download certificates in your preferred format
6. Click **+ SSH Key** to generate an SSH key pair

## Supported algorithms

| Algorithm | Key type | Hash |
|-----------|----------|------|
| Ed25519 | EdDSA | Built-in |
| ECDSA P-256 | Elliptic curve | SHA-256 |
| ECDSA P-384 | Elliptic curve | SHA-384 |
| RSA-2048 | RSA | SHA-256 |
| RSA-4096 | RSA | SHA-384 |

## Export formats

| Format | Extension | Contents |
|--------|-----------|----------|
| PEM | `.pem` | Base64-encoded, widely supported |
| DER | `.der` | Binary format |
| CRT | `.crt` | DER-encoded with Windows-native extension |
| PKCS12 | `.pfx` | Bundled cert + key, optional password protection |

Export options per certificate:
- **Certificate + Key** — full bundle
- **Certificate Only** — public certificate
- **Private Key Only** — private key
- **Full Chain** — leaf cert + issuing CA cert + root CA cert (PEM only, for leaf certs)

## Data storage

All CAs, certificates, and SSH keys are stored in a SQLite database at `~/.cert-generator/certs.db`. The directory is created with restrictive permissions (owner-only access). When database encryption is enabled, all private keys are encrypted at rest with AES-256-GCM using a master password.

## Version history

### v1.4.0 — 2026-09-01

- **SSH key management** — generate, store, export, and copy SSH key pairs (RSA 4096/2048, Ed25519, ECDSA P-256/P-384) with optional passphrase protection; in-app SSH guide with tabs for Bitwarden, Linux/macOS, Windows, and GitHub/GitLab
- **Database encryption at rest** — encrypt all private keys (CA, certificate, and SSH) with AES-256-GCM using a master password derived via Scrypt; unlock screen on startup, password change, and disable/re-enable support
- **Backup and restore** — export all CAs, certificates, and SSH keys to a single AES-256 encrypted `.certbak` file; restore replaces all data from a backup
- **App token authentication** — the pywebview app now generates a random session token and sets it as an httpOnly cookie, rejecting requests from any other browser on the same machine
- **Collapsible sidebar sections** — Certificate Authorities and SSH Keys sections can be collapsed/expanded, with item counts
- Added `bcrypt` dependency (required by `cryptography` for SSH key passphrase encryption)
- Upgraded `cryptography` from 44.0.3 to 50.0.1 (8 CVE fixes)
- Upgraded `flask` from 3.1.1 to 3.1.3 (1 CVE fix)

### v1.3.0 — 2026-08-31

- **User certificate template** — Client Authentication + Smart Card Logon EKU, with Microsoft UPN OtherName in the SAN and email address in subject/SAN, for Windows smart card logon, 802.1X, and VPN use cases
- **CRT export format** — DER-encoded `.crt` files that Windows recognizes natively (double-click to view or import); available for both CA and leaf certificate exports
- **Offline CRL generation** — opt-in "Include CRL Distribution Point" checkbox when issuing certificates embeds a CDP extension with a placeholder URL; "Export CRL" button on the CA page generates a signed `.crl` file for manual import into the Windows certificate store, providing offline revocation status without a live CRL/OCSP server
- Added User and CRL (Revocation) tabs to the in-app import guide
- Revoke endpoint now returns a reminder to re-export the CRL

### v1.2.1 — 2026-08-26

- Added a GitHub Repo link in the sidebar, opening in the system's default browser
- Exposed a `js_api` (`open_external`) from the pywebview window, restricted to an https-only, github.com-only allowlist

### v1.2.0 — 2026-08-26

- Fixed PKCS12 export for Windows — PFX files now use `BestAvailableEncryption` with a password (default: `changeit`) instead of `NoEncryption()`, which Windows rejected
- Optional CA chain inclusion — issued cert exports no longer bundle the CA certificate by default; an "Include CA chain" checkbox lets you opt in
- In-app import guide — tabbed guide with step-by-step instructions for each certificate template (Computer, Web Server, Client Auth, Code Signing, Email) covering Windows, macOS, and Linux
- Added Windows certificate store tip explaining that the import wizard shows only "Personal" (not "Personal > Certificates") and this is expected
- PKCS12 is now the default export format for both CA and issued certificate exports
- Password field pre-filled with default and visible `(default: changeit)` label on both CA and cert export UIs
- Refined delete button styling — outlined ghost style instead of solid red

### v1.1.0 — 2026-08-25

- Intermediate CA support — create subordinate CAs from any root CA that can issue their own certificates
- Hierarchical sidebar tree view showing root and intermediate CAs
- Full chain export now includes the complete chain (leaf + intermediate + root)
- Cascade delete — removing a root CA also deletes its intermediates and their certificates
- Days/Years unit selector for certificate lifetime inputs
- Fixed export/download — certificates now save directly to the Downloads folder
- Fixed responsive layout issues with header wrapping and modal clipping
- Sanitized export filenames to prevent path traversal
- Replaced `os._exit(0)` with `sys.exit(0)` for proper cleanup on exit

### v1.0.0 — 2026-08-25

First stable release with a distributable Windows EXE.

- Certificate templates (Web Server, Computer, Client Auth, Code Signing, Email) with correct X.509 extensions
- Password-protected exports for PEM private keys and PKCS12 bundles
- Hardened embedded server: random ephemeral port, loopback-only, CSRF origin check, clean shutdown on window close
- Standalone single-file Windows EXE via PyInstaller (`build.py`)
- App icon
- Responsive UI layout for narrow window widths

### v0.1.0 — 2026-08-25

Initial release.

- Certificate Authority creation with configurable domain, name, algorithm, and lifetime
- Leaf certificate issuance with SAN and wildcard support
- Certificate tracking with status display (active/revoked/expired)
- Export to PEM, DER, and PKCS12 formats with part selection
- Support for Ed25519, ECDSA P-256/P-384, and RSA-2048/4096
- Certificate revocation
- Dark-themed web UI with native Windows desktop wrapper (pywebview)
- SQLite-backed persistent storage
