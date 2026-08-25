# Cert Generator

A Windows desktop tool for creating Certificate Authorities and issuing self-signed certificates for posture demos. Built with Python, Flask, and pywebview.

## Features

- **Create Certificate Authorities** with configurable domain, name, algorithm, and lifetime
- **Issue leaf certificates** signed by your CA, with SAN (Subject Alternative Name) support including wildcards
- **Track all certificates** — view status (active/revoked/expired), details, and metadata
- **Export in multiple formats** — PEM, DER, PKCS12 (.pfx)
- **Export parts individually** — full bundle, certificate only, private key only, or full chain (cert + CA)
- **Modern crypto algorithms** — Ed25519, ECDSA P-256, ECDSA P-384, RSA-2048, RSA-4096
- **Revoke certificates** to mark them as no longer trusted
- **Native Windows app** — runs as a desktop window via pywebview, no browser needed

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

Then open `http://localhost:5174` in your browser.

## Server hardening

The embedded web server is hardened for desktop use:

- **Loopback only** — binds to `127.0.0.1`, never exposed to the network
- **Random port** — uses an ephemeral port each launch, not a fixed port
- **CSRF protection** — POST/DELETE/PUT requests must originate from the bound address
- **Auto-shutdown** — the server thread is daemonic and shuts down when the window closes
- **Process exit** — `os._exit(0)` ensures no orphan threads survive after the UI closes

### Quick start

1. Launch the app
2. Click **+ New CA** and enter a domain name (e.g. `example.com`) and lifetime
3. Select your CA in the sidebar
4. Click **+ Issue Certificate** to generate leaf certs
5. Use **Export** to download certificates in your preferred format

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
| PKCS12 | `.pfx` | Bundled cert + key, optional password protection |

Export options per certificate:
- **Certificate + Key** — full bundle
- **Certificate Only** — public certificate
- **Private Key Only** — private key
- **Full Chain** — leaf cert + CA cert (PEM only, for leaf certs)

## Data storage

All CAs and certificates are stored in a SQLite database at `~/.cert-generator/certs.db`. The directory is created with restrictive permissions (owner-only access).

## Version history

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
