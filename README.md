# Cert Generator

A tool for creating Certificate Authorities and issuing self-signed certificates for posture demos. Runs as a **Docker web app** or a **Windows desktop app** — both use the same interface and database format, and backups created in one mode can be restored in the other.

## Deployment options

| Mode | Best for | How it runs |
|------|----------|-------------|
| **Docker** (recommended) | Servers, shared access | Web app at `http://host:5000` with login authentication |
| **Standalone EXE** | Individual workstations | Native Windows window, no install needed |

Both modes have full feature parity — the same UI, database format, and capabilities. The only differences are how you access it (browser vs native window) and authentication (login vs automatic app token).

## Features

- **Create Certificate Authorities** with configurable domain, name, algorithm, and lifetime
- **Intermediate CAs** — create subordinate CAs from any root CA; intermediates can issue their own certificates (intermediates are issued with path length 0, so they cannot create further CAs)
- **Issue leaf certificates** signed by any CA (root or intermediate), with SAN (Subject Alternative Name) support including wildcards and IP addresses
- **Certificate templates** matching Windows CA templates — Web Server, Computer, Client Authentication, User (Smart Card Logon), Code Signing, Email (S/MIME) — each with the correct key usage and extended key usage extensions
- **Track all certificates** — view status (active/revoked/expired), details, and metadata
- **Export in multiple formats** — PEM, DER, CRT (.crt), PKCS12 (.pfx)
- **Export parts individually** — full bundle, certificate only, private key only, or full chain (cert + CA)
- **Password-protected exports** — optionally encrypt the private key (PEM); PKCS12 bundles always require a password (the export dialog pre-fills `changeit` for Windows compatibility)
- **Optional CA chain inclusion** — choose whether to bundle the issuing CA certificate when exporting issued certs
- **In-app import guide** — step-by-step instructions for importing certificates on Windows, macOS, and Linux for each template type
- **Modern crypto algorithms** — Ed25519, ECDSA P-256, ECDSA P-384, RSA-2048, RSA-4096
- **Revoke certificates** to mark them as no longer trusted
- **Offline CRL generation** — optionally embed a CRL Distribution Point in issued certificates and export a signed CRL file for manual import into Windows certificate stores, providing offline revocation status without a live server
- **SSH key generation** — generate Ed25519, ECDSA P-256/P-384, and RSA-2048/4096 SSH key pairs with optional passphrase protection
- **SSH key import** — import existing SSH private keys from Bitwarden or other sources; supports OpenSSH, PEM PKCS#8, PEM traditional, and DER formats with automatic algorithm detection and optional passphrase; imported keys are visually marked and fully functional (export, copy, backup/restore)
- **SSH key export** — download private keys in OpenSSH or PEM (PKCS#8) format, copy public keys, or copy private keys for Bitwarden SSH import
- **Database encryption** — encrypt all private keys at rest with AES-256-GCM using a master password derived via Scrypt; unlock screen on startup when enabled
- **Backup and restore** — export all data (CAs, certificates, SSH keys) to an AES-256 encrypted `.certbak` file; restore replaces all data from a backup. Backup files are portable between Docker and desktop — create on one, restore on the other
- **Login authentication** — username/password login for server mode (first-launch setup, bcrypt-hashed passwords, session-based auth)
- **TOTP multi-factor authentication** — optional TOTP second factor using any authenticator app (Google Authenticator, Authy, 1Password, etc.); enable/disable from the MFA Settings panel, requires password + code to disable
- **Trusted devices** — "Trust this device for 30 days" skips MFA on subsequent logins; trust tokens are SHA-256 hashed and stored server-side with auto-detected device labels (browser + OS); view and revoke individual devices from Account Settings or MFA Settings
- **Structured logging** — request and operation logging with timestamps, configurable via `LOG_LEVEL` environment variable

<img width="2373" height="474" alt="image" src="https://github.com/user-attachments/assets/a2f5d634-46ea-4e9d-9e8e-f98c4480abe1" />
<img width="574" height="517" alt="image" src="https://github.com/user-attachments/assets/e9dc86c0-e838-4b7b-ad1d-fd01772388a7" />
<img width="1345" height="832" alt="image" src="https://github.com/user-attachments/assets/dff10eb2-da88-4eac-8b27-0647439b233d" />


## Requirements

- Python 3.10+
- Windows 10/11 (desktop app) or Docker (server mode)

## Installation

```bash
pip install .
```

For the desktop app (pywebview), install with the desktop extra:

```bash
pip install ".[desktop]"
```

## Usage

### Docker (recommended)

```bash
docker compose up -d
```

Open `http://localhost:5000` in your browser. On first launch you'll be prompted to create an admin account. All data is persisted in Docker volumes.

To set a stable session secret (recommended — without this, everyone must sign in again after a container restart), put it in a `.env` file next to `docker-compose.yml` so it survives later `docker compose` commands:

```bash
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
docker compose up -d
```

#### HTTPS and network exposure

The server speaks plain HTTP. For anything beyond a trusted LAN, put it behind a reverse proxy that terminates TLS (Caddy, nginx, Traefik), then:

- set `COOKIE_SECURE=true` so session and trusted-device cookies are only sent over HTTPS
- publish the port on loopback only (`"127.0.0.1:5000:5000"` in `docker-compose.yml`) so the proxy is the only way in
- set `SETUP_TOKEN` before first launch if the instance is reachable before you create the admin account

Proxies that rewrite the `Host` header should forward the original as `X-Forwarded-Host`; the cross-site request check accepts either.

### Standalone EXE (Windows desktop)

Download `CertGenerator.exe` from the [latest release](https://github.com/darthrater78/cert-generator/releases/latest). Double-click to run — no Python installation needed. The desktop app runs as a native window; no login is required, and no network port is exposed.

To build from source:

```bash
pip install pyinstaller
python build.py
```

### Server mode (without Docker)

For running the web app directly without Docker:

```bash
pip install .
python -m app.serve
```

Opens on `http://0.0.0.0:5000`. Same login and UI as Docker. Configure with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `SECRET_KEY` | random | Session secret (set for persistent sessions; an empty value also means random) |
| `COOKIE_SECURE` | `false` | Set `true` when served over HTTPS so cookies are HTTPS-only |
| `SETUP_TOKEN` | — | If set, the first-run setup page requires this token |
| `DB_DIR` | `~/.cert-generator` | Database directory |
| `EXPORT_DIR` | `~/Downloads` | Desktop mode only: where exports are saved. Server mode sends exports straight to the browser |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `RESET_PASSWORD` | — | One-time: reset a user's password (`username:newpassword`) |
| `RESET_MFA` | — | One-time: disable MFA and clear trusted devices for a user |

### Desktop app (from source)

```bash
pip install ".[desktop]"
python -m app.main
```

This opens a native window with the full UI. App token authentication is handled automatically.

## Server hardening

The embedded web server is hardened for both desktop and server use:

**Desktop mode (pywebview):**
- **Loopback only** — binds to `127.0.0.1`, never exposed to the network
- **Random port** — uses an ephemeral port each launch, not a fixed port
- **App token authentication** — a random token is generated at startup and set as an httpOnly cookie via the pywebview window; requests without the cookie are rejected with 403, preventing access from other browsers on the same machine
- **Auto-shutdown** — the server thread is daemonic and shuts down when the window closes

**Server mode (Docker / standalone):**
- **Login authentication** — on first launch, you create an admin account (optionally gated by `SETUP_TOKEN`); all subsequent access requires sign-in with username and password (bcrypt-hashed, session-based)
- **Brute-force protection** — repeated failed passwords, MFA codes, or encryption passwords lock that account's attempts for 1 minute, doubling up to 15 minutes. Trusted devices are unaffected
- **TOTP MFA** — optional second factor via any authenticator app; enable per-user from MFA Settings. Each code is accepted only once
- **Trusted devices** — "Trust this device" sets an httpOnly cookie with a SHA-256 hashed token; auto-login skips password and MFA for 30 days unless "Require password every visit" is enabled. Signing out forgets the device
- **Session revocation** — password resets, MFA changes, "Revoke all devices", and backup restores end every other session
- **Session cookies** — httpOnly, `SameSite=Lax`, signed with `SECRET_KEY`; `Secure` when `COOKIE_SECURE=true`
- **Cross-site request protection** — state-changing requests from other sites are rejected (using `Sec-Fetch-Site`, falling back to `Origin`)
- **Security headers** — Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, and `Cache-Control: no-store` on API responses
- **No key material on the server's disk** — exports and backups stream to the browser instead of being written to an export folder

**Both modes:**
- **Encryption fails closed** — while an encrypted database is locked, anything that would store a private key is refused rather than written in plaintext
- **Clean exit** — `sys.exit(0)` after the UI closes ensures proper cleanup

### Account recovery

If you lose your password or MFA authenticator, use environment variables to reset on the next container start. These run once at startup — remove them afterward.

**Reset a password:**

```bash
# Docker
docker compose exec cert-generator env RESET_PASSWORD=admin:newpassword python -m app.serve &
# Or add to docker-compose.yml environment section, restart, then remove it
```

**Disable MFA for a locked-out user:**

```bash
# Docker
docker compose exec cert-generator env RESET_MFA=admin python -m app.serve &
# Or add to docker-compose.yml environment section, restart, then remove it
```

**Without Docker:**

```bash
RESET_PASSWORD=admin:newpassword python -m app.serve
RESET_MFA=admin python -m app.serve
```

`RESET_MFA` disables TOTP, clears all trusted devices, and turns off "Require password every visit" for the named user. `RESET_PASSWORD` also clears the user's trusted devices. Both end every existing session for that user, so recovering from a compromised account locks the intruder out. Neither variable affects database encryption — the master encryption password is separate from the login password.

With both MFA and database encryption enabled, the MFA page asks for the encryption password after a restart, because the MFA secret is encrypted too. Entering it also unlocks the database.

### Quick start

1. Launch the app (Docker: `docker compose up -d`, Desktop: run `CertGenerator.exe`)
2. Server mode: create your admin account on first launch, then sign in
3. Click **+ CA** and enter a domain name (e.g. `example.com`) and lifetime
3. Select your CA in the sidebar
4. Click **+ Issue Certificate** to generate leaf certs
5. Use **Export** to download certificates in your preferred format
6. Click **+ SSH Key** to generate an SSH key pair, or **Import SSH Key** to add an existing key

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

All CAs, certificates, and SSH keys are stored in a SQLite database. When database encryption is enabled, all private keys are encrypted at rest with AES-256-GCM.

| Mode | Database path | Exports path |
|------|--------------|--------------|
| **Desktop** | `~/.cert-generator/certs.db` | `~/Downloads/` |
| **Docker** | `/data/db/certs.db` (host: `/opt/docker/cert-generator/db/`) | Downloaded by your browser; nothing is kept on the server |

The database format is identical in both modes. Use **Backup** to create an encrypted `.certbak` file on one and **Restore** to load it on the other — this is the supported way to migrate data between Docker and desktop.

## Version history

### Unreleased

**Security**
- Database encryption fails closed: while locked, creating or importing keys returns an error instead of storing them unencrypted
- Login, MFA, and encryption-password attempts are rate limited; TOTP codes cannot be replayed
- Cross-site request protection, `SameSite=Lax` session cookies, optional `COOKIE_SECURE`, and CSP / frame / nosniff headers in server mode
- Sessions can be revoked: password resets, MFA changes, "Revoke all devices", and restores end other sessions; signing out forgets the trusted device
- Server-mode exports stream to the browser instead of accumulating unencrypted keys in `/data/exports`
- Optional `SETUP_TOKEN` for first-run setup; setup can no longer race to create two admins
- Constant-time token comparison and exact Origin matching in desktop mode; username timing no longer reveals valid accounts
- Request size capped at 32 MB; concurrent Scrypt derivations limited
- Dependencies pinned to exact versions; Docker base image pinned by digest; release workflow actions pinned by SHA, tag-on-default-branch check, and `latest` only moves for the newest release
- CI now runs tests on Python 3.10 and 3.14 and builds the image on every push and pull request

**Fixed**
- MFA users could not sign in after a restart with database encryption enabled (500 error), and `RESET_MFA` crashed at startup in that state
- An empty `SECRET_KEY` from Docker Compose broke setup and login
- Intermediate CAs could be created under intermediates with path length 0, producing invalid chains; deleting a root with a three-level hierarchy failed
- Full-chain export now includes every issuer up to the root
- IP addresses in SANs are encoded as IP addresses, not DNS names; invalid SAN entries are rejected
- CRLs record the actual revocation time instead of the issue time
- Passwords longer than 72 bytes caused a 500 with bcrypt 5; MFA disable no longer trims the login password
- Malformed JSON request bodies return 400 instead of 500; database connections are closed; encryption password changes run in a single transaction

**Behavior changes**
- `GET /api/download` is removed. In server mode, export, CRL, and backup endpoints return the file itself (`Content-Disposition: attachment`) instead of JSON with a server path. Desktop mode is unchanged
- PKCS12 exports without a password return 400 instead of silently using `changeit`
- Sign out is now a POST; visiting `/logout` directly returns to the app
- Resetting a password clears that user's trusted devices; enabling or disabling MFA and "Revoke all devices" sign out other sessions
- Creating an intermediate under an intermediate returns 400
- Files left in `/data/exports` by earlier versions are not deleted automatically; the server logs a warning at startup if any exist

### v1.9.0 — 2026-09-04

- **Account Settings panel** — new sidebar button providing a standalone settings view independent of MFA; "Require password every visit" toggle moved here from the MFA Settings modal so it's accessible without MFA enabled
- **Per-device trusted device management** — trusted devices now show browser and OS labels (auto-detected from user-agent); view individual devices with creation and expiry dates; revoke devices individually or all at once from Account Settings or MFA Settings
- Fixed device label detection for iPhone/iPad user agents that were incorrectly identified as macOS

### v1.8.0 — 2026-09-03

- **Account recovery via environment variables** — reset a locked-out user's password (`RESET_PASSWORD=user:newpass`) or disable their MFA (`RESET_MFA=user`) by setting environment variables before starting the server; resets run once at startup, then the app continues normally
- `RESET_MFA` disables TOTP, clears all trusted devices, and turns off "Require password every visit" for the named user
- Neither reset variable affects database encryption — the master encryption password is separate from the login password
- Annotated `docker-compose.yml` with commented examples for both reset variables

### v1.7.1 — 2026-09-03

- **Fixed Docker build** — added missing `pyotp` and `qrcode` dependencies that caused `ModuleNotFoundError` on container startup
- **Dockerfile now installs from requirements.txt** instead of a hardcoded package list, preventing future dependency drift between the manifest and the container
- Updated `requirements.txt` to match current `pyproject.toml` server dependencies

### v1.7.0 — 2026-09-03

- **TOTP multi-factor authentication** — enable a TOTP second factor from the new MFA Settings panel in the sidebar; scan the QR code with any authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter a verification code to confirm setup; requires both password and TOTP code to disable
- **Trusted devices** — "Trust this device for 30 days" checkbox on login and MFA verification pages; trust tokens are SHA-256 hashed and stored server-side; revoke all trusted devices from MFA Settings
- **Require password every visit** — opt-in setting (off by default) that forces password entry on each visit even with a trusted device; toggle from MFA Settings
- TOTP secrets are encrypted at rest when database encryption is enabled
- Trusted device cleanup runs automatically on login to remove expired tokens
- Backup/restore preserves MFA settings (TOTP secret, enabled state, require-password preference); trusted devices are not backed up (they are per-device and ephemeral)

### v1.6.0 — 2026-09-02

- **SSH key import** — import existing SSH private keys from Bitwarden or other sources via the new "Import SSH Key" button; supports OpenSSH, PEM PKCS#8, PEM traditional, and DER formats with automatic algorithm detection and optional passphrase
- Imported keys are visually distinguished with an "IMPORTED" badge in the sidebar and a "Source: Imported" indicator in the detail view
- Imported keys are fully functional — export, copy, backup/restore all work identically to generated keys
- Added `imported` column to the SSH keys database schema (auto-migrated on upgrade)

### v1.5.1 — 2026-09-02

- **Structured logging** — request logging (method, path, status, duration) and operation logging (CA/cert/SSH key create/delete, login, backup/restore); configurable via `LOG_LEVEL` environment variable
- **Expandable serial numbers** — click to expand/collapse full serial in the CA details view
- Fixed SSH key details grid overflow — fingerprint and long values now wrap properly
- Fixed `python` → `python3` in SECRET_KEY generation command (compose and README)
- Uncommented `SECRET_KEY` in compose since login is on by default
- Rewrote README to clarify Docker and desktop as equal deployment options with full feature parity and portable backups

### v1.5.0 — 2026-09-02

- **Docker deployment** — run as a web server with `docker compose up`, GitHub Actions CI builds and pushes to GHCR on every version tag; non-root container with `no-new-privileges`
- **Login authentication** — username/password login for server mode; first launch prompts for admin account creation, bcrypt-hashed passwords, Flask session-based auth
- **Server mode** — production WSGI entry point (`python -m app.serve`) using Waitress; configurable via `PORT`, `HOST`, `SECRET_KEY`, `DB_DIR`, `EXPORT_DIR` environment variables
- **Browser downloads** — exports in server mode trigger browser file downloads instead of saving to the local filesystem
- **Structured logging** — request logging (method, path, status, duration) and operation logging (CA/cert/SSH key create/delete, login, backup/restore); configurable via `LOG_LEVEL` environment variable
- **Expandable serial numbers** — click to expand/collapse full serial in the CA details view
- Moved `pywebview` to an optional `[desktop]` extra — server/Docker installs don't pull GUI dependencies
- Added `waitress` dependency for production WSGI serving

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
