# Cert Generator

**Your own certificate authority for the lab, the office and security demos.** Create root and intermediate CAs, issue certificates that match Windows CA templates, revoke them with a CRL clients can actually reach, and get every certificate onto the machine that needs it. Runs as a **Docker web app** or a **Windows desktop app**.

[Latest release](https://github.com/darthrater78/cert-generator/releases) · [What's new](CHANGELOG.md) · [Quick start](#quick-start) · [Cert Generator Pal](#cert-generator-pal-windows-pcs)

## New in 2.8: Cert Generator Pal

**Stop copying .pfx files to Windows PCs.** Cert Generator Pal is a small Windows app that ships with the Docker version. Pair a PC once, and from then on it **requests, installs and renews its own certificates**.

<table>
<tr>
<td width="50%" valign="top"><img alt="Add a Windows PC: the one-time pairing code with Copy, the address the PC downloads the Pal from, and the three steps on the PC" src="docs/screenshots/pal-pairing-code.png" /><br/><sub><b>On the server:</b> Add a PC gives a one-time pairing code.</sub></td>
<td width="50%" valign="top"><img alt="Cert Generator Pal on a PC that isn't paired yet: the three steps, the name the PC connects as, a pasted pairing code and Connect" src="docs/screenshots/pal-app-connect.png" /><br/><sub><b>On the PC:</b> paste it into Cert Generator Pal and choose Connect.</sub></td>
</tr>
</table>

| 1 · Add a PC | 2 · Pair it | 3 · Request |
|---|---|---|
| On **Windows PCs**, choose **Add a PC**, pick what it may request, and copy the one-time code. | Run `CertGeneratorPal.exe` on the PC (it downloads from your server) and paste the code. | Choose a tile: **Web server / RDP**, **This computer**, **Me** or **Code signing**. It lands in the right Windows store in seconds. |

- **Keys are made on the PC and never leave it**: non-exportable, in the TPM when there is one. The server only ever sees certificate requests.
- **You stay in charge**: for each PC, every kind of certificate is off, issued right away, or waits for your approval.
- **Renewal is one click**, and IIS sites and Remote Desktop move to the new certificate by themselves.
- **Works away from the LAN** through an end-to-end encrypted Cloudflare relay, without opening anything on your network.

<img width="1440" alt="The Windows PCs page: the Cert Generator Pal download card with the LAN link and SHA-256, two requests waiting for approval, and the connected PCs, each with what it may request, its CRL profiles, what is installed on it and its remote access" src="docs/screenshots/pal-windows-pcs.png" />

<sub><b>Windows PCs</b>: every paired PC, what it may request, what it holds, and the requests waiting for your approval.</sub>

**[Read the Pal guide ↓](#cert-generator-pal-windows-pcs)**. 2.8 is in pre-release (`2.8.0-dev.N` tags) while the Pal is tested on real PCs.

## What it does

<img width="1440" alt="The dashboard on the Slate theme: an intermediate CA's particulars, its Export CA certificate and Revocation list sections, and its Cloudflare Worker card, and its register of issued certificates with Export / install on each; the sidebar groups Tools into Create, Data, Security, Publishing and Help" src="docs/screenshots/dashboard.png" />

| | |
|---|---|
| **Certificate authorities** | Root and intermediate CAs with Ed25519, ECDSA P-256/P-384 or RSA-2048/4096 keys |
| **Certificates** | Templates matching a Windows CA (Web Server, Computer, Client Authentication, User, Code Signing, S/MIME), SANs with wildcards and IP addresses, and a viewer that reads like `openssl x509 -text` |
| **Getting them installed** | **Export / install** gives per-OS commands and a .zip with install scripts; PEM, DER, CRT and PKCS#12 files; **Cert Generator Pal** for Windows PCs |
| **Revocation** | A CRL served by this server, by a Cloudflare Worker per CA, or by each endpoint itself, and a CRL viewer |
| **SSH keys** | Generate or import, then export as OpenSSH or PEM |
| **Security** | Encryption at rest with a recovery key, TOTP sign-in, trusted devices, a fresh sign-in before any private key leaves, encrypted backups |
| **Looks** | Six themes and an accent colour |

### Tour

<table>
<tr>
<td width="50%" valign="top"><img alt="The Issue Certificate dialog: the Cert Generator Pal recommendation for Windows PCs at the top, then Include CRL Distribution Point ticked with Cert Generator (LAN) and the address clients fetch the CRL from" src="docs/screenshots/issue-certificate.png" /><br/><sub><b>Issue a certificate</b> from a Windows CA template, with the CRL address it carries.</sub></td>
<td width="50%" valign="top"><img alt="Export / install for a computer certificate on Windows: the question whether the CA chain is already on the machine, the Administrator notice, Download .zip, Download buttons for the CA files and the CRL, and the PowerShell commands with Copy code" src="docs/screenshots/export-install.png" /><br/><sub><b>Export / install</b>: the files and the commands for Windows, macOS or Linux, or a .zip that installs itself.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img alt="The certificate viewer: a web server certificate's general fields, subject, issuer, extensions, fingerprints and the issuing CA's CRL" src="docs/screenshots/cert-viewer.png" /><br/><sub><b>Certificate viewer</b>: every field and extension, fingerprints, and whether it's on the CRL.</sub></td>
<td width="50%" valign="top"><img alt="The CRL viewer: the intermediate CA's published CRL with its revoked serials, one linked to its certificate" src="docs/screenshots/crl-viewer.png" /><br/><sub><b>CRL viewer</b>: the published list, each revoked serial linked to its certificate.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img alt="An SSH key's particulars, public key and export options" src="docs/screenshots/ssh-key.png" /><br/><sub><b>SSH keys</b>, generated here or imported.</sub></td>
<td width="50%" valign="top"><img alt="The one-time recovery key shown when database encryption is enabled, with Copy, Download .txt and an I've stored it confirmation" src="docs/screenshots/recovery-key.png" /><br/><sub><b>Encryption at rest</b>, with a one-time recovery key.</sub></td>
</tr>
<tr>
<td width="50%" valign="top"><img alt="The sign-in page, set as an engraved certificate over a faint openssl readout" src="docs/screenshots/sign-in.png" /><br/><sub><b>Sign-in</b>, with optional TOTP and trusted devices.</sub></td>
<td width="50%" valign="top"><img alt="The Umber theme with the Appearance menu open: six themes and the accent colour picker" src="docs/screenshots/themes.png" /><br/><sub><b>Themes</b>: six of them, and any accent colour.</sub></td>
</tr>
</table>

<details>
<summary><b>Every feature, in detail</b></summary>

- **Create Certificate Authorities** with configurable domain, name, algorithm, and lifetime
- **Intermediate CAs** — create subordinate CAs from any root CA; intermediates can issue their own certificates (intermediates are issued with path length 0, so they cannot create further CAs)
- **Issue leaf certificates** signed by any CA (root or intermediate), with SAN (Subject Alternative Name) support including wildcards and IP addresses
- **Certificate templates** matching Windows CA templates — Web Server, Computer, Client Authentication, User (Smart Card Logon), Code Signing, Email (S/MIME) — each with the correct key usage and extended key usage extensions
- **Track all certificates** — view status (active/revoked/expired), details, and metadata
- **Certificate viewer** — click a certificate (or **View**) to read it like `openssl x509 -text`: subject, issuer, validity, key and signature algorithm, every extension (SANs including UPN, key usage, extended key usage, basic constraints, key identifiers, CRL distribution points), SHA-256/SHA-1 fingerprints and the PEM, with Copy PEM and Export. A **Show the issuing CA's CRL** checkbox adds the CA's revocation list: whether this certificate is on it, the distribution point it carries, the CRL's next update and every revoked serial. The private key is never sent to the viewer
- **Export in multiple formats** — PEM, DER, CRT (.crt), PKCS12 (.pfx)
- **Export parts individually** — full bundle, certificate only, private key only, or full chain (cert + every issuing CA up to the root)
- **Password-protected exports** — optionally encrypt the private key (PEM); PKCS12 bundles always require a password you choose: there is no default, and the old pre-filled `changeit` is refused
- **Optional CA chain inclusion** — choose whether to bundle the issuing CA certificate when exporting issued certs
- **In-app import guide** — step-by-step instructions for importing certificates on Windows, macOS, and Linux for each template type
- **Export / install** — on any certificate, **Export / install ▾** asks whether the CA chain is already on the machine, then gives the files to download and copy-paste commands for Windows, macOS or Linux in one block with **Copy code**, with Windows stores per Microsoft's layout (root → Trusted Root Certification Authorities, intermediate → Intermediate Certification Authorities, computer certificates → Local Computer › Personal, user certificates → Current User › Personal) and a notice when PowerShell must run as Administrator. **Download .zip** packs the certificate, the CA chain if needed, the CRL for an endpoint-hosted certificate, and install / uninstall scripts (`install.cmd` / `uninstall.cmd` on Windows). The **Export file** tab downloads the certificate in any format
- **Modern crypto algorithms** — Ed25519, ECDSA P-256, ECDSA P-384, RSA-2048, RSA-4096
- **Revoke certificates** to mark them as no longer trusted
- **CRL generation and publishing** — optionally embed a CRL Distribution Point in issued certificates. The distribution point is either **this server** (`<address>/crl/<CA id>.crl`, answered without sign-in; server mode only, see [Publishing the CRL](#publishing-the-crl)), where the app signs a 7-day CRL itself, re-signs it on every revocation and renews it before it runs out, a **Cloudflare Worker** per CA (server mode), or **endpoint-hosted** (`http://pki.<domain>/crl/<CA>.crl`, which no server answers): each machine gets the CRL from the certificate's install .zip, which on Windows also answers that address locally, or from an exported CRL you import (see [Endpoint-hosted CRL](#endpoint-hosted-crl-for-endpoints-that-cant-reach-docker-or-cloudflare-windows)). Exported CRLs stay valid as long as you choose (7 days to 10 years, default 10 years); the CA page shows the published CRL and the exported one separately, and each certificate shows where its CRL comes from and whether it is published
- **Cloudflare Worker CRL distribution point** (Docker only) — each CA can publish its CRL from its own Cloudflare Worker, set up entirely from the app: connect an API token under **Tools › Cloudflare**, then **Deploy**, **Test**, **Push now**, **View live CRL** and **Tear down** on the CA page. Revoking a certificate pushes the new CRL to the Worker, and the hourly renewal keeps it current. See [Cloudflare Worker CRL](#cloudflare-worker-crl)
- **CRL viewer** — **View CRL** on the CA page (or **Open in CRL viewer** from a certificate) shows the CRL this server publishes: issuer, this and next update, signature, every revoked serial linked to its certificate, fingerprints and the PEM. For a CA it doesn't publish for, it lists the revocations an export would contain now
- **Step-up confirmation for key material** — downloading a private key (CA, certificate or SSH), copying an SSH private key, backing up and restoring all ask for your password, or an authenticator code when MFA is on, unless you signed in within the last 5 minutes
- **Revocation survives deletion** — deleting a revoked certificate keeps its serial on the CA's CRL until the certificate would have expired, and deleting a certificate that isn't revoked warns that clients keep trusting it
- **SSH key generation** — generate Ed25519, ECDSA P-256/P-384, and RSA-2048/4096 SSH key pairs with optional passphrase protection
- **SSH key import** — import existing SSH private keys from Bitwarden or other sources; supports OpenSSH, PEM PKCS#8, PEM traditional, and DER formats with automatic algorithm detection and optional passphrase; imported keys are visually marked and fully functional (export, copy, backup/restore)
- **SSH key export** — download private keys in OpenSSH or PEM (PKCS#8) format, copy public keys, or copy private keys for Bitwarden SSH import
- **Database encryption** — encrypt all private keys at rest with AES-256-GCM using a master password derived via Scrypt; unlock screen on startup when enabled
- **Encryption recovery key** — enabling encryption shows a one-time recovery key; if you forget the master password, it unlocks the database and sets a new one (see [Forgotten encryption password](#forgotten-encryption-password))
- **Backup and restore** — export all data (CAs, certificates, SSH keys) to an AES-256 encrypted `.certbak` file; restore replaces all data from a backup. Backup files are portable between Docker and desktop — create on one, restore on the other
- **Login authentication** — username/password login for server mode (first-launch setup, bcrypt-hashed passwords, session-based auth)
- **TOTP multi-factor authentication** — optional TOTP second factor using any authenticator app (Google Authenticator, Authy, 1Password, etc.); enable/disable from the MFA Settings panel, requires password + code to disable
- **Trusted devices** — "Trust this device for 30 days" skips MFA on subsequent logins; trust tokens are SHA-256 hashed and stored server-side with auto-detected device labels (browser + OS); view and revoke individual devices from Account Settings or MFA Settings
- **Structured logging** — request and operation logging with timestamps, configurable via `LOG_LEVEL` environment variable
- **Themes and accent colour** — six themes (Slate by default, Flashbang, Graphite, Umber, Ink and OLED) and an accent colour picker (twelve presets, a colour picker or a typed hex value; brass by default), chosen from the Appearance menu and saved per browser; the sign-in pages follow the same choice

</details>

## Deployment options

| Mode | Best for | How it runs |
|------|----------|-------------|
| **Docker** (recommended) | Servers, shared access | Web app at `http://host:5000` with login authentication |
| **Standalone EXE** | Individual workstations | Native Windows window, downloaded from the release — no install needed |

**They are separate installs.** Each keeps its own database, and nothing syncs between them. To move your CAs, certificates and SSH keys from one to the other, use **Backup** in one to create an encrypted `.certbak` file and **Restore** it in the other (see [Data storage](#data-storage)). Backups go either way.

Both use the same interface and database format. Where they differ:

| | Docker | Standalone EXE |
|---|---|---|
| Access | Browser, from any machine that can reach it | Native window on one PC, no network port |
| Sign-in | User accounts, optional TOTP 2FA, trusted devices | Optional username + master password (turns on encryption) |
| CRL distribution point | **Cert Generator (LAN)** (this server), a **Cloudflare Worker**, or **endpoint-hosted** | Endpoint-hosted only: each machine gets the CRL from the install .zip or an import |
| Windows PCs (Cert Generator Pal) | Yes: PCs request and install their own certificates | No |
| Encryption at rest + recovery key | Optional | Optional |

For a CRL that clients fetch over the network, you need the Docker version.

## Quick start

1. Launch the app (Docker: `docker compose up -d`, Desktop: run `CertGenerator.exe`)
2. Server mode: create your admin account on first launch, then sign in. Desktop: choose whether to protect the app with a username and password
3. With no CA yet, the **Certificate Import Guide** opens on its Quick Start. **Open in new window** keeps it beside the app while you work
4. Click **+ New** next to **Authorities** (or **Tools › Create › New certificate authority**) and enter a domain name (e.g. `example.com`) and lifetime
5. Select your CA in the sidebar
6. Click **Issue certificate** to generate leaf certs
7. To trust the CA on a machine, **Download** it from the CA page: the default, **DER · Certificate Only**, is the file an endpoint needs
8. Click **Export / install ▾** on a certificate for step-by-step install commands or a .zip with install scripts, or its **Export file** tab to download it in the format you choose
9. Docker: for Windows PCs, open **Windows PCs**, download **Cert Generator Pal** and choose **Add a PC**: the PC then requests and installs its own certificates (see [Cert Generator Pal](#cert-generator-pal-windows-pcs))
10. Docker: to publish a CA's CRL on the internet, connect **Tools › Cloudflare** and deploy a Worker from the CA page (see [Cloudflare Worker CRL](#cloudflare-worker-crl))
11. Click **+ New** next to **SSH keys** to generate an SSH key pair, or **Tools › Create › Import SSH key** to add an existing key

## Install and run

### Docker (recommended)

**1. Create the data folder and move into it** (the container runs as UID 1000):

```bash
sudo mkdir -p /opt/docker/cert-generator && sudo chown 1000:1000 /opt/docker/cert-generator && sudo chmod 700 /opt/docker/cert-generator && cd /opt/docker/cert-generator
```

**2. Save this as `compose.yaml`** in that folder:

```yaml
services:
  cert-generator:
    image: ghcr.io/darthrater78/cert-generator:2.8.0-dev.6
    container_name: cert-generator
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "5000:5000"
    volumes:
      - /opt/docker/cert-generator:/data
    environment:
      - TZ=America/New_York
      - PORT=5000
      - SECRET_KEY=${SECRET_KEY:-}
      # - COOKIE_SECURE=true
      # - SETUP_TOKEN=${SETUP_TOKEN:-}

# image: pinned to a release. To upgrade, change the tag and run: docker compose pull && docker compose up -d
# no-new-privileges: the app never needs to gain privileges after it starts
# ports: the web UI on port 5000. Behind a reverse proxy, use "127.0.0.1:5000:5000" (see below)
#NOTE: this is only for scenarios where the proxy is on the same host as cert manager. 
# volumes: the database and exports live in /opt/docker/cert-generator on the host
# TZ: timezone for log timestamps
# PORT: the port the app listens on inside the container
# SECRET_KEY: signs session cookies; set it in .env (step 3) so sign-ins survive a restart
# COOKIE_SECURE: uncomment when the app is served over HTTPS
# SETUP_TOKEN: uncomment to require a token on the first-run setup page
```

**3. Set a session secret and start it:**

```bash
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env && docker compose up -d
```

Open `http://<host>:5000` in your browser. On first launch you'll be prompted to create an admin account. The repository's [`docker-compose.yml`](docker-compose.yml) is the same file with longer comments, including the one-time account-recovery variables.

#### HTTPS and network exposure

The server speaks plain HTTP. For anything beyond a trusted LAN, put it behind a reverse proxy that terminates TLS (Caddy, nginx, Traefik), then:

- set `COOKIE_SECURE=true` so session and trusted-device cookies are only sent over HTTPS
- publish the port on loopback only (`"127.0.0.1:5000:5000"` in `compose.yaml`) so the proxy is the only way in
  NOTE: this is only for scenarios where the proxy is on the same host as cert manager. 
- set `SETUP_TOKEN` before first launch if the instance is reachable before you create the admin account

Proxies that rewrite the `Host` header should forward the original as `X-Forwarded-Host`; the cross-site request check accepts either.

### Standalone EXE (Windows desktop)

Download `CertGenerator.exe` from the [latest release](https://github.com/darthrater78/cert-generator/releases/latest). Double-click to run — no Python installation needed. The desktop app runs as a native window, and no network port is exposed.

On first run the app offers to **protect it with a username and password**. That turns on database encryption with the password as the master password, so the app asks for both at every start and a copied database file can't be read. Next it shows a one-time **recovery key**: if you forget the password, the sign-in screen takes the key, sets a new password and shows your username. You can skip it (**Not now**, or **Don't ask again**) and turn it on later in **Encryption** settings.

The EXE offers only the endpoint-hosted CRL distribution point. To serve a CRL that clients fetch, run the Docker version and move your data across with Backup and Restore.

The EXE is not code-signed, so Windows SmartScreen shows a warning on first run. To confirm the file is the one GitHub Actions built from this repository, compare it with the release's `CertGenerator.exe.sha256`, or verify its build attestation with the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify CertGenerator.exe --repo darthrater78/cert-generator
```

To build it yourself on Windows:

```bash
pip install -r requirements-desktop.txt
python build.py
dist\CertGenerator.exe --self-test result.json
```

`--self-test` exercises the packaged app against a throwaway database without opening a window and writes the results to `result.json`; `--self-test-gui` also opens and checks the real window.

### Server mode (without Docker)

Run `python -m app.serve` (see [From source](#from-source)). It opens on `http://0.0.0.0:5000`. Same login and UI as Docker. Configure with environment variables:

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
| `RESET_PASSWORD` | — | One-time: reset a user's password (`username:newpassword`), clear their trusted devices, and end their sessions |
| `RESET_MFA` | — | One-time: disable MFA, clear trusted devices, and end sessions for a user |

### From source

Needs Python 3.10+. For the web app (server mode):

```bash
pip install .
python -m app.serve
```

For the desktop app (pywebview), on Windows 10/11:

```bash
pip install ".[desktop]"
python -m app.main
```

This opens a native window with the full UI. App token authentication is handled automatically.

## Cert Generator Pal (Windows PCs)

Cert Generator Pal is a Windows companion app for the Docker version. You pair a PC with a **one-time pairing code**; from then on the PC asks your server for certificates, installs them in the right Windows store, and renews them near expiry, all in one click. **The private keys are made on the PC, never leave it, and can't be exported** (in the TPM when the PC has one). The server only ever sees certificate requests.

### What a PC can get

| In the Pal | Certificate | Installed in |
|---|---|---|
| **Web server / RDP** | TLS server certificate named after the PC, plus names you allow (IIS sites, Remote Desktop) | Local Computer › Personal |
| **This computer** | The computer's own certificate, named like a Windows CA names it (Wi-Fi, VPN, 802.1X) | Local Computer › Personal |
| **Me** | The signed-in user's client certificate (client authentication, smart card logon) | Current User › Personal |
| **Code signing** | Signing scripts and programs | Current User › Personal |
| **TLS inspection** | Trusts your CA for HTTPS inspection (no request) | Local Computer › Trusted Root |

Only what the pairing code allows appears. The CA chain is checked before every install and any missing root or intermediate is added. A web server certificate can go straight to work: tick **Use for Remote Desktop** and/or **Bind to an IIS site** (site, port, and every name or one of the certificate's names) when you request it, or use **Bind…** on one already installed.

### Setting up a PC

1. **Get the app.** Open **Windows PCs** (sidebar, under Devices). The download card at the top has the EXE, its LAN address to copy, and its SHA-256. PCs on your LAN download it from your server without signing in. It is one file with nothing else to install, and it is **only** shipped inside the Docker image, with the same version as the server.
2. **Add a PC.** Choose **Add a PC** and set what this code allows:
   - **What the PC may request**: each kind is *Off*, *Issue right away* or *Needs my approval*.
   - **Allowed DNS names and addresses** (`*.home.arpa`, `10.0.0.0/24`) and **allowed user names** (`*@home.arpa`). The PC's own name must fit. Wildcard certificates are never issued to a PC.
   - **Longest lifetime**, how long the code works for, and the address the PC uses for this server.
   - **CRL profiles**: which revocation checks the PC may use: **Cert Generator (LAN)** (this server), **the CA's Cloudflare Worker**, **On each PC (self-hosted)** or **None**. Each one ticked becomes a CRL profile in the Pal.
   - **Allow remote connection**: whether the PC may use the [remote connection](#remote-connection-pcs-away-from-the-lan) once paired.
3. **Send the pairing code** to the PC the way you'd send a password. It is shown only once, works for one PC, and expires.
4. **On the PC**, run `CertGeneratorPal.exe` (it is unsigned, so Windows SmartScreen asks: choose **More info › Run anyway**), paste the code and choose **Connect**. Windows asks for administrator approval once, to trust your CA. The PC names itself from its own fully qualified name.
5. **Pick a CRL profile** in the Pal. Until you do, nothing can be requested: the profile decides where the PC's certificates check revocation.

<img width="49%" alt="The Add a Windows PC dialog: what the PC may request with an approval mode for each, allowed DNS and user names, lifetime, code expiry, server address, the CRL profiles the PC may use and Allow remote connection" src="docs/screenshots/pal-add-pc.png" /> <img width="49%" alt="The one-time pairing code, with Copy, the download address and the three steps on the PC" src="docs/screenshots/pal-pairing-code.png" />

### Using the Pal

- **Request** with a tile. *Issue right away* installs the certificate in seconds. *Needs approval* waits for you: the request appears on the **Windows PCs** page with a banner and a count in the sidebar, and the Pal's **Check again** installs it once you approve.
- **The certificate list** shows every certificate on the PC that chains to your CA, in the user's and the computer's stores, with the server's view of each (valid, revoked, expired) and anything that needs a look. **Details** opens a full certificate view (every field and extension, the chain, where the key lives). **Remove** takes one or several out, with one administrator prompt for the computer's.
- **Renew** opens in a certificate's last 30 days (the last third for short-lived ones). Until then the button says how long is left. Renewing makes a new key and replaces the old certificate, which is then revoked. Whatever used the old certificate (IIS sites, other HTTPS bindings, Remote Desktop), even if you set it up by hand, moves to the new one first.
- **Bind…** uses a web server certificate in the computer's store for **Remote Desktop** or an **IIS site**: the site's https binding is added if it has none, or switched to this certificate. The list shows what uses each certificate, and **Remove** warns before taking away one that's in use.
- **One live certificate** per PC, kind and name: the server refuses duplicates and early renewals.
- **CRL profiles**: switching profile backs out the current one first (its certificates leave the PC); the root CA stays trusted. **Self-hosted** adds a small listener on the PC that answers its own revocation checks, for laptops away from the LAN; its tile shows only under that profile.
- **Connectivity** shows the cert server (over the LAN, and through the relay when the PC has one) and the CRL of the profile in use, each with a coloured status and **Test**. **Refresh** re-checks, and **Log** shows the Pal's log with a **Debug logging** switch (every request and check; never keys or pairing codes). The CRL profile is locked while the server can't be reached.
- **Disconnect this PC** removes the pairing and every certificate it installed.

The Pal keeps its pairings in `C:\ProgramData\CertGeneratorPal` (written only with administrator approval) and its log in `%LOCALAPPDATA%\CertGeneratorPal\pal.log`.

### Managing PCs

The **Windows PCs** page ([pictured above](#new-in-28-cert-generator-pal)) lists each PC with what it may request, its CRL profiles, what its last check-in found installed, its Pal version and how its last request arrived. From there you **approve or deny** requests, **allow or turn off** remote access, **Disconnect** a PC (it can't request again, and its certificates are revoked) or **Delete** it from the list. Pairing codes that haven't been used can be revoked. A PC whose Pal comes from another release is flagged, so you know to update it from the server.

### How it stays secure

- **Keys stay on the PC**, non-exportable, in the TPM when there is one. The server stores no Pal private keys.
- **Pairing** proves both sides hold the code's secret without sending it, and **pins your root CA**: a server or network in the middle can't plant another CA.
- **Every request is signed** by the PC's own device key, with a timestamp and a single-use nonce. What a PC may ask for is enforced by the server, not the app.
- **LAN only**: the server answers the Pal's API only from private addresses (RFC 1918, CGNAT `100.64.0.0/10` for SSE / ZTNA overlays such as Tailscale or Zscaler, link-local, IPv6 ULA), and the Pal connects only to such addresses. Don't publish `/api/pal/` through an internet-facing reverse proxy; use the remote connection instead.
- **Disconnecting** a PC revokes its certificates; a renewal revokes the certificate it replaces.

### Remote connection (PCs away from the LAN)

A PC allowed remote access keeps requesting and renewing when it isn't on your LAN, through a **relay Worker** on your Cloudflare account. **Nothing on your network opens to the internet**: your server connects *out* to the Worker and collects the requests waiting there.

<img width="1440" alt="The Remote connection card once set up: the relay address with a green status, when the server last collected, how many PCs are allowed and requests answered, the Worker's queues, and Check now, Update Worker and Tear down" src="docs/screenshots/pal-remote.png" />

1. Turn on **database encryption** and connect **Cloudflare** (**Tools › Cloudflare**) if you haven't: the relay's keys are only ever stored encrypted.
2. On **Windows PCs › Remote connection**, choose **Set up remote connection**. It deploys a relay Worker on your `workers.dev` subdomain and the server starts collecting from it. **Check now** shows the server collecting within a minute.
3. **Allow** remote access for a PC on its card (or tick **Allow remote connection** when you make its pairing code).
4. The PC learns the relay the next time it checks in **on the LAN**. From then on, when the LAN can't be reached, each request goes through the relay instead. In the Pal, **Cert server · Remote** shows the relay, and **Connect to remote** uses only the relay for the session (to test it).

What Cloudflare sees: a PC's device id, sizes and times. Each request is **end-to-end encrypted** to a key only your server holds (a one-time P-256 key per request, AES-256-GCM), and each reply to a key only that request's sender can derive, so the Worker can't read, change or replay either. The Worker only takes envelopes signed by a PC you allowed, and **pairing never goes through the relay**. **Tear down** deletes the Worker; the relay key stays, so PCs pick up a new relay without pairing again.

### Troubleshooting

<details>
<summary><b>What the Pal's messages mean</b></summary>

| The Pal says | What to do |
|---|---|
| **Wrong domain.** / **No DNS suffix.** | The PC's full name must fit the code's allowed DNS names; set the PC's primary DNS suffix, or allow its domain on a new code |
| **Code already used / expired / revoked.** | Make a new pairing code |
| **… isn't a LAN address.** | The server address resolves to a public address: use its LAN name or address (or set up the remote connection) |
| **Clock wrong.** | The PC's clock is more than 5 minutes off the server's |
| **Not allowed.** / **Revocation type not allowed.** | The pairing doesn't allow that; make a new code with it |
| **Too early to renew.** | Renewal opens in the certificate's last 30 days |
| **IIS refused.** / **No such site.** | Check the site name in IIS Manager; the log has appcmd's full answer |
| **Remote Desktop isn't set up.** | Turn on Remote Desktop in Settings, then **Bind…** again |
| **Remote access refused.** | Allow remote for the PC on the Windows PCs page; the relay hears about it within a minute |
| Windows SmartScreen blocks the EXE | It's unsigned: **More info › Run anyway**, after checking its SHA-256 on the Windows PCs page |

</details>

For anything else, turn on **Log › Debug logging** in the Pal and look at the log; the server's log has the matching entries. The design, protocol and relay envelope are documented in [docs/cert-generator-pal.md](docs/cert-generator-pal.md).

## Revocation lists (CRL)

A certificate can carry a CRL distribution point: the address clients check to learn it was revoked. There are three kinds, picked per certificate when you issue it: **this server** (Docker), a **Cloudflare Worker** (Docker), or **endpoint-hosted**, where each machine answers its own revocation check.

### Publishing the CRL

Certificates issued with the **Cert Generator (LAN)** distribution point (this server) name `<address>/crl/<CA id>.crl`, where `<address>` is the one typed in the Issue Certificate dialog (it defaults to the address you are using). That path is the only one that answers without signing in. The app signs that CRL itself the first time a certificate names this server, and keeps it current: each served CRL is valid for 7 days, it is re-signed on every revocation, and an hourly check renews it when less than half its life is left. Clients cache a CRL until its next update, so a revocation reaches them within 7 days. Nothing is signed per request. A CA's CRL is served only once a certificate has named this server, and unknown, unpublished and never-opted-in CAs all get the same `404`.

With an encrypted database, signing needs the CA key, so revoking a certificate of a CA served here is refused while the database is locked, and renewals wait until it is unlocked (the served CRL keeps answering meanwhile). **Export CRL** is for the endpoint-hosted distribution point and offline import: it downloads a CRL with the lifetime you choose and never replaces the one this server serves. After you revoke a certificate whose CRL is endpoint-hosted, or that has none, the app offers that updated CRL for download.

If clients reach the app through a reverse proxy, expose `/crl/` alone to them and keep everything else private. Allow only `GET` and `HEAD` on `^/crl/[0-9]+\.crl$`. Revocation checks are usually plain HTTP (clients don't fetch a CRL over HTTPS to avoid a circular check), so the CRL vhost is often HTTP while the admin UI stays on HTTPS.

nginx:

```nginx
server {
    listen 80;
    server_name pki.example.lan;

    location ~ ^/crl/[0-9]+\.crl$ {
        limit_except GET { deny all; }  # GET also allows HEAD
        proxy_pass http://127.0.0.1:5000;
    }
    location / { return 404; }
}
```

Traefik (compose labels on the `cert-generator` service):

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.crl.rule=Host(`pki.example.lan`) && PathRegexp(`^/crl/[0-9]+\.crl$`) && (Method(`GET`) || Method(`HEAD`))
  - traefik.http.routers.crl.entrypoints=web
  - traefik.http.services.crl.loadbalancer.server.port=5000
```

The desktop app can't serve CRLs (it listens on loopback only), so it offers the endpoint-hosted distribution point alone.

### Cloudflare Worker CRL

For clients that can't reach this server, each CA can publish its CRL from its own [Cloudflare Worker](https://developers.cloudflare.com/workers/), on Cloudflare's free plan. Everything happens in the app; there is no `wrangler` or command line. Docker only: the EXE never stores a Cloudflare token.

<img width="1440" alt="A root CA's Cloudflare Worker for CRL card after Test: the address certificates carry, the Worker name, the last push, and the plain HTTP and HTTPS results with the recommended address" src="docs/screenshots/cloudflare-worker.png" />

**1. Connect (once).** Turn on database encryption first: the API token can rewrite your CRL Workers, so it is only ever stored encrypted with the database key, and the app can't use it while the database is locked (encryption can't be turned off while Cloudflare is connected). Then open **Tools › Cloudflare** and follow its steps: create a custom API token in the Cloudflare dashboard with **Account · Workers Scripts · Edit** on your account only (for an address on your own domain, add **Zone · Zone · Read**, **Zone · Workers Routes · Edit** and **Zone · DNS · Edit** for that one zone), and paste it with your account ID. The token is checked with Cloudflare and never shown again.

**2. Deploy per CA.** On the CA page, the **Cloudflare Worker for CRL** card deploys a Worker for that CA at `certgen-crl-<CA>-<random>.<your subdomain>.workers.dev`, or at a hostname on one of your Cloudflare domains (Cloudflare creates the DNS record). Pick an address you'll keep: it is written into every certificate issued with it. Then issue certificates with **Include CRL Distribution Point › Cloudflare Worker (this CA)**.

**3. Test.** **Test** fetches the CRL from the Worker over plain HTTP and HTTPS, from this server, and checks that it parses, is signed by the CA, is current and matches what the app last pushed. It recommends the address to put in certificates: plain HTTP with no redirect where that works, since Windows and most clients fetch CRLs over HTTP. **View live CRL** opens the CRL the Worker is serving in the CRL viewer, and **Copy** gives the address for your own testing (`certutil -url`, `openssl crl`).

**Keeping it current.** The CRL is built into the Worker, so publishing is a redeploy. Revoking a certificate asks to confirm and pushes the new CRL; the hourly renewal re-signs and pushes it before it runs out (7-day CRLs, renewed at half-life); **Push now** does it by hand. A failed push shows **not published** on the CA page and in the log, and is retried hourly. **Refresh** re-reads the Worker and checks it still exists in Cloudflare.

**Tear down** deletes the CA's Worker (and its custom domain) after a confirmation that says how many certificates carry its address, since they lose their working CRL. **Tools › Cloudflare** lists every `certgen-crl-*` Worker in the account as **in use**, **unlinked** (in Cloudflare, but no CA here uses it: a deleted CA, a failed setup, a restore or another install of the app) or **missing** (a CA here names a Worker Cloudflare no longer has), with **Delete** and **Delete unlinked**. **Disconnect** deletes the stored token (delete it in the Cloudflare dashboard too); it needs a recent sign-in and is refused while any CA still has a Worker, since the app could no longer update or remove it.

<img width="49%" alt="Tools › Cloudflare: the connected account and the Workers this app created, each with its CA and state" src="docs/screenshots/cloudflare-settings.png" />

**Security.** The Worker's code is fixed and contains no secrets: it answers `GET` and `HEAD` on its one CRL path, `404`/`405` for anything else, sets no cookies and no CORS headers, and sends `nosniff` and a `default-src 'none'; sandbox` CSP. Nothing on it can write; changing the CRL takes the API token, which stays encrypted in this app's database. A CRL is public by design and signed by the CA, so a Worker can't forge one.

### Endpoint-hosted CRL, for endpoints that can't reach Docker or Cloudflare (Windows)

A certificate with the **endpoint-hosted** distribution point names `http://pki.<domain>/crl/<CA name>.crl`, an address no server on the network answers. (Older versions called it *placeholder*; the API value is still `placeholder`.) Windows' own revocation check can still use a CRL imported into the certificate store, but programs that download the CRL from that address (some agents, browsers, Java, OpenSSL-based tools) get nothing. For endpoints that can reach neither this server nor a Cloudflare Worker, the Windows install bundle makes the endpoint answer that address itself.

**Get it:** on the certificate, open **Export / install ▾**, choose **Windows**, answer the CA question, and use **Download .zip**. For an endpoint-hosted certificate the zip holds the CRL, `install.cmd` / `install.ps1`, `uninstall.cmd` / `uninstall.ps1`, `serve-crl.ps1` and a `README.txt` that repeats everything below.

**Install:** extract the zip anywhere and double-click **`install.cmd`**. It asks for administrator rights, shows each command before running it, stops with an explanation if a step fails, and waits for Enter before the window closes. It's safe to run again.

The scripts are unsigned, so Windows' default execution policy blocks running `install.ps1` directly ("running scripts is disabled on this system"). `install.cmd` isn't subject to that policy: it starts the script with the policy bypassed for that one run, and your setting doesn't change. The PowerShell equivalent is `powershell -ExecutionPolicy Bypass -File .\install.ps1`. If Windows warns that the publisher can't be verified, choose **Run**; unblocking the .zip first (**Properties › Unblock**) avoids the warning. A Group Policy that enforces `AllSigned` overrides the bypass; then run the commands from **Export / install** by hand.

<details>
<summary><b>What the install changes on the PC</b></summary>

Besides the certificate (and the CAs, if included), it changes only:

| What | Where | Why |
|---|---|---|
| Hosts entry `127.0.0.1 pki.<domain> # cert-generator` | `C:\Windows\System32\drivers\etc\hosts` | Sends the CRL's host name to this machine, and only on this machine |
| The CRL, `serve-crl.ps1`, `crl-hosts.txt` | `C:\ProgramData\CertGenerator` | Writable by Administrators and SYSTEM only, readable by LOCAL SERVICE |
| CRL import | Local Machine › Intermediate Certification Authorities | For Windows' own revocation check |
| URL reservation for `http://pki.<domain>:80/crl/` | `netsh http show urlacl` | Lets LOCAL SERVICE answer that one path, nothing else |
| Scheduled task **Cert Generator CRL server** | Task Scheduler | Starts the listener at boot as LOCAL SERVICE |

The listener is a few lines of PowerShell on Windows' built-in HTTP.sys (the same component IIS uses, so it shares port 80 with IIS). It answers `GET` and `HEAD` for `/crl/<name>.crl` from that folder and `404` for everything else. Several CAs and domains share one listener. The script finishes by downloading the address itself and stops with an error if nothing answers. Check it any time with `certutil -verify -urlfetch <certificate.cer>`.

</details>

**After a revocation:** nothing updates the endpoint's copy by itself. Download a new bundle and run its `install.cmd`: it replaces the CRL and restarts the listener. Until then the endpoint doesn't see the revocation.

**Back out:** double-click **`uninstall.cmd`** in the same extracted folder (keep it for this). Like the install, it asks for administrator rights, shows each step and waits before closing; it carries on past a failed step and lists what it couldn't remove. From PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1            # asks before removing CA certificates
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveCA  # removes them without asking
```

It removes the certificate, the imported CRL, the hosts line, the URL reservation and this domain from the listener. With the last domain gone it also deletes the scheduled task and `C:\ProgramData\CertGenerator`. Use the `uninstall.ps1` from the last bundle you installed: it names the current CRL. To back out by hand: delete the `# cert-generator` line from the hosts file, run `netsh http delete urlacl url=http://pki.<domain>:80/crl/`, delete the **Cert Generator CRL server** task and `C:\ProgramData\CertGenerator`, and remove the certificate and CRL in `certlm.msc`.

<details>
<summary><b>Security notes</b></summary>

- **Exposure:** HTTP.sys accepts the request on any interface, but Windows Firewall blocks inbound port 80 unless you open it, and the only thing served is the CRL, which is public by design.
- **Tampering:** a CRL is signed, so it can't be forged, but an older valid copy could hide a revocation. That's why the folder is admin-only. If it already exists and isn't owned by Administrators (any user can create folders in `C:\ProgramData`), or is a link, the install moves it aside as `CertGenerator.untrusted-<time>` and starts fresh, so nobody else can swap the script the listener runs. The listener runs as LOCAL SERVICE, not SYSTEM, and may use only the reserved path.
- **Freshness** is the real weakness: an endpoint that isn't given the new CRL keeps trusting a revoked certificate until the old CRL expires.
- **Security tools** may flag the hosts-file edit and the new startup task. That is this install; undo it with `uninstall.cmd`.
- **Port 80** taken by a program that doesn't use HTTP.sys (Apache, nginx, some Docker setups) stops the listener. `install.cmd` reports it.
- **A system-wide proxy** (`netsh winhttp show proxy`) needs `pki.<domain>` on its bypass list.

</details>

macOS and Linux bundles include the CRL file, but the local CRL server is Windows-only for now.

## Server hardening

The embedded web server is hardened for both desktop and server use.

<details>
<summary><b>Desktop mode, server mode and both: the full list</b></summary>

**Desktop mode (pywebview):**
- **Loopback only** — binds to `127.0.0.1`, never exposed to the network
- **Random port** — uses an ephemeral port each launch, not a fixed port
- **App token authentication** — a random token is generated at startup and set as an httpOnly cookie via the pywebview window; requests without the cookie are rejected with 403, preventing access from other browsers on the same machine
- **Auto-shutdown** — the server thread is daemonic and shuts down when the window closes

**Server mode (Docker / standalone):**
- **Login authentication** — on first launch, you create an admin account (optionally gated by `SETUP_TOKEN`); all subsequent access requires sign-in with username and password (bcrypt-hashed, session-based)
- **Brute-force protection** — repeated failed passwords, MFA codes, encryption passwords, or recovery keys lock that account's attempts for 1 minute, doubling up to 15 minutes. Trusted devices are unaffected
- **TOTP MFA** — optional second factor via any authenticator app; enable per-user from MFA Settings. Each code is accepted only once
- **Trusted devices** — "Trust this device" sets an httpOnly cookie with a SHA-256 hashed token; auto-login skips password and MFA for 30 days unless "Require password every visit" is enabled. Signing out forgets the device
- **Session revocation** — password resets, MFA changes, "Revoke all devices", and backup restores end every other session
- **Step-up confirmation** — private-key downloads (CA and certificate keys, any bundle that includes a key, SSH private keys in any format), backup and restore require a password or authenticator-code sign-in within the last 5 minutes; otherwise the page asks for one and retries. Confirmations share the sign-in lockout, and a trusted-device auto-login doesn't count as one. Desktop mode has no accounts (its optional sign-in is the encryption password) and is exempt
- **Session cookies** — httpOnly, `SameSite=Lax`, signed with `SECRET_KEY`; `Secure` when `COOKIE_SECURE=true`
- **Cross-site request protection** — state-changing requests from other sites are rejected (using `Sec-Fetch-Site`, falling back to `Origin`)
- **Internal API** — the routes under `/api/` are the page's own API, authenticated by the session cookie. They are not a stable public interface and can change between releases
- **Cloudflare token** — stored only encrypted with the database key (connecting requires encryption), never returned by the API, unusable while the database is locked, and scoped by you to Workers Scripts (plus one zone for a custom domain). Cloudflare calls go only to `api.cloudflare.com` with certificate verification
- **Public CRL path** — `/crl/<id>.crl` is the one unauthenticated route. It accepts only `GET` and `HEAD`, serves only CAs that opted in by issuing a certificate pointing at this server, answers unknown and unpublished CAs with the same `404`, never reads or sets a session cookie, sends the CRL as an attachment under `Content-Security-Policy: default-src 'none'` with an `ETag`, and is rate limited to 300 requests a minute per client address
- **Security headers** — a Content-Security-Policy that allows no inline script (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, and `Cache-Control: no-store` on API responses
- **No key material on the server's disk** — exports and backups stream to the browser instead of being written to an export folder. If an older version left export files in `EXPORT_DIR`, a banner offers to review and delete them (only files matching the old export names are touched)
- **Clean shutdown** — `docker stop` ends the server immediately instead of waiting for its timeout
- **Patched, minimal image** — the image applies Debian security updates at build time rather than waiting for the base image to be rebuilt, and drops `pip` (with the libraries it bundles) once the app's dependencies are installed

**Both modes:**
- **Encryption fails closed** — while an encrypted database is locked, anything that would store a private key is refused rather than written in plaintext
- **Clean exit** — `sys.exit(0)` after the UI closes ensures proper cleanup

</details>

### Account recovery

If you lose your password or MFA authenticator, use environment variables to reset on the next container start. These run once at startup — remove them afterward.

**Reset a password:**

```bash
# Docker
docker compose exec cert-generator env RESET_PASSWORD=admin:newpassword python -m app.serve &
# Or add to compose.yaml environment section, restart, then remove it
```

**Disable MFA for a locked-out user:**

```bash
# Docker
docker compose exec cert-generator env RESET_MFA=admin python -m app.serve &
# Or add to compose.yaml environment section, restart, then remove it
```

**Without Docker:**

```bash
RESET_PASSWORD=admin:newpassword python -m app.serve
RESET_MFA=admin python -m app.serve
```

`RESET_MFA` disables TOTP, clears all trusted devices, and turns off "Require password every visit" for the named user. `RESET_PASSWORD` also clears the user's trusted devices. Both end every existing session for that user, so recovering from a compromised account locks the intruder out. Neither variable affects database encryption — the master encryption password is separate from the login password.

With both MFA and database encryption enabled, the MFA page asks for the encryption password after a restart, because the MFA secret is encrypted too. Entering it also unlocks the database. If you've forgotten it, **Forgot it? Use your recovery key** on the same page takes the recovery key and a new encryption password instead.

### Forgotten encryption password

The account-recovery variables can't help here: nobody can decrypt the keys without the master password or the **recovery key**. The recovery key is shown once when you enable encryption, as five groups of five characters (`K7QM2-XR4TD-…`). Store it away from the server, in a password manager or on paper. Anyone with it and a copy of the database can read your private keys.

- **To use it**, choose **Forgot it? Use your recovery key** on the unlock screen (or on the MFA page), enter the key and a new master password. The database unlocks, and a **new recovery key** replaces the one you typed, which stops working. Case, spaces and dashes don't matter.
- **To replace it** (lost, or possibly seen), open **Encryption** settings and choose **Replace recovery key** with your current password. The old key stops working.
- **Databases encrypted before v2.6.0** have no recovery key. Their next unlock upgrades them to the new format, and a banner offers **Create recovery key**.
- Changing the master password keeps the recovery key valid. Disabling encryption removes it.

This works the same in Docker and the Windows EXE. In the EXE, if you set a username, recovery also shows it.

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
| PKCS12 | `.pfx` | Bundled cert + key, password required |

Export options per certificate:
- **Certificate + Key** — full bundle
- **Certificate Only** — public certificate
- **Private Key Only** — private key
- **Full Chain** — leaf cert + issuing CA cert + root CA cert (PEM only, for leaf certs)

A CA's export defaults to **DER · Certificate Only**, which is all an endpoint needs to trust the CA. Export a CA's **Certificate + Key** only for a device that issues certificates with it, such as a firewall or proxy doing TLS inspection, or to move the CA to another server; never install it on endpoints. CA files are named after the CA (`ca-<CA name>-certificate.der`), certificate files after the common name (`<common name>-certificate.pfx`).

## Data storage

All CAs, certificates, and SSH keys are stored in a SQLite database. When database encryption is enabled, all private keys (and the MFA secrets) are encrypted at rest with AES-256-GCM under a random 256-bit data key. The database stores that key only wrapped: once with a key derived from the master password (Scrypt), and once with one derived from the recovery key (HKDF; the recovery key is 125 random bits). Changing the password re-wraps the data key without re-encrypting anything. Backups are separate: a `.certbak` holds the decrypted data, sealed with the backup password you choose.

| Mode | Database path | Exports path |
|------|--------------|--------------|
| **Desktop** | `~/.cert-generator/certs.db` | `~/Downloads/` |
| **Docker** | `/data/db/certs.db` (host: `/opt/docker/cert-generator/db/`) | Downloaded by your browser; nothing is kept on the server |

The database format is identical in both modes. Use **Backup** to create an encrypted `.certbak` file on one and **Restore** to load it on the other — this is the supported way to migrate data between Docker and desktop.

## Development

### Running tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Browser tests drive the real UI (downloads, sign-out, CRL export, mobile layout) with Playwright and check for JavaScript and Content-Security-Policy errors:

```bash
pip install -r requirements-e2e.txt
python -m playwright install --with-deps chromium firefox webkit
python -m pytest -m e2e --browser chromium --browser firefox --browser webkit
```

Security scans before a release: Bandit and pip-audit come with `requirements-dev.txt`, and [Trivy](https://github.com/aquasecurity/trivy/releases) (a standalone binary) scans a built image with the same config CI uses:

```bash
bandit -r app -c pyproject.toml
pip-audit -r requirements.txt -r requirements-desktop.txt
docker build -t cert-generator:dev . && trivy image --config trivy.yaml --ignorefile .trivyignore.yaml cert-generator:dev
```

Editing a file under `.github/workflows/`? Lint it the same way CI does:

```bash
bash scripts/lint-workflows.sh
```

CI runs on every push and pull request to `master`:
- the unit tests on Linux (Python 3.10 and 3.14) and Windows
- the browser tests in Chromium, Firefox, and WebKit
- a Windows EXE build and its `--self-test` / `--self-test-gui` checks (the EXE is kept as a workflow artifact for 7 days)
- a Docker image build with a container smoke test, including a clean shutdown on `docker stop`, and a Trivy scan of the image's OS and Python packages (report only)
- `actionlint` against `.github/workflows/**` (only runs when those files change)
- dependency review on pull requests, which fails a PR that adds a dependency with a known high or critical advisory

A change that touches only documentation (`*.md`, `docs/**`, `LICENSE`) skips the tests, browser tests, EXE build and image build: a first `detect changes` job decides with `scripts/ci-changes.sh`, and the skipped jobs still report as passing, so required checks and the release workflow's CI check are satisfied. If that job fails or can't tell what changed, everything runs.

### Releases

Pushing a `vX.Y.Z` tag on `master` runs `.github/workflows/release.yml`. Before building anything, it requires a passing CI run for the tagged commit — an in-progress run is waited on, but a missing or failed one stops the release. Both deliverables share one version line, and the changelog decides which of them a release publishes: the version's entry in [CHANGELOG.md](CHANGELOG.md) must carry a `#### Docker` section, a `#### Windows EXE` section, or both, and at least one is required.
- **Docker image** — built once and pushed by digest; that digest is smoke-tested and scanned with Trivy (a fixable high or critical vulnerability in an OS or Python package stops the release, and the scan is uploaded to the Security tab), and only then tagged in `ghcr.io/darthrater78/cert-generator` as `X.Y.Z`, `X.Y`, and — only when the release includes Docker and is the newest — `latest`, with a build provenance attestation
- **Windows EXE** — built and self-tested on Windows, attached to the GitHub release with a SHA-256 checksum and a build provenance attestation

Whichever deliverable the entry lists is built, and the release is created only once those succeed. A deliverable with no section is not rebuilt: it stays at the version it last shipped, and the notes say so ("Docker image unchanged (2.1.0)"). GitHub's **Latest** release follows the newest release that includes the EXE, so `/releases/latest/download/CertGenerator.exe` always resolves to the current build.

## Version history

Every release, with what changed for Docker and for the Windows EXE: **[CHANGELOG.md](CHANGELOG.md)**.
