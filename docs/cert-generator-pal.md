# Cert Generator Pal — design

A Windows companion app that connects to a cert-generator server (Docker / server
mode), requests certificates, and installs them where Windows expects them.

**Goal: easy request and install, without giving up security.** A PC connects once
with a pairing code. After that, getting a certificate is one click, the private
key never leaves the PC, and everything the PC may ask for is set by the admin.

**LAN only.** The Pal and its API are designed for a home or office LAN, not
the public internet:

- The server answers `/api/pal/v1/*` only from private source addresses
  (RFC 1918, CGNAT `100.64.0.0/10`, loopback, link-local, IPv6 ULA); anything
  else gets `404`. CGNAT is included because SSE / ZTNA overlays (Tailscale,
  Zscaler and the like) give PCs and servers addresses there. Behind a
  reverse proxy the source is the proxy, so **don't publish `/api/pal/` through
  an internet-facing proxy** (README says so).
- The Pal accepts a pairing code only when the server address is a private IP
  or a name that resolves to one, and re-checks the resolved address on every
  connection (so a DNS change can't point it at the internet).
- The protocol does not depend on TLS (plain `http://` on a LAN is normal):
  pairing is HMAC-authenticated both ways, the root is pinned, and every later
  request is signed by the device key. TLS is still used when the server has it.

Target release: **v2.8.0** (server API + Pal ship together, one version).

---

## 1. User experience

### Admin, in cert-generator (once per PC)

*Devices → Add a Windows PC*:

| Field | Default |
|---|---|
| Label | `pc01` |
| CA | — (required) |
| Use cases, each **Off / Auto-issue / Needs approval** | Web server/RDP: Auto · This computer: Auto · Me: Needs approval · Code signing: Off |
| Allowed DNS names (patterns) | `*.<CA domain>` |
| Allowed user names (patterns, for "Me") | `*@<CA domain>` |
| Max lifetime (days) | 365 |
| CRL distribution point | same choices as the Issue form |
| Server address the PC will use | the address in the admin's browser |
| Code expires after | 24 hours |

**Create** shows the pairing code once, with a Copy button:
`CGP1.eyJ1Ijoi…` (one string; it carries the server address, a one-time key
and the root CA fingerprint).

The **Windows PCs** page (sidebar › Devices) opens with the Pal download, then
lists **requests waiting for approval** (Approve / Deny; a banner and a sidebar
count announce new ones), the PCs (what each may request, its CRL profiles, what
it holds, its Pal version, remote access and how its last request arrived;
Disconnect, Delete) and the pairing codes (unused / used / expired / revoked).

### User, on the PC

1. **Connect (once):** run `CertGeneratorPal.exe` → paste the code → **Connect** →
   UAC → "✅ Connected to *pki.lan* — *Homelab Root CA* is now trusted."
   The root, intermediate(s) and CRL are installed: **"trust only" is done here.**
2. **Pick a CRL profile.** A new pairing starts with none ("None: pick a CRL
   profile"); nothing can be requested until the user picks one.
3. **Request:** the main window shows a tile per use case the code allows (the
   others are hidden).
   Names are filled in the way a Windows (AD CS) CA builds them, so the
   usual request is a single click with nothing to type:
   - **This computer** — Wi-Fi / VPN / 802.1X machine certificate. **No names
     to enter or edit:** like AD CS's *Computer* template (subject built from
     the directory), it is issued to the PC's FQDN recorded at pairing
     (CN = SAN = `pc01.lan`). The server ignores any names the PC sends.
   - **Web server / RDP** — starts from the same FQDN; extra names (aliases,
     the PC's LAN IP) can be added within the policy, like AD CS's *Web
     Server* template. Binding it to an IIS site or Remote Desktop is not built
     yet (§4 Bindings): the certificate is installed with its key, ready to bind.
   - **Me** — user/client-auth certificate, filled with the signed-in user's
     UPN (`whoami /upn`, falling back to the e-mail the admin's pattern
     expects); editable only within the user patterns.
   - **Code signing** — CN filled with the user's display name.
   Click → **Request** → installed. If the use case needs approval: "Waiting
   for your admin" with a **Check again** button.

   **Before every install the Pal checks that the CA chain is present** and
   adds what is missing in the same step: root → `LocalMachine\Root` and
   intermediates → `LocalMachine\CA` (same UAC prompt as a machine cert), or,
   for a user cert on a PC where the user isn't an admin, root →
   `CurrentUser\Root` (Windows asks the user to confirm). Every issued cert
   comes back with its full chain, so this never needs another round trip. A
   chain whose root doesn't match the pinned fingerprint is never installed.
4. **Certificates from *Homelab Root CA*:** an audit of this PC's user **and**
   machine stores showing **only certificates that chain to the connected CA** —
   whether the Pal installed them or not (install bundles, manual imports, MMC).
   Each row: subject/names, store (machine/user), expiry, has private key,
   status from the server (valid / **revoked** / expired / not issued by this
   server), and *Installed by Pal* or *Found*. Actions: **Renew** (Pal-issued; the
   button counts down to when renewal opens), **Details** (full certificate view),
   **Remove**. (*Replace* for found certificates is not built.) See §4 "Store audit".
5. **Connectivity:** the cert server over the LAN and through the relay, and the
   CRL of the profile in use, each with a status and **Test**; **Refresh**, and
   **Log** with a debug-logging switch. The CRL profile locks while the server
   can't be reached.

Footer on every screen: version · GitHub · release notes.

### Where things are installed

| Use case | Template | Leaf cert | Key | Elevation |
|---|---|---|---|---|
| Web server / RDP | `web-server` | `LocalMachine\My` | machine key | UAC |
| This computer | `computer` | `LocalMachine\My` | machine key | UAC |
| Me | `user` | `CurrentUser\My` | user key | none |
| Code signing | `code-signing` | `CurrentUser\My` | user key | none |
| Trust (at connect) | — | Root → `LocalMachine\Root`, intermediates → `LocalMachine\CA` | — | UAC |

Email (S/MIME) is **out of v1**: a non-exportable key would make old encrypted
mail unreadable when the PC dies.

---

## 2. Protocol

All Pal endpoints are under `/api/pal/v1/`, JSON only, **no cookies or session**,
and exempt from the browser login. They are **disabled in desktop mode** (404).

### Pairing code

`CGP1.` + base64url(JSON):

```json
{"u": "https://pki.lan:5000", "i": "<code id, 16 bytes b32>", "k": "<32-byte key b64url>", "r": "<sha256 of root CA cert DER, hex>"}
```

- `k` is **never sent over the network**. The PC proves it holds it with an
  HMAC; the server proves it the same way in its reply.
- `r` pins the root CA. The Pal refuses to install a chain whose root does not
  match, so a MITM cannot plant its own root even over plain HTTP or a
  TLS-terminating proxy.
- The server stores `k` **encrypted with the database key** when encryption is
  on (it needs the plaintext to verify the HMAC), the code is single-use, expires (default 24 h),
  and can be revoked.

### Enroll — `POST /api/pal/v1/enroll`

Request body: `{code_id, device_key (SPKI DER, b64), hostname, fqdn, os, ts, nonce}`
Header `X-Pal-Proof: b64url(HMAC-SHA256(k, "CGP1-ENROLL\n" + sha256hex(body)))`.

Server: code exists, unused, unexpired, unrevoked → proof verifies
(`compare_digest`) → `|now − ts| ≤ 300 s` → `fqdn` is a DNS name and, when
web server or computer certs are allowed, matches the policy (otherwise `400`
and the code stays unused) → code marked used **atomically**
(`UPDATE … WHERE used_at IS NULL`) → device created with the code's policy
and the FQDN. **Renaming the PC means pairing it again**, the way an AD
computer account owns its name.
Failures count toward the shared attempt limiter (per code id and per IP) and
all return the same generic error.

Response: `{device_id, label, fqdn, ca_name, policy, chain: [root…issuer PEM], crls}`
with `X-Pal-Mac: b64url(HMAC-SHA256(k, "CGP1-ENROLLED\n" + sha256hex(body)))`.
The Pal verifies the MAC and that `sha256(chain[0]) == r` before installing.

### Device-signed requests

Every later call is signed by the **device key** (ECDSA P-256, created on the PC
at connect, non-exportable, TPM-backed when available):

```
X-Pal-Device: <device_id>
X-Pal-Time: <unix seconds>
X-Pal-Nonce: <16 random bytes, b64url>
X-Pal-Signature: b64url(DER ECDSA-SHA256 over
  "CGP1-REQ\n{METHOD}\n{path}\n{time}\n{nonce}\n{sha256hex(body)}")
```

Server: device exists and is not revoked → time within ±300 s → nonce unseen
for that device (stored in `pal_nonces`, pruned after 10 min) → signature
verifies. Any failure: `401` with a generic message.

| Endpoint | Purpose |
|---|---|
| `GET /api/pal/v1/device` | policy, CA chain, CRL URLs, this device's requests and certs |
| `POST /api/pal/v1/requests` | `{use_case, names, csr, renew_of?}` → `201 issued {cert, chain}` / `202 pending` / `4xx` |
| `GET /api/pal/v1/requests/<id>` | status; the cert once issued |
| `POST /api/pal/v1/status` | `{serials: [hex…]}` (≤ 500) → per serial `valid` / `revoked` / `expired` / `unknown` (no such cert under this device's CA chain). Used by the store audit |

### Issuance rules (server)

- The CSR is used **only for its public key**, after its self-signature
  verifies (proof of possession). Subject and extensions in the CSR are ignored;
  the template and the request's `names` decide the certificate.
- Allowed keys: ECDSA P-256 / P-384, RSA 2048 / 3072 / 4096.
- **"This computer"**: names come from the device record (its FQDN), never
  from the request.
- Every other DNS name / IP must match the device policy's DNS patterns (`*.lan` =
  any name under `lan`, `10.0.0.0/24` = any address in it). **A PC can never
  request a wildcard name** — that cert would impersonate every host it covers;
  the admin can still issue one in the web UI. The "Me"
  UPN / e-mail must match the user patterns. Code-signing CN: 1–64 printable
  characters.
- Lifetime: `min(requested, policy max)`.
- Use case **Off** → 403; **Auto** → issued now; **Needs approval** → queued.
- **Renewal** (`renew_of` = a cert this device holds, same use case and names,
  not revoked) is issued without approval even for "Needs approval" use cases:
  it was approved once. Changed names are a new request.
- The database must be unlocked to sign: a locked server answers `423`, and the
  Pal says "The server is locked — ask your admin to unlock it."
- Issued certs are ordinary rows in `certificates` (revocable, on the CRL, in the
  UI), with `key_pem` empty and `pal_device_id` set. Exports offer the public
  parts only for them.

### Revocation

Revoking a **device** stops all its requests; optionally revokes its
certificates (one checkbox, default on). Revoking a single cert works as today.

---

## 3. Data model (server)

```sql
pal_codes    (id TEXT PK, label, ca_id, policy JSON, key BLOB /*encrypted*/, server_url,
              created_at, expires_at, used_at, device_id, revoked_at)
pal_devices  (id TEXT PK, label, hostname, os, public_key BLOB, ca_id, policy JSON,
              code_id, created_at, last_seen, revoked_at)
pal_requests (id INTEGER PK, device_id, use_case, names JSON, csr_pem, lifetime_days,
              status /*pending|issued|denied*/, cert_id, renew_of, reason,
              created_at, decided_at)
pal_nonces   (device_id, nonce, expires_at, PK(device_id, nonce))
certificates + pal_device_id TEXT
```

---

## 4. The Pal (Windows)

- **.NET 10 (LTS) WinForms**, single-file self-contained `win-x64` EXE,
  `asInvoker` manifest; it relaunches itself elevated (`runas`) only for
  machine-scope actions (connect, web server, this computer, their renewals).
- `pal/src/CertGeneratorPal.Core` — pairing-code parsing, canonical signing
  strings, HMAC/MAC checks, API client, policy matching, chain/fingerprint
  checks. No Windows APIs; unit-tested on Linux and in CI.
- `pal/src/CertGeneratorPal` — WinForms UI, CNG keys, CSR building
  (`CertificateRequest`), `X509Store` installs.
- `pal/tests/CertGeneratorPal.Tests` — xUnit for Core, including vectors produced
  by the Python server so both sides agree byte for byte.
- No third-party NuGet packages unless one is unavoidable.

**Keys.** Device and leaf keys: CNG, *Microsoft Platform Crypto Provider* (TPM)
when present, else *Microsoft Software Key Storage Provider*; non-exportable.
Machine-scope keys in the machine key store. The device key's ACL also grants
*use* to Interactive users so the unelevated Pal can sign "Me" / code-signing
requests (⚠ verify on a real PC, with and without a TPM).

**Bindings (web server / RDP) — not built yet.** Planned: IIS: `netsh http` SSL binding plus the site's
`https` binding via `appcmd`. RDP: `Win32_TSGeneralSetting.SSLCertificateSHA1Hash`.
Both run fixed executables with argument lists — never a shell string built from
input. Renew re-applies the binding to the new thumbprint.

**Store audit.** Runs on start and on **Refresh**, unelevated (reading the
stores needs no admin rights; removing from machine stores does):

- **Stores scanned**, both `CurrentUser` and `LocalMachine`: `My`, `Root`,
  `CA`, `WebHosting`, `Remote Desktop`, `TrustedPeople`.
- **"Ties back to the CA"** = `X509Chain` with `TrustMode = CustomRootTrust`,
  `CustomTrustStore` = **only the pinned root** from pairing, `ExtraStore` = the
  intermediates the server sent, revocation `NoCheck` (status comes from the
  server instead). A cert counts only if the chain builds to that exact root
  (thumbprint match on the chain's last element). Everything else is never
  shown — not even counted.
- **CA certificates** found (the root and intermediates themselves) are listed
  in their own section, flagging copies in the wrong store (e.g. the root in
  `CurrentUser\Root` only, an intermediate in `Root`) and expired or
  superseded intermediates.
- **Status** comes from `POST /api/pal/v1/status` with the serials found; the
  server answers only for certs under this device's CA chain. Offline: the
  audit still lists them, with status "unknown — server unreachable".
- Flags: **revoked**, **expired**, **expires within 30 days**, **leaf without
  its private key**, **same names in more than one cert** (stale copies left
  after a renewal).
- The audit is local; nothing about other certs on the PC is sent to the
  server (only serials of certs that already chain to the CA).

**Stored on the PC** (`%ProgramData%\CertGeneratorPal\device.json`): server URL,
device id, root fingerprint, CNG key name, cached policy, and the thumbprints
the Pal installed. No secrets (the key is in CNG). ACL: Administrators/SYSTEM
full control, Users read.

---

## 5. Security notes

**Encryption at rest**
| Data | Where | At rest |
|---|---|---|
| Pairing-code key | server DB `pal_codes.key` | encrypted with the DB column key when database encryption is on — the same protection as CA and certificate private keys; useless once used, revoked or expired |
| Device public keys, CSRs, policies, nonces | server DB | plaintext — public data |
| Pal-issued certs | server DB `certificates` | public; **no private key stored** |
| Device and leaf private keys | PC, CNG | non-exportable; TPM-protected when present |
| `device.json` | PC | plaintext, no secrets; admin-only write |

**Login standard.** The Pal has no login: a PC authenticates with its device
key. The admin side keeps cert-generator's existing TOTP, 30-day trust and
recovery key.

**Threats covered:** stolen pairing code after use (single-use); code
brute force (128-bit id + attempt limiter); MITM / malicious proxy (HMAC both
ways at enroll, root pinned, device-signed requests, replay window + nonces);
PC asking for names it doesn't own (server-side policy); stolen `device.json`
(no key in it); compromised PC (revoke device → its requests stop, its certs
revoked).

**Known limits:** an admin on the PC can use the device key — the device *is*
the PC. "Me" certs trust the PC to say who its user is, within the user patterns
the admin set.

---

## 6. Build, release, test

- **Server:** existing `scripts/` + pytest; new `tests/test_pal_api.py`.
- **Pal locally:** `dotnet build -p:EnableWindowsTargeting=true` and
  `dotnet test` (Core) on Linux, `dotnet publish -r win-x64` for the EXE.
- **Distribution:** the Pal is never a separate release artifact. It is built in
  the Dockerfile's `pal` stage and ships only inside the server image, which
  serves it on the LAN at `/pal/CertGeneratorPal.exe`. Unsigned (SmartScreen warns).
- **One version:** `pal/Directory.Build.props` reads the version from
  `app/__init__.py`, so a Pal always carries the version of the server it shipped
  with. The Pal sends it in its User-Agent; the server records it per PC, the
  Windows PCs page flags a PC whose Pal differs from the server, and the Pal
  shows the same warning with a link to download the matching build from its server.
- **Real-PC test before merge:** connect, each use case, approval flow, renew,
  IIS/RDP binding, revoke device — with and without TPM.

## 7. Phases

1. **Server API** — tables, pairing codes, enroll, signed requests, CSR
   issuance, approval queue, admin endpoints, tests.
2. **Devices page** in the web UI.
3. **Pal core + UI** — connect, four use cases, trust, renew, store audit. ✅
   (v2.8.0-dev.1 – dev.3, then real-PC feedback rounds)
4. **Bindings** — IIS and RDP. ⬜ not built
5. **CI / release, README, screenshots, real-PC test.** ⏳ (pre-releases
   `2.8.0-dev.N` from the branch; README and screenshots done; real-PC test
   ongoing)
6. **Remote relay** (§8, R1–R4). ✅ in v2.8.0-dev.5

## 8. Remote relay (built in v2.8.0-dev.4 – dev.5)

A PC away from the LAN (a laptop at home, on the road) still renews and
requests certificates, **without exposing the server**. Decisions, 2026-10-02:
no token, end-to-end encrypted, LAN-paired PCs only, automatic LAN ↔ relay
switching with a manual button and both statuses shown.

### Shape: a mailbox, not a proxy

```
 Pal ──HTTPS──▶ relay Worker (Durable Object mailbox) ◀──outbound── server
```

- **Docker app:** *Tools › Remote connection › Set up* deploys one relay Worker
  per server, the same way CRL Workers are deployed (encrypted Cloudflare token,
  `workers.dev` or your own domain, Test / Tear down). It never calls the server.
- **The server connects out:** it keeps one WebSocket to the mailbox's Durable
  Object and polls as a fallback. It authenticates with a secret held only by
  the server and the Worker (a Worker secret binding). **Nothing on the LAN opens
  inbound**, and the direct API stays LAN-only, unchanged.
- **The Worker is fixed code:** it accepts a request from a PC, holds it until the
  server collects it, and holds the reply until the PC collects it (long poll).
  It stores only encrypted blobs, with a short TTL (10 min), and caps their size
  and count per PC.

### No token: the Worker checks each PC's key

- The server pushes to the Worker the **public keys of PCs allowed to use the
  relay**, and nothing else. The Worker refuses any message not signed by one of
  them (the same ECDSA P-256 signature, timestamp and nonce as the LAN API), so a
  leaked relay address lets nobody in.
- **Revoking or deleting a PC, or turning its remote access off, removes its key**
  from the Worker at the server's next sync (turning remote off syncs at once;
  within a minute otherwise). A pairing code carries an **Allow remote** switch;
  the Windows PCs page can change it per PC.

### End-to-end encryption

- At pairing (on the LAN only) the server also hands over a **relay public key**
  (P-256), which the Pal keeps; a PC allowed remote later learns it from a LAN
  check-in. Never from an answer that came through the relay.
- Each request is encrypted to the server with a one-time key; the reply is
  encrypted with a key derived from the same exchange, which only that request's
  sender and the server hold, so it needs no separate signature (see "Envelope
  protocol" below). The Worker can't read, alter, reorder or replay either side.
- Cloudflare sees only: a device id, sizes and times.

### LAN-paired only

- Pairing never happens through the relay: a new PC pairs on the LAN with a
  pairing code, as today. The relay serves the signed API afterwards (requests,
  status, renewals, CRL refresh for the self-hosted listener).
- The EXE download stays LAN-only.

### The Pal: automatic, with a button and both statuses

- The status area shows **two rows, LAN and Remote**, each with a dot (reachable /
  unreachable / not set up), the last check time and a **Test** link.
- **Automatic:** each operation tries the LAN first (short timeout), then the relay.
  The status bar names the path used.
- **Connect to remote** forces the relay (for testing, or a LAN that answers but
  shouldn't be used). The relay address arrives with the pairing, so there is
  nothing to paste. An existing pairing picks it up the next time the PC is on the LAN.

### Envelope protocol (CGP1 relay, v1)

The relay carries **whole signed LAN requests**, sealed. The server opens one and runs
it through the same handlers as the LAN API, so the device signature, nonce,
policy and rate limits are checked exactly as on the LAN.

Keys: the server's **relay key** (static P-256, private half encrypted with the
database key, public half pinned by the Pal at pairing) and, per request, a
**one-time P-256 key** made by the PC. The device key only signs (it is a CNG
ECDSA key), so it never takes part in key agreement.

```
shared  = ECDH(one-time key, relay key)
okm     = HKDF-SHA256(shared, salt = "CGP1-RELAY", info = epk ‖ relay_pub, 64 bytes)
k_req   = okm[0:32]      k_rep = okm[32:64]
```

**Request** (PC → Worker → server), JSON with base64url fields:

```json
{"v": 1, "d": "<device id>", "t": <unix time>, "n": "<nonce>",
 "e": "<one-time public key, SEC1 uncompressed>", "i": "<12-byte IV>",
 "c": "<AES-256-GCM(k_req, inner), tag appended>", "s": "<ECDSA P-256 / SHA-256, IEEE P1363>"}
```

- `s` is the device key's signature over `"CGP1-RELAY\n" + d + "\n" + t + "\n" + n + "\n" + e + "\n" + i + "\n" + c`,
  in the raw r‖s form WebCrypto verifies, so the Worker can refuse anything not
  signed by a PC allowed to use the relay, without being able to read it.
- GCM associated data: `"CGP1-RELAY-REQ\n" + d + "\n" + t + "\n" + n`.
- `inner` is JSON `{"method", "path", "headers": {X-Pal-*, User-Agent}, "body": base64}`:
  the signed request exactly as it would go over the LAN.

**Reply** (server → Worker → PC): `{"v": 1, "n": "<request nonce>", "i": "<IV>", "c": "<AES-256-GCM(k_rep, inner reply)>"}`,
associated data `"CGP1-RELAY-REP\n" + d + "\n" + n`, inner reply
`{"status", "headers": {X-Pal-Mac…}, "body": base64}`. Only the holder of the
one-time key can open it, and only the server could have sealed it (it needs
`shared`), so the Worker can neither read, forge nor swap replies.

The server refuses: an unknown, disconnected or not-remote-allowed device; a bad
outer signature; a time outside ±5 min; an inner path outside `/api/pal/v1/`; and
**enrollment** (pairing is LAN only).

### Build phases

- **R1:** envelope in Python and C# (shared test vectors), relay key, server-side
  dispatch, enrollment refused through the relay. No Cloudflare yet.
- **R2:** the relay Worker (Durable Object mailbox, `app/relay_worker.py`), its
  deploy (`cloudflare.deploy_relay`: the migration is sent only on the first
  upload), the server's outbound collector (`app/relay_collector.py`: long-polls
  the Worker, rate-limits per PC, pushes the allowed PCs' keys when they change),
  and set up / tear down. Tested with the Worker's real code in Node against a
  stand-in for Durable Object storage; the first real deploy happens in R3.
- **R3:** admin UI: the Windows PCs page's **Remote connection** card (set up,
  check, update the Worker, tear down; prerequisites: encryption on and
  Cloudflare connected), **Allow remote connection** on a pairing code (copied to
  the PC when it pairs) and an Allow / Turn off switch per PC with how its last
  request arrived. A PC allowed remote gets `relay: {url, public_key}` in its
  enroll reply (MACed with the pairing key) and in `GET device` over the LAN.
- **R4:** the Pal (`PalClient`): each signed request goes over the LAN, and through
  the relay when the LAN can't be reached at all (an HTTP answer is never
  retried); **Connect to remote** forces the relay for the session. Relay details
  come from the MACed enroll reply or a LAN `GET device` (kept per user in
  `%LOCALAPPDATA%\CertGeneratorPal\relay-<device>.json`), never from an answer
  that came through the relay. Connectivity shows Cert server · LAN and · Remote.

### Server side

- New table columns: `pal_devices.remote_allowed`, server relay key pair (private
  key encrypted with the database key when encryption is on).
- The collector runs in the server process, like the CRL renewal timer. It
  dispatches each decrypted request through the same handlers as the LAN API,
  so policy, approvals and rate limits are identical.
- The Windows PCs page shows per PC: last path used (LAN / remote) and the
  relay's health (connected, queue depth, last delivery).

### Notes from the build

- Durable Objects with SQLite storage are on the Workers free plan; the first
  real deploy (dev.4) worked on a free account.
- Cloudflare answers urllib's default User-Agent with 403 "error code: 1010": the
  collector and the Pal always send their own.
- A PC remote for longer than a CRL's lifetime: the self-hosted listener's CRL
  refresh goes through the relay like any other signed request.
