# Changelog

What changed in each release of Cert Generator and Cert Generator Pal. The [README](README.md) covers what the app does and how to run it.

## Version history

Each entry lists its changes per deliverable: a `#### Docker` section means the image is published for that version, a `#### Windows EXE` section means the EXE is built and attached, and anything under another heading (such as `#### Internal`) is carried into the notes as-is. Entries before v2.1.0 predate the split and shipped both.

### v2.10.0-dev.3 — 2026-10-06

Third pre-release of 2.10: the Pal's **Connectivity panel is one line per section**, its **revocation guide is laid out properly**, the Pal has the **web app's six themes**, and it **checks that it has really exited** when closed. The CA page's two CRL lifetimes are labelled. Not for production: none of the Pal's changes have run on a real Windows PC yet.

#### Docker
- **Pal — Connectivity, one line per section.** **Cert server**, **CRL**, **Windows cache** and **This PC** each show one line saying how they are doing. Click a section's name to open it for the addresses, **Test** and **View**, and its links. A section with a problem opens by itself, with a rule in its colour down the side. **Refresh all** and **Log** moved to the panel's heading
- **Pal — themes.** **Theme** in the footer offers the web app's six themes (Slate, Flashbang, OLED, Graphite, Umber, Ink) and **Match Windows**, the default, which is Slate in light mode and Ink in dark as before. Choosing one restarts the Pal. The accent stays brass
- **Pal — closing.** Closing the Pal while it is working asks first, because the step in progress would be abandoned. Once the window has closed the Pal writes to its log what was still open, and if the process is still running 5 seconds later it logs that and ends itself
- **Changed:** the Pal's **How Windows checks** guide is set in the serif at a readable width; its strip is labelled and drawn for the CA's own CRL lifetime; the outcomes are ruled, labelled notes; and the timings are a ledger with leaders
- **Changed:** a Windows cache row marked **BEHIND** says when the server's newer CRL was issued, in place of a revoked count that could match the cached one
- **Changed:** on the CA page the two CRL lifetimes are labelled rows, **Published CRL valid for** and **Exported CRL valid for**, with plain values (1 day, 10 years) that line up

#### Internal
- Pal: `Theme.cs` holds a palette per theme, read once at start from `%LOCALAPPDATA%\CertGeneratorPal\theme.txt`; `tests/test_pal_theme.py` fails when its colours differ from `app/static/theme.css`. `Program.ExitCompletely` is the exit watch; `Elevation.HelperRunning` says whether an administrator step is still running

### v2.10.0-dev.2 — 2026-10-06

Second pre-release of 2.10: the Pal's **Connectivity panel is split into sections**, the Pal shows **what Windows has cached of a CRL** and can make Windows fetch it again, and each CA's **published CRL lifetime can be shortened**. Also a fix for the Pal **freezing while removing a certificate**. Not for production: none of the Pal's changes have run on a real Windows PC yet.

#### Docker
- **Published CRL lifetime, per CA.** On the CA page, **Published CRL valid** sets how long each CRL this server publishes is valid: 1, 2, 3, 7 (the default) or 14 days. It applies to the CRL served here and to the CA's Cloudflare Worker, and the CRL is re-signed and republished at once. Clients keep a CRL until it runs out, so this is the longest a revocation can take to reach them. A shorter CRL is re-signed more often (at half its life) and leaves clients without a usable CRL sooner when the server is down. The revoke confirmation states the CA's own lifetime
- **Pal — Connectivity in sections.** The cert server and the CRL no longer share one list: **Cert server**, **CRL**, **Windows cache** and **This PC** are ruled sections, each with its own links. The profile's CRL is marked **IN USE**
- **Pal — Windows cache.** One row per CRL address of this CA shows the copy Windows holds for your account: when it was issued, how many certificates it revokes and until when Windows uses it, marked **BEHIND** when the server has published a newer one. **Clear cached CRLs** deletes your account's copies of this CA's CRLs; **Force re-check now** makes every account, service and running program fetch again what it cached before now, and asks for administrator approval
- **Pal — How Windows checks.** A guide window: when Windows looks at a CRL, how long it keeps a copy, what happens to a revoked certificate once the copy runs out, and whether a program can ask early. Its timings use the CA's own CRL lifetime
- **Changed:** the **No revocation checks** profile is **No CRL**, and the profile list reads **CRL: Cloudflare Worker** and so on, so a CRL profile no longer reads as a server
- **Fix:** removing a certificate could freeze the Pal until it was force closed. Deleting the certificate and its key, signing the revocation and waiting for the Windows administrator prompt all ran on the window's own thread; they now run in the background, and the status line says when a Windows prompt is waiting

#### Internal
- `POST /api/ca/<id>/crl/lifetime` (`days`: 1, 2, 3, 7 or 14; 423 while locked); `crl_days`, `crl_maintained` and `crl_days_choices` on `GET /api/ca/<id>`; a `crl_days` column that backups carry. A CRL is renewed at half of its own validity
- Pal: `WindowsCrlCache` reads the cache with `CryptRetrieveObjectByUrl` (cache only), clears with `certutil -urlcache <address> delete`, and the elevated helper gains `crl-resync` (`certutil -setreg chain\ChainCacheResyncFiletime @now`). `Elevation.RunAsync` never runs on the caller's thread

### v2.10.0-dev.1 — 2026-10-06

First pre-release of 2.10: **a certificate with no CRL can't be revoked**, CRL profiles can be **changed on a connected PC**, and the Pal can **show a CRL** and ask the server to **publish it now**. Not for production: none of the Pal's changes have run on a real Windows PC yet.

#### Docker
- **No CRL, no revocation.** A certificate issued without a CRL distribution point can't be revoked, because nothing would ever check. **Revoke** is unavailable for it on the CA page; removing it in the Pal or disconnecting its PC records it as gone and leaves it unrevoked, and both say so. Delete it, or issue its replacement with a CRL distribution point
- **CRL profiles can be edited on a connected PC.** **Windows PCs › Edit** now shows the revocation checkboxes, so a profile such as **None** can be added without a new pairing code. The Pal offers the new list after its next check-in. A profile that is unticked while in use stays selected in the Pal, and the server refuses new requests with it
- **Pal — View a CRL.** The CRL rows under Connectivity have a **View** link: issuer, issued and next update, and every revoked serial with its date, marking the ones installed on this PC. The CRLs this server and its Cloudflare Worker publish are listed even when another profile is in use
- **Pal — Publish CRL now.** A link under Connectivity asks the server to sign the CA's CRL again and publish it, here and to its Cloudflare Worker, and reports how many certificates it lists. At most twice a minute per CA; each use is in the activity log
- **Changed:** the Pal's **Cert server · LAN** row is **Cert server · Direct**, and the **Cert Generator (LAN)** CRL profile is **Cert Generator (Direct)** everywhere: a PC on a private overlay reaches the server directly without being on its LAN
- **Fix:** the Windows install .zip put the CA into **Personal** next to the certificate, whether or not the root was included. Its .pfx now holds only the certificate and key; the CAs go only to their own stores, and only when you choose to include them. A CA already left in Personal by an older .zip has to be deleted by hand (`certlm.msc`)
- **Fix:** the Pal's **Key** column said **Unknown** for a certificate installed by hand in the computer's store (an install .zip, a .pfx), and for any RSA key. It now reads where the key lives from the certificate itself

#### Internal
- `POST /api/pal/v1/crl/publish` (signed device, its own CA, 429 after two a minute); `revocable` on each certificate in `GET /api/pal/devices`; `POST /api/certs/<id>/revoke` answers 409 for a certificate with no `crl_dp_url`
- `PUT /api/pal/devices/<id>/policy` is now sent the edited `crl_dps`; the Pal keeps the list it was last given in `crl-<device id>.json` in its per-user folder
- `CrlList` in the Pal's core library parses a DER CRL (tested on Linux); the Pal reads `CERT_KEY_PROV_INFO_PROP_ID` when a key can't be opened

### v2.9.0 — 2026-10-05

**Binding is its own step, with your approval per role**: a certificate is requested first and put to work second, for Remote Desktop, WinRM, IIS, RD Gateway and the RD Connection Broker. Also in this release: **edit what a connected PC may request**, an **activity log**, user certificates that behave on **shared PCs**, and a **standards pass** over every certificate and CRL the app signs. It gathers the three `2.9.0-dev` pre-releases listed below.

#### Docker
- **Binding is separate from requesting.** In the Pal, a request only gets the certificate; **Bind…** on a certificate in the computer's store opens one dialog with a row per role: **Remote Desktop**, **WinRM over HTTPS**, an **IIS site**, **RD Gateway** and the **RD Connection Broker**. A role is offered when the certificate's names fit it and the PC runs it. After a new machine certificate is installed the Pal says what it already does (Wi-Fi, VPN, 802.1X, device identity such as posture checks) and offers the dialog. See [Binding a certificate](https://github.com/darthrater78/cert-generator#binding-a-certificate)
- **You decide what a PC may bind.** **Add a PC** and **Edit** have a switch per role: **Off**, **Allow** or **Needs my approval**. A bind that needs approval waits on the **Windows PCs** page beside certificate requests. PCs paired earlier allow every role, as before
- **A bind can be removed** for Remote Desktop, WinRM and an IIS site. A renewal moves every bind to the new certificate
- **Changed:** a **Web server** request for nothing but the PC's own name, on a PC that already holds a **This computer** certificate, is refused and points to Bind… on that certificate
- **Certificates issued on this page are bound the same way:** **Issue Certificate** and **Export / install** for Windows say that issuing only creates the certificate, and where to bind it
- **Edit a connected PC:** **Windows PCs › Edit** changes the certificate kinds, approvals, allowed names, longest lifetime and bind switches without a new pairing code
- **Activity log:** **Tools › Activity log** lists sign-ins, certificates issued, revoked, deleted and exported (and whether a private key left with them), PCs connecting, approvals and settings changes. Keys, passwords and pairing codes are never recorded
- **Who asked, and on which account:** each request and bind carries the Windows account the Pal ran as (reported, not attested) and an optional one-line **note for the admin**
- **Shared PCs:** a **Me** or code-signing certificate lives in one person's own store, so only the account that asked for it can report it missing
- **Remove and Revoke in the Pal:** **Remove** takes a certificate off the PC and has the server revoke it; **Revoke** revokes and leaves it installed. Offline, the revocation is kept and sent at the next check-in
- **Where a PC's keys live** shows on the server and in the Pal: **TPM**, **Software key** or **Not reported** (reported by the Pal, not TPM attestation)
- **Timestamps** on certificates: when each was issued and when it was revoked
- **Pal window:** a seal with your CA's name and the PC's domain, a certificate list that sorts by any column and always fits its width, a **Key** column, and **Help** and **Troubleshooting** links
- **Clearer wording throughout:** **Endpoint-hosted** CRL everywhere, **Publish now** and **Delete Worker** on a CA's Cloudflare Worker, **Export / install** asks **Install the root CA as well?**, and the guide is the **Certificate Guide**
- **Standards — CRLs:** every CRL now carries its **CRL Number** and **Authority Key Identifier**, as RFC 5280 requires
- **Standards — lifetimes:** a certificate or intermediate CA never outlives the CA that signs it (its expiry is capped there), an expired CA signs nothing, and new certificates are dated 5 minutes back so a PC whose clock runs behind doesn't refuse them as not yet valid
- **Standards — key usage** follows the key: an ECDSA or Ed25519 certificate no longer carries Key Encipherment, and an **Email (S/MIME)** certificate on an ECDSA key gets Key Agreement so mail can be encrypted to it
- **Names are checked before signing:** SANs must be real DNS names or IP addresses with at most one leading wildcard; an international name is issued in its `xn--` form; an e-mail address and a UPN must look like one; a CA's name and domain are at most 64 characters; an intermediate CA can't take its issuer's name. A host name over 64 characters is issued with its first label as the common name and the full name in the SAN (this includes a Pal PC with a long name)
- **Issue Certificate** says when a choice will be refused somewhere: **Ed25519** (browsers and Windows can't use it for a server) and a server lifetime over **825 days** (Apple devices refuse it)
- **Changed:** the **Me** tile no longer mentions smart card sign-in; signing in to Windows with the certificate is not supported
- **Fix:** a Me certificate's sign-in name (UPN) is no longer also written as an e-mail address
- **Fix:** a certificate that checks revocation at its CA's Cloudflare Worker was labelled **External**
- **Fix:** issuing with a name the certificate can't carry answered with a server error instead of saying what was wrong

#### Internal
- `binds` in a PC's policy; `POST /api/pal/v1/binds`, `GET /api/pal/v1/binds/<id>`, `POST /api/pal/v1/revoke`; `GET /api/pal/binds` with `…/approve` and `…/deny`; `PUT /api/pal/devices/<id>/policy`; `GET /api/activity`
- New table `pal_binds`; new columns `pal_requests.windows_user`, `pal_requests.note`, `certificates.pal_user`, `certificates.pal_binds`
- **The standalone Windows EXE is deprecated** and is not built for this release: v2.8.0 is its last build, kept available with security patches only. CI no longer builds it on every change
- A Docker-only release opens its notes with that notice and is GitHub's **Latest** release (it used to stay on the last release carrying the EXE); the README links the EXE by version instead of through `/releases/latest`
- A release's notes name the last *released* build of a deliverable it doesn't ship, never a pre-release

### v2.9.0-dev.3 — 2026-10-05

Third pre-release of 2.9: **binding is its own step, with your approval per role**, user certificates behave on **shared PCs**, requests say **who asked**, and the Pal's window is tidied. Not for production: none of the Pal's new screens have run on a real Windows PC yet.

#### Docker
- **Binding is separate from requesting.** A request only gets the certificate. **Bind…** on a certificate in the computer's store opens one dialog with a row per role: Remote Desktop, WinRM over HTTPS, an IIS site, RD Gateway and the RD Connection Broker. After a new machine certificate is installed the Pal says what it already does (a This computer certificate works at once for Wi-Fi, VPN, 802.1X and device identity such as posture checks), lists what needs a bind, and offers the dialog
- **You decide what a PC may bind.** **Add a PC** and **Edit** have a switch per role: **Off**, **Allow** or **Needs my approval**. The Pal asks the server before every bind. One that needs approval waits on the **Windows PCs** page beside certificate requests and is applied by the Pal's **Check again**. PCs paired earlier allow every role, as before
- **Changed:** a role is offered when the certificate's names fit it, whichever kind it is. Remote Desktop and WinRM need a certificate that carries the PC's own name; this replaces 2.9.0-dev.1's rule that Remote Desktop is only for This computer certificates
- **Changed:** a **Web server** request for nothing but the PC's own name, on a PC that already holds a **This computer** certificate, is refused and offers Bind… on that certificate. Ask for a Web server certificate when you need other names
- **A bind can be removed** for Remote Desktop (Windows goes back to its self-signed certificate), WinRM (the HTTPS listener is removed) and an IIS site (its https binding is removed). RD Gateway and the broker roles can only be given another certificate
- **Certificates issued on this page are bound the same way.** **Issue Certificate** now says, for Web Server and Computer certificates, that issuing only creates the certificate, and **Export / install** for Windows ends with a step pointing to the Pal's **Bind…** on that PC (or the service's own settings). A certificate installed in the computer's store with its key can be bound in the Pal like one the Pal requested
- **What uses each certificate** shows in the Pal's Notes column, now including RD Gateway and the broker roles and binds still waiting for approval, and on the server on the PC's card and the certificate's row
- **Shared PCs:** a **Me** or code-signing certificate lives in one person's own store, so only the Windows account that asked for it can report it missing. Someone else signing in and checking no longer frees its name or gets it revoked when a new one is issued
- **Who asked:** each request and bind carries the Windows account the Pal ran as (reported by the Pal, not attested) and an optional one-line **note for the admin**. Both show in the waiting list; the account stays on the issued certificate and in the activity log
- **Remove and Revoke in the Pal:** **Remove** takes a certificate off the PC and has the server revoke it in the same step when this PC was issued it; **Revoke** revokes and leaves it installed. With the server unreachable the revocation is kept on the PC and sent at the next check-in. When the server revokes a certificate, the Pal shows a notice; when one disappears from a PC another way, the server marks it **no longer on the PC, not revoked** and never revokes on absence alone
- **Pal (served by this image) — window:** a seal in the upper right carries your CA's name and the PC's domain; the certificate list sorts by any column, always fits its width instead of scrolling sideways, and is given room at the default window size (it could shrink to a sliver); **Help** and **Troubleshooting** links in the footer
- **Changed:** the **Me** tile no longer mentions smart card sign-in. The certificate is for client authentication (Wi-Fi, VPN, websites); signing in to Windows with it is not supported
- **Fix:** key usage follows the key. An ECDSA or Ed25519 certificate no longer carries Key Encipherment, which only an RSA key can do. This applies to certificates issued in the web UI as well as to the Pal's
- **Fix:** a Me certificate's sign-in name (UPN) is no longer also written as an e-mail address; an e-mail address goes in only when the request sends one
- **Fix:** the Pal flagged a Web server and a This computer certificate with the same name as an **Older copy**; it now takes the same name and the same purposes
- **Fix:** when the administrator step is answered with a different account's password, the Pal says so instead of "ended without a result"

#### Internal
- `binds` in a PC's policy; `POST /api/pal/v1/binds`, `GET /api/pal/v1/binds/<id>`, `POST /api/pal/v1/revoke`; `GET /api/pal/binds` with `…/approve` and `…/deny`; `windows_user` and `note` on `requests`; `windows_user` and `binds` on `status`
- New table `pal_binds`; new columns `pal_requests.windows_user`, `pal_requests.note`, `certificates.pal_user`, `certificates.pal_binds`
- The Pal keeps waiting binds in `pending-binds.json` and the RD Gateway and broker binds it made in `binds.json`, both in its machine folder

### v2.9.0-dev.2 — 2026-10-05

Second pre-release of 2.9, from the first run on a real Windows PC: **edit what a connected PC may request**, an **activity log**, **timestamps** on certificates, and the Pal shows **where its keys live**. Not for production.

#### Docker
- **Edit a connected PC:** **Windows PCs › Edit** changes what a PC may request (certificate kinds and their approval, allowed names, longest lifetime) without a new pairing code. The PC picks it up at its next check-in; certificates it already holds are not touched, and remote access keeps its own switch. CRL profiles are still fixed when a PC pairs
- **Activity log:** **Tools › Activity log** lists what was done, when and by whom: sign-ins and failed ones, certificates issued, revoked, deleted and exported (and whether a private key left with them), PCs connecting and what they asked for, approvals and settings changes. The newest 5,000 entries are kept; keys, passwords and pairing codes are never recorded. Entries start with this version
- **Timestamps:** each certificate row shows when it was issued and when it was revoked; the Windows PCs page shows when each of a PC's certificates was issued
- **Where a PC's key lives** moved next to the certificate's name (**key on the PC · TPM**), instead of inside the Key on PC chip
- **Pal (served by this image):** a **Key storage** line under Connectivity says whether this PC's keys live in its **TPM** or in Windows' software key store, and the certificate list has a **Key** column. Tile subtitles are shorter so they no longer cut off
- **Fix:** a certificate that checks revocation at its CA's Cloudflare Worker was labelled **External** in the CRL column; it now reads **Cloudflare Worker**, or **Not published** when the last publish failed
- Private-key exports (CA, certificate, install bundle, SSH key) are now written to the server log, with what was exported

#### Internal
- CI no longer builds the standalone Windows EXE on every change; the release workflow still builds and self-tests it for a release whose entry has a Windows EXE section. The README marks the EXE as maintenance only: no new features after v2.8.0, security patches when needed
- `PUT /api/pal/devices/<id>/policy`, `GET /api/activity`, and `key_storage` on the certificates in the Pal's `device` reply
- The container smoke test no longer fails when `grep` exits before `curl` has finished

### v2.9.0-dev.1 — 2026-10-05

First pre-release of 2.9: **clearer wording throughout**, the Pal's **TPM state shown in the app**, and **more things a certificate can be bound to** on a PC. Not for production: the Pal's new binds and its key-storage reporting have not run on a real Windows PC yet.

#### Docker
- **Export / install** asks what you are deciding: **Install the root CA as well?**, with **Root CA + certificate** or **Certificate only**. The steps read **Easiest · one .zip that installs itself**, then **By hand · 1. download the files** and **2. run these commands**
- **Where a PC's keys live is shown:** the **Windows PCs** page marks each PC's device key and each of its certificates **TPM**, **Software key** or **Not reported**, and a CA's certificate list shows it beside **Key on PC**. The Pal reports this when it makes a key; it is not TPM attestation. Web server and computer certificates issued before this version stay **Not reported** until they are renewed
- **Pal (served by this image) — Bind…:** a **This computer** certificate serves **Remote Desktop** and, new, **WinRM over HTTPS** (adds or switches the listener on port 5986; Windows Firewall is not changed). A **Web server** certificate serves an **IIS site** and, new, **RD Gateway** (restarts its service) and the **RD Connection Broker**'s publishing and single sign-on certificates. Roles the PC doesn't run aren't offered, and a renewal moves all of them to the new certificate
- **Changed:** a Web server certificate is no longer offered for Remote Desktop; use the This computer certificate. One already bound that way keeps working and still moves on renewal
- **One name for each thing:** **Endpoint-hosted** CRL everywhere (was also "self-hosted" and "On each PC"); a CA's Cloudflare Worker has **Publish now** and **Delete Worker** (were Push now and Tear down); the remote connection has **Remove**; the guide is the **Certificate Guide**, and its Quick Start names the buttons as they are
- **CA export note:** **Trust on a machine** (certificate only, which is also what PCs behind TLS inspection need) and **Signing device / CA move** (certificate and key, for the one device that signs as this CA)
- **Add a PC:** **Issuing CA**, **Pairing code works for**, **Signed-in user** (the Pal calls it "Me"), and a line saying what a CRL profile is
- Plainer text on the lock screen, the empty state, the CRL address checkbox and the restore confirmation, which now names the backup file

#### Windows EXE
- The same wording changes in the desktop app: Export / install, the CA export note, the Certificate Guide, the lock screen, the empty state and the restore confirmation
- The Cert Generator server CRL option reads **Cert Generator server (not in the desktop app)**

#### Internal
- The Pal sends `key_storage` with `enroll` and `requests`, and `device_key_storage` and `keys` with `status`; the server keeps it on the device, the request and the certificate
- The Pal's WinRM, RD Gateway and RD Connection Broker binds run a fixed Windows PowerShell script from the elevated helper, with modules loaded from Windows' own folder only
- README screenshots retaken where the screens changed

### v2.8.0 — 2026-10-04

**Cert Generator Pal**: a Windows companion app that pairs a PC with your server once, then requests, installs and renews its own certificates. Also in this release: a one-line command to authorize an SSH key on a server, and the app's own colours. It gathers the eight `2.8.0-dev` pre-releases listed below.

#### Docker
- **Cert Generator Pal**, a Windows app served by this image at `/pal/CertGeneratorPal.exe` to PCs on your LAN. **Windows PCs** (sidebar) › **Add a PC** makes a one-time pairing code; the PC pastes it once and from then on requests, installs and renews certificates in one click. See [Cert Generator Pal](https://github.com/darthrater78/cert-generator#cert-generator-pal-windows-pcs)
- **Keys are made on the PC and never leave it**: non-exportable, in the TPM when there is one. The server only sees certificate requests
- **What a PC may request** is set per PC: **Web server**, **This computer**, **Me** and **Code signing**, each off, issued right away, or after your approval. Requests waiting for approval show a count in the sidebar and a banner
- **IIS and Remote Desktop:** a Web server request can bind to an IIS site (every name, or one name via SNI) and to Remote Desktop; a PC that only needs RDP uses its This computer certificate. **Bind…** does the same for a certificate already installed. A renewal moves every binding of the old certificate to the new one before removing it
- **Windows PCs** page: the Pal download card with the LAN link and SHA-256, each PC with what it may request, its CRL profiles and what is installed on it right now, and disconnect or delete (its certificates are revoked)
- **CRL profiles:** each PC is told which CRL addresses it may use and picks one before requesting; the Pal can make the PC answer a CRL address itself, like the endpoint-hosted .zip
- **Remote connection:** **Set up** deploys a relay Worker on your Cloudflare account so paired PCs away from the LAN can request and renew, while nothing on your network opens to the internet. Requests are end-to-end encrypted to a key only this server holds, and it is off per PC until you allow it. Pairing stays LAN only. Needs database encryption on and Cloudflare connected
- **CGNAT addresses count as LAN** (`100.64.0.0/10`), so PCs and servers on overlays such as Tailscale or Zscaler can pair and request
- The Pal always carries the server's version; the Windows PCs page and the Pal warn when a PC runs one from another release
- **Issue Certificate** recommends the Pal for Windows PCs, and the **This server** CRL option is now **Cert Generator (LAN)**
- **SSH keys — Authorize on a server:** the Public key card has a one-line command to paste on the server, for **Linux / macOS** or **Windows** (PowerShell, OpenSSH Server). It sets the permissions sshd requires, adds the key once (safe to paste again), and on Windows puts an administrator's key in `administrators_authorized_keys`
- **Look:** status colours are bottle green, oxblood and sienna (sage, madder and terracotta on the dark themes); dialogs, menus and popovers have a hard offset shadow; the accent presets are named pigments. A custom accent you already chose is kept
- Issued certificates: a **Refresh** button
- Fixed: on the dark themes, a Delete button's hover text is readable; a library's error text could reach the browser on a failed export, SSH key import, encryption change or restore
- An SSH key's comment must fit on one line (up to 200 characters), since it ends the line that goes into `authorized_keys`

#### Windows EXE
- The same **Authorize on a server** command for SSH keys, new look, **Refresh** button and fixes as Docker. Cert Generator Pal needs the Docker version

#### Internal
- CI builds and tests the Pal on Windows; the README shows a banner for the newest dev build while one is ahead of the latest release
- `DESIGN.md` describes the app's visual identity; the version history moved from the README to `CHANGELOG.md`

### v2.8.0-dev.8 — 2026-10-04

Eighth pre-release: **authorize an SSH key on a server with one pasted line**, and the app's own colours in place of generic defaults. Not for production.

#### Docker
- **SSH keys — Authorize on a server:** the Public key card has a one-line command to paste on the server, for **Linux / macOS** (any distro, in bash, zsh or sh) or **Windows** (PowerShell, OpenSSH Server). On Linux and macOS it makes `~/.ssh` 700 and `authorized_keys` 600, adds the key once (safe to paste again) and restores the SELinux label on Fedora, RHEL, Rocky and Alma. On Windows an administrator's key goes to `administrators_authorized_keys` with the permissions sshd requires
- **Look:** status colours are bottle green, oxblood and sienna (sage, madder and terracotta on the dark themes) instead of stock green, red and amber; dialogs, menus and popovers drop their soft blurred shadow for a hard offset one; the accent presets are named pigments (Vermilion, Oxblood, Madder, Tyrian, Indigo dye, Prussian, Verdigris, Viridian, Olive, Sepia, Pewter). A custom accent you already chose is kept
- **Fix:** on the dark themes, a Delete button's hover text is now readable (it was white on light red)
- **Pal (served by this image):** status colours match the web app

#### Internal
- `DESIGN.md` describes the app's visual identity and the patterns to avoid; read it before UI changes

### v2.8.0-dev.7 — 2026-10-03

Seventh pre-release: **Remote Desktop without a web server certificate**. A PC that only needs RDP uses its This computer certificate. Not for production.

#### Docker
- **Pal (served by this image) — This computer for Remote Desktop:** the This computer request has **Use for Remote Desktop**, so a PC that only needs RDP gets one machine certificate for Wi-Fi, VPN, 802.1X and Remote Desktop. **Bind…** already accepted it for a certificate that's installed
- **Pal — Web server:** the tile is now just **Web server** (IIS sites and the extra names they need); it keeps **Use for Remote Desktop** for a PC reached by an alias or IP address
- Windows PCs page: the pairing code's use cases read **Web server** and **This computer … Remote Desktop** to match

### v2.8.0-dev.6 — 2026-10-02

Sixth pre-release: **Cert Generator Pal binds web server certificates to IIS and Remote Desktop**, and keeps them bound through renewals. Not for production.

#### Docker
- **Pal (served by this image) — bindings:** the Web server / RDP request has **Use for Remote Desktop** and **Bind to an IIS site** (site, port, and every name or one of the certificate's names via SNI); **Bind…** does the same for a certificate already in the computer's store. The site's https binding is added when missing, and Remote Desktop's service is given read access to the key
- **Pal — renewals keep working:** before the old certificate is removed (the server revokes it), every HTTPS binding, IIS site and Remote Desktop that used it moves to the new one, including bindings made by hand. If that can't be done, the old certificate stays installed and the Pal says so
- **Pal — certificate list:** shows what uses each certificate; **Remove** and a CRL profile switch warn before taking away one in use
- Windows PCs page: disconnected PCs are listed last

### v2.8.0-dev.5 — 2026-10-02

Fifth pre-release: **Cert Generator Pal uses the remote relay**. A PC allowed remote connection requests and renews certificates away from your LAN. Not for production.

#### Docker
- **Pal (served by this image) — remote connection:** a PC paired on the LAN with remote allowed learns the relay's address and key from your server. When the LAN can't be reached, each request goes through the relay instead, end-to-end encrypted to your server's relay key; a refusal from your server is never retried through the relay
- **Pal — Connectivity:** a **Cert server · LAN** row and a **Cert server · Remote** row, each with status, time and **Test**; **Connect to remote** uses only the relay for the session (to test it, or when the LAN shouldn't be used) and **Use LAN first** switches back. The CRL profile stays available while either route answers
- The Pal only takes relay details from your server over the LAN (or in its pairing reply), never through the relay itself

### v2.8.0-dev.4 — 2026-10-02

Fourth pre-release: the server side of the **remote relay** for Cert Generator Pal, to try against a real Cloudflare account. The Pal doesn't use the relay yet (that comes next). Not for production.

#### Docker
- **Download the Pal** from the top of the Windows PCs page: a download card with the LAN link to copy and the SHA-256; the page header and the Issue Certificate dialog offer it too
- **Remote connection** (Windows PCs page): **Set up** deploys a relay Worker on your `workers.dev` subdomain. Paired PCs away from the LAN will reach this server through it, while **nothing on your network opens to the internet**: the server collects from the Worker over outbound HTTPS. Needs database encryption on and Cloudflare connected. **Check now** shows whether the server is collecting; **Update Worker** and **Tear down** manage it
- Requests through the relay are **end-to-end encrypted** to a key only this server holds (a one-time key per request, ECDH P-256, AES-256-GCM): Cloudflare can't read, change or replay them, and the Worker accepts only envelopes signed by a PC you allowed
- **Allow remote connection** on a pairing code, and an **Allow / Turn off** switch per PC (off by default); each PC shows whether its last request came over the LAN or through the relay. Pairing is LAN only, never through the relay

### v2.8.0-dev.3 — 2026-10-02

Third pre-release for testing Cert Generator Pal. Not for production.

#### Docker
- **Issue Certificate** recommends Cert Generator Pal for Windows PCs (the key never leaves the PC; it requests, installs and renews itself), with a **Windows PCs** button; issuing by hand stays for servers, appliances and other systems
- The **This server** CRL option is now **Cert Generator (LAN)**: in the Issue dialog, the CRL column, the Windows PCs page, Add a PC and the Pal's CRL profiles

### v2.8.0-dev.2 — 2026-10-02

Second pre-release for testing Cert Generator Pal on a real PC. Not for production.

#### Docker
- **CGNAT addresses count as LAN:** the Pal API and the Pal accept `100.64.0.0/10` along with RFC 1918, so PCs and servers on SSE / ZTNA overlays such as Tailscale or Zscaler can pair and request
- **Pal (served by this image) — Connectivity:** one row for the **cert server** (a signed request, timed) and one for the **CRL profile in use**, each with a coloured status and a **Test** link; **Refresh** re-checks both, and **Log** shows the Pal's log with a **Debug logging** switch (every request and check; never keys or pairing codes)
- **Pal — no CRL profile until you pick one:** after pairing the dropdown reads *None: pick a CRL profile*, and nothing can be requested until one is chosen. The CRL profile is locked while the cert server can't be reached
- **Pal — certificate view:** values line up and are never cut off, long labels wrap, and the window resizes. **Copy PEM** is gone (it could crash when another program held the clipboard); **Save…** writes PEM or .cer
- **Pal:** request tiles keep their status colour when disabled (red when the server can't be reached), and an unexpected error is logged and shown as a short message instead of the .NET crash dialog

### v2.8.0-dev.1 — 2026-10-02

Pre-release for testing Cert Generator Pal against a real server. Not for production: pairings and Pal-issued certificates made with it may need redoing before v2.8.0, and this README documents the Pal fully in v2.8.0.

#### Docker
- **Cert Generator Pal (preview)**, a Windows companion app: **Windows PCs** (sidebar, under Devices) › **Add a PC** makes a single-use pairing code that says what the PC may request (web server / RDP, this computer, the signed-in user, code signing; each issued at once or after your approval) and which CRL profiles it may use. The PC makes its own keys, so they never leave it, requests and installs certificates in one click, and renews them near expiry. LAN only
- The Pal ships only inside the Docker image, served at `/pal/CertGeneratorPal.exe` to PCs on your LAN with no sign-in needed. It always carries the server's version: the Windows PCs page and the Pal itself warn when a PC runs a Pal from another release
- **Windows PCs** page: each PC with what it may request, its CRL profiles and what is installed on it right now; approve or deny requests; disconnect or delete a PC (its certificates are revoked). Requests waiting for approval show a count in the sidebar and a banner, checked every minute
- Issued certificates: a **Refresh** button, and the row actions line up whether a certificate offers Export or has its key on a PC
- Fixed: a library's error text could reach the browser on a failed export, SSH key import, encryption change or restore; those now answer with the app's own message

### v2.7.0 — 2026-10-01

#### Docker
- **Cloudflare Worker CRL distribution point.** Each CA can publish its CRL from its own Cloudflare Worker, set up entirely in the app: **Tools › Cloudflare** connects an API token (stored encrypted, so database encryption must be on), and the CA page's **Cloudflare Worker for CRL** card deploys the Worker on `workers.dev` or your own domain, then offers **Test**, **Refresh**, **Push now**, **View live CRL**, **Copy** and **Tear down**. Issue certificates with **Distribution point › Cloudflare Worker (this CA)**. See [Cloudflare Worker CRL](https://github.com/darthrater78/cert-generator#cloudflare-worker-crl)
- **Test** fetches the Worker's CRL over plain HTTP and HTTPS from this server, checks its signature, freshness and that it matches the last push, and recommends the address for certificates
- Revoking a certificate of a CA with a Worker says the new CRL will be published there and pushes it; the hourly renewal pushes too. A failed push shows **not published** on the CA page and in the log, and is retried hourly
- **Tools › Cloudflare** lists every Worker the app created in the account as in use, unlinked or missing, with **Delete** and **Delete unlinked**. Tear down and Disconnect say what they affect before they run
- The Worker is fixed, read-only code: `GET`/`HEAD` on its one CRL path, nothing else, no secrets, cookies or CORS
- **Export / install ▾** replaces Endpoint import: one panel per certificate with **Windows**, **macOS**, **Linux** and an **Export file** tab (the old Export dialog). All commands sit in one block with **Copy code**, and Windows says when PowerShell must run as Administrator
- **Download .zip** per OS: the certificate, the CA chain if the machine doesn't have it, the CRL for an endpoint-hosted certificate, and install / uninstall scripts that find their own folder, show each command and explain failures. On Windows, `install.cmd` / `uninstall.cmd` ask for administrator rights, get past the unsigned-script block for that one run, and wait for Enter before closing
- **Endpoint-hosted** is the new name of the *placeholder* distribution point, and it is for demos and testing only. On Windows, its .zip also makes the endpoint answer the CRL address itself (a hosts entry and a small HTTP.sys listener running as LOCAL SERVICE), and `uninstall.cmd` backs it all out. See [Endpoint-hosted CRL](https://github.com/darthrater78/cert-generator#endpoint-hosted-crl-for-endpoints-that-cant-reach-docker-or-cloudflare-windows)
- **No default export passwords.** The pre-filled `changeit` is gone and refused by the server; a PKCS12 export needs a password you choose
- The CA page's **Export CA certificate** and **Cloudflare Worker for CRL** are cards you can fold away, remembered per browser; the CRL note points to the certificate's Export / install as the usual way to get a CRL onto a machine
- The certificate guides fit the window, their tabs wrap instead of scrolling, and **Open in new window** pops a guide out beside the app. The Quick Start opens by itself while there are no CAs yet
- Fixed: the password confirmation opened behind the Encryption dialog when creating a recovery key from **Encryption** settings
- The Windows local CRL server won't reuse a `C:\ProgramData\CertGenerator` folder that someone else created (or a link): it moves it aside, so a non-admin user can't swap the script that runs at boot
- Fixed: the issued-certificates table ran past its card between about 1400 and 1500px wide, hiding Delete; and on phones a long CRL address pushed a Download button off the Export / install panel
- README screenshots retaken, with new ones for Export / install and the Cloudflare Worker

#### Windows EXE
- **Optional sign-in.** On first run the app offers to protect it with a username and password, which become the database encryption password, followed by a one-time recovery key that resets the password and shows the username. **Not now** and **Don't ask again** skip it
- The window opens maximized, so the whole layout fits on scaled (125–150%) displays
- The same Export / install panel, .zip bundles, endpoint-hosted rename and Windows local CRL server, no default export passwords, foldable CA cards, adaptive and pop-out guides, Quick Start on first run and the fixes above as Docker. The CRL options say the served distribution point and Cloudflare need the Docker version

#### Internal
- The browser tests close the Quick Start that now opens on an empty database; a new test covers it. The pop-out guide drops its handle on the app window, with tests for the guide page's headers, path allowlist and the desktop app token
- Tests run the Cloudflare flow against a fake Cloudflare API, and CI's Windows job parses the generated PowerShell scripts
- The Cloudflare and install-bundle routes show only the app's own error messages; any other error is logged and answered generically

### v2.6.0 — 2026-10-01

#### Docker
- **Encryption recovery key.** Enabling database encryption now shows a one-time recovery key (five groups of five characters) with **Copy** and **Download .txt**, and asks you to confirm you've stored it. If you forget the master password, **Forgot it? Use your recovery key** on the unlock screen takes the key and a new password, unlocks the database, and issues a new recovery key; the used one stops working. See [Forgotten encryption password](https://github.com/darthrater78/cert-generator#forgotten-encryption-password)
- With MFA and a locked database, the MFA page offers the same recovery: the authenticator code, the recovery key and a new encryption password. The new recovery key is shown once on the next page
- **Encryption** settings can replace the recovery key (with your current password), which revokes the old one
- **Existing encrypted databases upgrade on their next unlock**: the keys are re-encrypted under a random data key, and a banner offers **Create recovery key**. Until you create one, a forgotten password still means the keys are lost
- Changing the master password no longer re-encrypts every key; it re-wraps the data key, and the recovery key stays valid
- Wrong recovery keys count toward the same lockout as wrong encryption passwords
- **Endpoint import for each certificate.** An **Endpoint import ▾** button on every valid certificate opens the commands to install it on a machine, with **Windows**, **macOS** and **Linux** tabs and **Copy commands**. It first asks whether the root CA (and any intermediate) is already on that machine: **No** gives the whole workflow, trust chain first, with a **Download** button for each CA file the commands use; **Yes** gives just the certificate step. Either way, **Export…** opens this certificate's export in the format the commands expect. The commands follow the certificate's template and chain, with Windows stores per Microsoft's layout: the root CA in Trusted Root Certification Authorities, an intermediate in Intermediate Certification Authorities, Computer and Web Server certificates in Local Computer › Personal, and Client Auth, User, Email and Code Signing in Current User › Personal (Code Signing adds Trusted Publishers). macOS uses the System and login keychains; Linux uses the system CA bundle, `/etc/ssl` for server certificates and the NSS database for user certificates. File names match what **Export** downloads
- **CA exports are named after the CA** (`ca-<CA name>-certificate.der`) instead of its domain, so a root and an intermediate that share a domain no longer download to the same file name
- **The CA's Export defaults to DER · Certificate Only**, the file an endpoint needs to trust the CA. A note under it explains the two cases: **Trusted Endpoint** (Certificate Only, no key) and **TLS Inspection / CA Move** (Certificate + Key, only for a device that issues certificates with this CA, never on endpoints).
- The CA page groups its controls under **Export CA certificate** and **Revocation list (CRL)**, and the Import Guide's Quick Start points to Endpoint import
- **Export CRL** now says on the page that it's for the placeholder distribution point only and never changes the CRL this server publishes
- The issued-certificates table fits narrower windows: below 1700px the row actions take two rows, and below 1400px the Algorithm column (shown in the viewer) steps aside, so Revoke and Delete are never pushed out of view
- README screenshots retaken for this version, with new ones for Endpoint import and the recovery key
- Dialog buttons (Close, Export…, Copy PEM and the rest) stay pinned at the bottom of the dialog while long content, such as the certificate viewer, scrolls
- The sidebar's **Tools** stand out and are grouped by use: Create, Data, Security, Help; the sidebar is more compact, so more of it fits without scrolling
- On phones, warning banners show one line with **More**, so they no longer fill the screen
- The Certificate and SSH guides have a bolder, clearer tab bar (shorter labels: S/MIME, CRL) and section headings with an accent bar, so they're easier to scan

#### Windows EXE
- The same recovery key, unlock-screen recovery, replace option and upgrade of existing encrypted databases as Docker. **Download .txt** is browser-only; the EXE offers **Copy**
- The same Endpoint import, pinned dialog buttons, CA export default and key warning, CA export names, Export CRL note (placeholder only, as the EXE doesn't serve CRLs), grouped Tools and guide styling as Docker
- The built-in self-test now covers unlocking with the recovery key

#### Internal
- Every change to the encryption key settings runs under SQLite's write lock, so two simultaneous unlocks of a pre-2.6.0 database can't upgrade it twice with different keys

### v2.5.0 — 2026-10-01

#### Docker
- **Certificate viewer.** Click an issued certificate's name, or its new **View** button, to see what's inside it: subject and issuer, validity to the minute, serial, key type and signature algorithm, every extension (SANs including UPN, key usage, extended key usage, basic constraints, key identifiers, CRL distribution points), SHA-256 and SHA-1 fingerprints, and the PEM with a **Copy PEM** button. **Export…** opens the usual export dialog. The private key is never sent to the viewer
- **Show the issuing CA's CRL** — a checkbox in the viewer adds the CA's revocation list: whether this certificate is revoked, the CRL distribution point it carries (or a note that it has none), the CRL's next update, and every revoked serial with this certificate's highlighted. It reads what's already there
- **The CRL distribution point can be this server.** When issuing a certificate with **Include CRL Distribution Point**, choose **This server** or **Placeholder URL (offline import)**. This server writes `<address>/crl/<CA id>.crl` into the certificate (the address is pre-filled from the page you're on and can be changed to one your clients reach) and opens that path, without sign-in, for the CA. See [Publishing the CRL](#publishing-the-crl) for exposing only that path through nginx or Traefik. Requests that set the old `include_crl_dp` flag still get the placeholder
- **The served CRL keeps itself current.** This server signs a 7-day CRL for each CA it serves, re-signs it on every revocation and renews it hourly once less than half its life is left, so clients see a revocation within 7 days without any exporting. **Export CRL** now only downloads a file for offline import and never changes what is served. Revoking a certificate of a served CA needs the database unlocked
- **Revoking says what happens next**: for a certificate pointing at this server, nothing to do; for a placeholder or no distribution point, the app offers the updated CRL for download to import on each machine
- **CRL viewer.** **View CRL** on the CA page, or **Open in CRL viewer** in the certificate viewer, shows the published CRL: issuer, this and next update, signature, each revoked serial linked to its certificate, fingerprints and PEM, with **Copy PEM**. For a CA this server doesn't publish for, it lists the revocations an export would contain. The CA page now shows the **Published CRL** and the **Exported CRL** separately
- **Confirm it's you before key material leaves.** Downloading any private key, copying an SSH private key, backing up and restoring ask for your password (or an authenticator code with MFA) unless you signed in within the last 5 minutes. Trusted-device auto-login doesn't count, and confirmations share the sign-in lockout
- `/api/` is documented as the page's internal API (session-authenticated, not a stable contract)
- **A CRL column** in the certificate table shows where each certificate's CRL comes from (None, Placeholder, This server, Not published, External), and the viewer's CRL row adds whether the URL answers from your browser
- **Deleting a revoked certificate keeps it on the CRL** until it would have expired, so deleting never un-revokes it; the viewer marks such serials as "deleted certificate". Deleting a certificate that isn't revoked now warns that clients keep trusting it until it expires. Backups carry these entries and each CA's published CRL
- The in-app Import Guide's CRL tab covers both distribution points, automatic publishing and the CRL viewer
- After sign-in the first certificate authority opens right away. Previously the "No authorities yet" screen stayed up until you picked a CA, even when you had some, and it came back after deleting the open CA
- Restoring a backup now keeps each CA's CRL next-update date instead of resetting it to "Not exported"
- The image picks up Debian security updates at build time (fixes OpenSSL CVE-2026-75804 and CVE-2026-84782, and PCRE2 CVE-2026-103111, ahead of the upstream `python:3.14-slim` rebuild) and no longer ships `pip`, which removes the copies of urllib3, msgpack and setuptools it bundled

#### Windows EXE
- The same certificate viewer, CRL section, first-CA-on-load fix and restore fix as Docker
- The same CRL column, deleted-revocation handling, delete warning, revoke guidance, CRL viewer and Import Guide update. The desktop app can't serve CRLs, so its Issue Certificate dialog offers the placeholder distribution point only. It has no accounts, so it doesn't ask you to confirm before key material leaves

#### Internal
- The image's Trivy scans (CI and release) now cover Python packages as well as OS packages, so a library bundled by the base image can no longer slip past them
- CI skips the tests, browser tests, EXE build and image build when a change touches only documentation
- Bandit and pip-audit come with `requirements-dev.txt`, and the README lists the local scan commands (Bandit, pip-audit, Trivy)
- The page no longer reports an error when a reload cuts off a request still loading (it made a Firefox browser test flaky)

### v2.4.0 — 2026-09-29

#### Docker
- A full visual refresh. The dashboard is set like a registry of issued documents: serif headings, monospace for serials, dates and fingerprints, and ruled, framed sections instead of soft cards, gradients and glows. The sidebar is an index with **Authorities** and **SSH keys** as headed sections, each with a count and a **+ New** link, and intermediates drawn under their root. A selected CA's header shows its serial and what issued it; issued certificates read as a register, with status set as text, revoked entries struck through and anything expiring within 30 days flagged. Emoji are gone from the interface
- Six themes: **Slate** (the new default, a soft light grey), **Flashbang** (white), and four darks — **Graphite**, **Umber**, **Ink** and **OLED** (pure black)
- An **Appearance** menu under the title holds the theme list and the accent colour: twelve presets, a colour picker, an editable hex field (`#d4a017`, `d4a017` or `#fa0`) and a reset. The choice is saved per browser, applies on the sign-in pages too, and the accent's text and button-text shades are derived automatically so both stay above WCAG AA contrast on every theme
- The default accent is now brass (`#d4a017`), the gold of a certificate seal, instead of indigo. Indigo is still one of the presets
- Redesigned sign-in, first-run setup and MFA pages — the card is set like an engraved certificate (double rule, a fresh decorative serial on every visit, and a seal), over slowly shifting guilloché bands and a faint `openssl x509 -text` readout. The readout is fixed sample text, never data from your store. Animation stops when your system asks for reduced motion and idles while the tab is hidden
- The unencrypted-keys and old-exports warnings now run across the top of the page instead of crowding the sidebar, and the sidebar scrolls as a whole on short screens so no list or the sign-out link is ever cut off

#### Windows EXE
- The same refresh, themes, Appearance menu and accent picker as Docker — the desktop build bundles the same templates (the redesigned sign-in pages are Docker-only; the desktop app has no login)

#### Internal
- The release workflow builds the image once, smoke-tests and Trivy-scans that exact digest, and only then applies the version tags; CI adds a report-only Trivy scan and a dependency-review check on pull requests
- `docker-compose.yml` pins the image to the release version instead of `latest`
- The README's Docker section is now a copy-paste quickstart: create the data folder, save `compose.yaml`, set the session secret and start
- README screenshots redone for the new design, rendered from sample data and kept in `docs/screenshots/`

### v2.3.2 — 2026-09-16

#### Docker
- Fixed low-contrast algorithm/type badges (e.g. "RSA 4096", the CA type tag) — badge text used the same accent hue as its own translucent background tint, landing below WCAG AA contrast in both OLED Black and Flashbang. Badge text now uses a dedicated, theme-aware shade.

#### Windows EXE
- Same badge contrast fix as Docker — the desktop build bundles the same templates, so both deliverables ship identically

### v2.3.1 — 2026-09-16

#### Docker
- OLED Black theme contrast fix — brighter surface/border tokens and a redesigned shadow/glow so panel edges, modal shadows, and focus rings stay visible against the pure-black background
- Removed the indigo "Dark" theme option — only OLED Black and Flashbang remain, switchable from the sidebar swatch control, with OLED Black as the default

#### Windows EXE
- Same theme fixes as Docker — the desktop build bundles the same templates, so both deliverables ship identically

### v2.3.0 — 2026-09-16

#### Docker
- **Theme switcher** — OLED black and "Flashbang" white themes alongside the existing indigo-dark default, switchable from a sidebar swatch control; the choice persists across sessions (`localStorage`) and applies consistently on the dashboard and the login/setup/MFA screens
- Subtle animated title shimmer and swatch glow accents

#### Windows EXE
- Same theme switcher and visual accents as Docker — the desktop build bundles the same templates, so both deliverables ship identically

### v2.2.0 — 2026-09-16

#### Docker
- **Visual refresh** — gradient buttons and wordmarks, card/modal depth via shadows, focus-glow rings on inputs, a modal open/close animation, and colored accent borders on toasts and status badges, across the dashboard and the login/setup/MFA screens
- Fixed the MFA screen's encryption-password field (shown when the database is locked): it had no CSS rule at all and rendered as an unstyled browser-default input

#### Windows EXE
- Same visual refresh as Docker — the desktop build bundles the same templates, so both deliverables ship identically

#### Internal
- The release workflow now requires a passing CI run for the tagged commit before building or publishing anything, waiting out an in-progress run rather than treating it as a failure — protects against tagging a commit CI hasn't checked yet
- `.github/workflows/*.yml` are linted with `actionlint` in CI whenever they change (`scripts/lint-workflows.sh`)
- Branch protection enabled on `master`

### v2.1.0 — 2026-09-14

Resolves #15, #16, #17, #18, #19, and #20.

**Docker and the Windows EXE now share one release line.** The EXE was never published before, so this release rebuilds the image at 2.1.0 — unchanged in behaviour from 2.0.0 apart from the fixes below — to bring both deliverables onto the same version. From here on a release publishes whichever of the two its changelog entry lists, and the other stays where it is.

#### Docker
- **CRL lifetime is configurable** (#15) — choose 7 days to 10 years when exporting a CRL (default stays 10 years); the CA page shows the CRL's next-update date and warns when it is expired or due within 30 days
- **No inline script** (#16) — the page script moved to `/static/app.js` and inline event handlers were replaced, so the Content-Security-Policy now forbids inline script
- **Old export cleanup** (#17) — a banner lists files that versions before 2.0.0 left in `EXPORT_DIR` and deletes them on confirmation; unrelated files, subfolders, and symlinks are left alone
- **Clean shutdown** (#19) — the server handles SIGTERM, so `docker stop` returns in under a second instead of waiting 10 seconds
- **Browser-tested UI** (#20) — Playwright tests cover every download, sign-out, CRL export, restore, the unlock screen, and the mobile menu in Chromium, Firefox, and WebKit
- Image builds are smoke-tested before publishing and carry a build provenance attestation

#### Windows EXE
- **Released as a download** — releases that include the desktop app attach `CertGenerator.exe`, built and tested by GitHub Actions on Windows, with a SHA-256 checksum and a verifiable build provenance attestation (not code-signed)
- **pywebview 6.2.1** (from 5.3.2) and pinned PyInstaller 6.22.3
- **Self-test mode** — `CertGenerator.exe --self-test` and `--self-test-gui` check the packaged app against a throwaway database; CI runs both on every change
- Static files (including the app icon) are now bundled; previously `/static` was missing from the EXE
- Same CRL lifetime option (#15), page script changes (#16), and UI fixes as the Docker image

#### Internal
- `app/server.py` split into blueprints (`auth`, `account`, `pki`, `ssh`, `settings`) with shared helpers in `app/web.py`; long functions broken up (#18)
- CI adds Windows unit tests, browser tests, the EXE build and self-test, and a container smoke test; `release.yml` builds the Docker image and the EXE from one tag, and `scripts/release_notes.py` decides which of them a release publishes from this changelog

### v2.0.0 — 2026-09-14

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
