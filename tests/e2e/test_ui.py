"""End-to-end UI tests (#20): downloads, sign-out, CRL lifetime, legacy cleanup, mobile."""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pyotp
import pytest
from playwright.sync_api import Page, expect

from .conftest import ADMIN, ADMIN_PASSWORD

pytestmark = pytest.mark.e2e


def _toast(page: Page, text: str) -> None:
    expect(page.locator(".toast", has_text=text).first).to_be_visible()


def _create_ca(page: Page, domain: str) -> None:
    page.click(".sidebar-actions [data-action=showCreateCA]")
    page.fill("#caDomain", domain)
    page.click("[data-action=createCA]")
    _toast(page, "CA created")
    expect(page.locator("#caViewTitle")).to_have_text(f"{domain} Root CA")


def _download(page: Page, click_selector: str) -> tuple[str, bytes]:
    with page.expect_download() as info:
        page.click(click_selector)
    download = info.value
    return download.suggested_filename, Path(download.path()).read_bytes()


def test_csp_blocks_inline_script(signed_in: Page, live_server):
    response = signed_in.request.get(live_server.url + "/")
    assert "script-src 'self';" in response.headers["content-security-policy"]
    # Sidebar and delegated handlers work under that policy.
    signed_in.click("[data-action=showGuide]")
    signed_in.click("[data-action=showGuideTab][data-arg=guide-crl]")
    expect(signed_in.locator("#guide-crl")).to_be_visible()
    signed_in.click("#guideModal [data-action=hideModal]")
    expect(signed_in.locator("#guideModal")).to_be_hidden()


def test_certificate_exports_download(signed_in: Page):
    page = signed_in
    _create_ca(page, "e2e.test")

    name, data = _download(page, "[data-action=exportCA]")
    assert name == "ca-e2e.test-certificate.pfx" and len(data) > 500

    page.click("[data-action=showIssueCert]")
    page.fill("#certCN", "host.e2e.test")
    page.fill("#certSANs", "host.e2e.test, 10.0.0.5")
    page.click("[data-action=issueCert]")
    _toast(page, "issued")

    page.click("#certTableContainer [data-action=showExportCert]")
    name, data = _download(page, "[data-action=doExportCert]")
    assert name == "host.e2e.test-certificate.pfx" and len(data) > 500

    page.click("#certTableContainer [data-action=showExportCert]")
    page.select_option("#certExportFormat", "pem")
    page.select_option("#certExportPart", "chain")
    name, data = _download(page, "[data-action=doExportCert]")
    assert name == "host.e2e.test-fullchain.pem" and data.count(b"BEGIN CERTIFICATE") == 2

    # no distribution point on this server: revoking offers the updated CRL for import
    name, _ = _download(page, "#certTableContainer [data-action=revokeCert]")
    assert name.endswith(".crl")


def test_crl_lifetime_and_next_update(signed_in: Page):
    page = signed_in
    _create_ca(page, "crl.test")
    expect(page.locator("#caInfo")).to_contain_text("Not exported")
    page.select_option("#crlLifetime", "90")
    name, data = _download(page, "[data-action=exportCRL]")
    assert name.endswith(".crl") and data[:1] == b"\x30"
    _toast(page, "CRL valid until")
    expect(page.locator("#caInfo .badge-active", has_text="20")).to_be_visible()

    page.select_option("#crlLifetime", "7")
    _download(page, "[data-action=exportCRL]")
    expect(page.locator("#caInfo")).to_contain_text("re-export soon")


def test_ssh_key_downloads(signed_in: Page):
    page = signed_in
    page.click("[data-action=showCreateSSHKey]")
    page.fill("#sshKeyName", "e2e-key")
    page.select_option("#sshKeyAlgorithm", "ed25519")
    page.click("[data-action=generateSSHKey]")
    _toast(page, "SSH key generated")

    page.select_option("#sshExportPart", "public")
    name, data = _download(page, "[data-action=exportSSHKey]")
    assert name == "e2e-key.pub" and data.startswith(b"ssh-ed25519 ")
    page.select_option("#sshExportPart", "private")
    name, data = _download(page, "[data-action=exportSSHKey]")
    assert name == "e2e-key-id_key" and b"OPENSSH PRIVATE KEY" in data


def test_backup_download_and_restore(signed_in: Page, tmp_path):
    page = signed_in
    _create_ca(page, "backup.test")
    page.click("[data-action=showBackupModal]")
    page.fill("#backupPassword", "backup-pass")
    page.fill("#backupPasswordConfirm", "backup-pass")
    name, data = _download(page, "[data-action=createBackup]")
    assert name == "cert-generator-backup.certbak" and data.startswith(b"CERTBAK")

    backup_file = tmp_path / name
    backup_file.write_bytes(data)
    page.click("[data-action=showRestoreModal]")
    page.set_input_files("#restoreFile", str(backup_file))
    page.fill("#restorePassword", "backup-pass")
    page.click("[data-action=restoreBackup]")
    _toast(page, "Restored: 1 CAs")


def test_sign_out_from_sidebar(signed_in: Page, live_server):
    signed_in.click(".signout-link")
    signed_in.wait_for_url(live_server.url + "/login")
    assert signed_in.request.get(live_server.url + "/api/ca").status == 401


def test_sign_out_from_mfa_page(signed_in: Page, live_server, browser):
    page = signed_in
    secret = page.request.post(live_server.url + "/api/mfa/setup", data={}).json()["secret"]
    confirm = page.request.post(live_server.url + "/api/mfa/confirm", data={"code": pyotp.TOTP(secret).now()})
    assert confirm.ok

    context = browser.new_context()
    other = context.new_page()
    other.goto(live_server.url + "/login")
    other.fill("#username", ADMIN)
    other.fill("#password", ADMIN_PASSWORD)
    other.click("button[type=submit]")
    other.wait_for_url(live_server.url + "/mfa")
    other.click("button.link-button")
    other.wait_for_url(live_server.url + "/login")
    context.close()


def test_legacy_exports_banner_cleanup(signed_in: Page, live_server):
    legacy = live_server.export_dir / "old-host-certificate.pfx"
    unrelated = live_server.export_dir / "notes.txt"
    legacy.write_bytes(b"x")
    unrelated.write_bytes(b"x")
    page = signed_in
    page.reload()
    banner = page.locator("#legacyExportsBanner")
    expect(banner).to_be_visible()
    expect(page.locator("#legacyExportsCount")).to_have_text("1")
    page.click("[data-action=deleteLegacyExports]")
    _toast(page, "Deleted 1 old export files")
    expect(banner).to_be_hidden()
    assert not legacy.exists() and unrelated.exists()


def test_locked_database_shows_unlock_overlay(signed_in: Page, live_server):
    page = signed_in
    page.click(".sidebar-actions [data-action=showEncryptionSettings]")
    page.fill("#encEnablePassword", "encryption-123")
    page.fill("#encEnableConfirm", "encryption-123")
    page.click("[data-action=doEnableEncryption]")
    _toast(page, "ncryption")
    # Simulate a restart: a fresh server process on the same database is locked.
    live_server.process.terminate()
    live_server.process.wait(timeout=10)
    from .conftest import _start_server
    restarted = _start_server(live_server.db_dir.parent)
    try:
        # Cookies are not port-specific and SECRET_KEY is unchanged, so the session survives the restart.
        page.goto(restarted.url + "/")
        expect(page.locator("#unlockOverlay")).to_be_visible()
        # Anything that would store a key is refused while locked.
        locked = page.request.post(restarted.url + "/api/ca", data={"domain": "locked.test"})
        assert locked.status == 423
        page.fill("#unlockPassword", "encryption-123")
        page.press("#unlockPassword", "Enter")
        expect(page.locator("#unlockOverlay")).to_be_hidden()
    finally:
        restarted.process.terminate()
        restarted.process.wait(timeout=10)
        live_server.process = restarted.process


@pytest.mark.parametrize("viewport", [{"width": 390, "height": 844}])
def test_mobile_menu_and_sign_out(page: Page, live_server, browser_errors, viewport):
    page.set_viewport_size(viewport)
    page.goto(live_server.url + "/")
    page.fill("#username", ADMIN)
    page.fill("#password", ADMIN_PASSWORD)
    page.fill("#confirm", ADMIN_PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(live_server.url + "/")
    expect(page.locator("#sidebar")).not_to_have_class("sidebar open")
    page.click("#hamburgerBtn")
    expect(page.locator("#sidebar")).to_have_class("sidebar open")
    page.click(".signout-link")
    page.wait_for_url(live_server.url + "/login")


def test_existing_ca_opens_on_load_instead_of_empty_state(signed_in: Page):
    page = signed_in
    _create_ca(page, "reload.test")
    page.reload()
    expect(page.locator("#caViewTitle")).to_have_text("reload.test Root CA")
    expect(page.locator("#welcomeView")).to_be_hidden()


def test_certificate_viewer(signed_in: Page):
    page = signed_in
    _create_ca(page, "viewer.test")
    page.click("[data-action=showIssueCert]")
    page.fill("#certCN", "www.viewer.test")
    page.fill("#certSANs", "www.viewer.test, 10.0.0.5")
    page.click("[data-action=issueCert]")
    _toast(page, "issued")

    page.click("#certTableContainer .cert-link")
    modal = page.locator("#viewCertModal")
    expect(modal).to_be_visible()
    expect(page.locator("#certViewTitle")).to_have_text("www.viewer.test")
    expect(modal).to_contain_text("DNS: www.viewer.test")
    expect(modal).to_contain_text("IP: 10.0.0.5")
    expect(modal).to_contain_text("Server Authentication")
    expect(modal).to_contain_text("SHA-256")
    assert page.input_value("#certViewPem").startswith("-----BEGIN CERTIFICATE-----")

    page.click("[data-action=exportFromCertView]")
    expect(modal).to_be_hidden()
    expect(page.locator("#exportCertModal")).to_be_visible()


def test_certificate_viewer_crl_section(signed_in: Page):
    page = signed_in
    _create_ca(page, "crlview.test")
    page.click("[data-action=showIssueCert]")
    page.fill("#certCN", "www.crlview.test")
    page.click("[data-action=issueCert]")
    _toast(page, "issued")
    _download(page, "#certTableContainer [data-action=revokeCert]")

    page.click("#certTableContainer .cert-link")
    crl = page.locator("#certViewCrl")
    expect(crl).to_be_hidden()
    page.check("#certViewShowCrl")
    expect(crl).to_contain_text("Revoked")
    expect(crl).to_contain_text("this certificate")
    page.click("#certViewCrl [data-action=viewCRL]")
    viewer = page.locator("#viewCrlModal")
    expect(viewer).to_contain_text("Revocations (not published here)")
    expect(viewer).to_contain_text("www.crlview.test")
    expect(page.locator("#crlViewPemCard")).to_be_hidden()
    page.click("#viewCrlModal [data-action=viewCertFromCrl]")
    expect(viewer).to_be_hidden()
    expect(page.locator("#viewCertModal")).to_be_visible()
    page.uncheck("#certViewShowCrl")
    expect(crl).to_be_hidden()


def test_crl_served_by_this_server(signed_in: Page, live_server, playwright):
    page = signed_in
    _create_ca(page, "served.test")
    page.click("[data-action=showIssueCert]")
    page.fill("#certCN", "www.served.test")
    expect(page.locator("#crlDpRow")).to_be_hidden()
    page.check("#certIncludeCRL")
    expect(page.locator("#certCrlDp")).to_have_value("server")
    expect(page.locator("#certCrlBaseUrl")).to_have_value(live_server.url)
    page.click("[data-action=issueCert]")
    _toast(page, "issued")

    # published as soon as a certificate points here; no export needed
    expect(page.locator("#caInfo .crl-url")).to_contain_text("/crl/")
    expect(page.locator("#caInfo")).to_contain_text("Renews automatically")

    page.click("#certTableContainer .cert-link")
    expect(page.locator("#viewCertModal")).to_contain_text(live_server.url + "/crl/")
    page.check("#certViewShowCrl")
    crl_url = page.locator("#certViewCrl .mono").first.inner_text()
    assert crl_url.startswith(live_server.url + "/crl/") and crl_url.endswith(".crl")

    anon = playwright.request.new_context()
    resp = anon.get(crl_url)
    assert resp.status == 200 and resp.headers["content-type"] == "application/pkix-crl"
    empty = len(resp.body())
    page.click("#viewCertModal [data-action=hideModal]")

    # revoking republishes the served CRL right away
    page.click("#certTableContainer [data-action=revokeCert]")
    _toast(page, "serves an updated CRL")
    assert len(anon.get(crl_url).body()) > empty
    anon.dispose()

    page.click("[data-action=viewCRL]")
    viewer = page.locator("#viewCrlModal")
    expect(viewer).to_contain_text("Published CRL")
    expect(viewer).to_contain_text("www.served.test")
    expect(page.locator("#crlViewPem")).to_have_value(re.compile("BEGIN X509 CRL"))


def test_private_key_asks_to_confirm_after_trusted_device_sign_in(signed_in: Page, live_server, browser_errors):
    page = signed_in
    page.click("[data-action=showCreateSSHKey]")
    page.fill("#sshKeyName", "reauth-key")
    page.click("[data-action=generateSSHKey]")
    _toast(page, "SSH key generated")
    # Sign in again as a trusted device, then drop the session: the next visit is
    # signed in by the device cookie alone, which doesn't count as a recent sign-in.
    page.context.clear_cookies()
    page.goto(live_server.url + "/login")
    page.fill("#username", ADMIN)
    page.fill("#password", ADMIN_PASSWORD)
    page.check("#trust_device")
    page.click("button[type=submit]")
    page.wait_for_url(live_server.url + "/")
    page.wait_for_load_state("networkidle")  # a late response would set the session cookie again
    page.context.clear_cookies(name="session")
    page.reload()
    page.click(".ssh-item >> text=reauth-key")
    page.select_option("#sshExportPart", "private")

    page.click("[data-action=exportSSHKey]")
    expect(page.locator("#reauthModal")).to_be_visible()
    page.click("[data-action=cancelReauth]")
    _toast(page, "Cancelled")

    page.click("[data-action=exportSSHKey]")
    page.fill("#reauthSecret", "wrong-password")
    page.click("[data-action=submitReauth]")
    expect(page.locator("#reauthError")).to_have_text("That password or code isn't right")
    page.fill("#reauthSecret", ADMIN_PASSWORD)
    with page.expect_download() as info:
        page.press("#reauthSecret", "Enter")
    assert b"OPENSSH PRIVATE KEY" in Path(info.value.path()).read_bytes()
    expect(page.locator("#reauthModal")).to_be_hidden()
    # the expected 403s and the failed attempt are logged by the browser as resource errors
    browser_errors[:] = [e for e in browser_errors if "status of 403" not in e and "status of 400" not in e]
