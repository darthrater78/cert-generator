"""The README's dev-build banner (scripts/dev_banner.py)."""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dev_banner  # noqa: E402

DEV6_BODY = (
    "Sixth pre-release: **Cert Generator Pal binds web server certificates to IIS and "
    "Remote Desktop**, and keeps them bound through renewals. Not for production.\r\n\r\n"
    "## 🐳 Docker (server mode)\r\n\r\n- change\r\n\r\n**Install**\r\n```bash\r\n"
    "docker pull ghcr.io/darthrater78/cert-generator:2.8.0-dev.6\r\n```\r\n"
)


def rel(tag, prerelease=False, body="", draft=False):
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "body": body}


def test_versions_sort_dev_before_rc_before_final():
    tags = ["v2.8.0", "v2.8.0-rc.1", "v2.8.0-dev.10", "v2.8.0-dev.9", "v2.7.0", "v2.8.0-beta.1"]
    assert sorted(tags, key=dev_banner.version_key) == [
        "v2.7.0", "v2.8.0-dev.9", "v2.8.0-dev.10", "v2.8.0-beta.1", "v2.8.0-rc.1", "v2.8.0"]
    assert dev_banner.version_key("nightly") is None


def test_newest_pre_release_ahead_of_stable_is_picked():
    releases = [rel("v2.7.0"), rel("v2.8.0-dev.5", True), rel("v2.8.0-dev.6", True), rel("v2.6.0")]
    assert dev_banner.pick_dev(releases)["tag_name"] == "v2.8.0-dev.6"


def test_no_banner_once_the_stable_release_ships_or_without_a_pre_release():
    assert dev_banner.pick_dev([rel("v2.8.0-dev.6", True), rel("v2.8.0")]) is None
    assert dev_banner.pick_dev([rel("v2.7.0")]) is None
    assert dev_banner.pick_dev([rel("v2.8.0-dev.7", True, draft=True), rel("v2.7.0")]) is None
    assert dev_banner.render(None) == dev_banner.EMPTY


def test_banner_shows_tag_summary_and_image():
    svg = dev_banner.render(rel("v2.8.0-dev.6", True, DEV6_BODY))
    ET.fromstring(svg)  # well-formed
    assert "v2.8.0-dev.6" in svg
    assert "docker pull ghcr.io/darthrater78/cert-generator:2.8.0-dev.6" in svg
    text = " ".join(t.text or "" for t in ET.fromstring(svg).iter("{http://www.w3.org/2000/svg}text"))
    assert "Sixth pre-release: Cert Generator Pal binds web server" in text
    assert "**" not in svg and "Not for production." not in text


def test_banner_escapes_markup_and_caps_long_summaries():
    body = "Fixes <script> & " + "very long words " * 40
    svg = dev_banner.render(rel("v3.0.0-rc.1", True, body))
    root = ET.fromstring(svg)
    assert "<script>" not in svg
    lines = [t for t in root.iter("{http://www.w3.org/2000/svg}text") if t.get("font-size") == "16"]
    assert len(lines) == 3 and lines[-1].text.endswith("…")
    assert "docker pull" not in svg  # no image in these notes, so no pull line


def test_paginated_gh_output_is_read_page_by_page():
    pages = json.dumps([rel("v2.7.0")]) + "\n" + json.dumps([rel("v2.8.0-dev.1", True)])
    assert [r["tag_name"] for r in dev_banner.parse_pages(pages)] == ["v2.7.0", "v2.8.0-dev.1"]
