"""Build GitHub release notes for a version from README.md's version history.

Each version entry must have a "#### Docker" and a "#### Windows EXE" subsection
so the two deliverables' changes are listed separately. Install details (image
tags and digest, EXE checksum and attestation) are appended to each section.

Usage:
  python scripts/release_notes.py v2.1.0 --image-digest sha256:... --exe-sha256 abc... > notes.md
  python scripts/release_notes.py v2.1.0 --check     # validate the README entry only
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "darthrater78/cert-generator"
IMAGE = f"ghcr.io/{REPO}"
REQUIRED_SECTIONS = ("Docker", "Windows EXE")


class NotesError(ValueError):
    pass


def version_entry(readme: str, version: str) -> str:
    """Body of the '### vX.Y.Z — date' entry, without its heading."""
    match = re.search(rf"^### v{re.escape(version)}\b[^\n]*\n(.*?)(?=^### v|^## |\Z)", readme, re.S | re.M)
    if not match:
        raise NotesError(f"README.md has no '### v{version}' version history entry")
    return match.group(1).strip()


def split_sections(entry: str) -> tuple[str, dict[str, str]]:
    """Split an entry into its intro text and '#### Title' subsections."""
    parts = re.split(r"^#### +(.+?) *$", entry, flags=re.M)
    intro, sections = parts[0].strip(), {}
    for title, body in zip(parts[1::2], parts[2::2]):
        sections[title.strip()] = body.strip()
    missing = [name for name in REQUIRED_SECTIONS if not sections.get(name)]
    if missing:
        raise NotesError(f"version entry is missing non-empty section(s): {', '.join('#### ' + m for m in missing)}")
    return intro, sections


def build_notes(version: str, readme: str, image_digest: str | None, exe_sha256: str | None,
                is_newest: bool = True) -> str:
    intro, sections = split_sections(version_entry(readme, version))
    major_minor = ".".join(version.split(".")[:2])
    tag = f"v{version}"

    docker_install = [
        "**Install**",
        "```bash",
        f"docker pull {IMAGE}:{version}",
        "```",
        f"Tags: `{version}`, `{major_minor}`" + (", `latest`" if is_newest else ""),
    ]
    if image_digest:
        docker_install += [
            f"Digest: `{image_digest}`",
            "",
            f"Verify provenance: `gh attestation verify oci://{IMAGE}@{image_digest} --repo {REPO}`",
        ]

    exe_install = [
        "**Download** `CertGenerator.exe` from the assets below (unsigned — Windows SmartScreen will warn).",
    ]
    if exe_sha256:
        exe_install += [
            "",
            f"SHA-256: `{exe_sha256}`",
            "",
            f"Verify provenance: `gh attestation verify CertGenerator.exe --repo {REPO}`",
        ]

    lines: list[str] = []
    if intro:
        lines += [intro, ""]
    lines += ["## 🐳 Docker (server mode)", "", sections["Docker"], "", *docker_install, ""]
    lines += ["## 🪟 Windows EXE (desktop)", "", sections["Windows EXE"], "", *exe_install, ""]
    for title, body in sections.items():
        if title not in REQUIRED_SECTIONS:
            lines += [f"## {title}", "", body, ""]
    lines += [f"**Full changelog:** https://github.com/{REPO}/compare/{previous_tag(readme, version)}...{tag}"]
    return "\n".join(lines).strip() + "\n"


def previous_tag(readme: str, version: str) -> str:
    versions = re.findall(r"^### v(\d+\.\d+\.\d+)\b", readme, re.M)
    later = versions.index(version) + 1 if version in versions else len(versions)
    return f"v{versions[later]}" if later < len(versions) else f"v{version}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag", help="release tag, e.g. v2.1.0")
    parser.add_argument("--image-digest")
    parser.add_argument("--exe-sha256")
    parser.add_argument("--not-newest", action="store_true", help="an older version: latest tag does not move")
    parser.add_argument("--check", action="store_true", help="only validate the README entry")
    args = parser.parse_args(argv)

    version = args.tag.removeprefix("v")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    try:
        notes = build_notes(version, readme, args.image_digest, args.exe_sha256, is_newest=not args.not_newest)
    except NotesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not args.check:
        sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
