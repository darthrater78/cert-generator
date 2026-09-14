"""Build GitHub release notes for a version from README.md's version history.

One version, and the changelog picks what ships. A version entry carries a
"#### Docker" and/or a "#### Windows EXE" subsection; whichever is present is
built and published for that tag, and at least one is required. A deliverable
with no section is reported as unchanged, naming the release it last shipped in.

Usage:
  python scripts/release_notes.py v2.1.0 --image-digest sha256:... --exe-sha256 abc... > notes.md
  python scripts/release_notes.py v2.1.0 --check       # validate the README entry only
  python scripts/release_notes.py v2.1.0 --components  # docker=<bool> / exe=<bool> for CI
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "darthrater78/cert-generator"
IMAGE = f"ghcr.io/{REPO}"
DOCKER, EXE = "Docker", "Windows EXE"
COMPONENTS = (DOCKER, EXE)


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
    sections = {title.strip(): body.strip() for title, body in zip(parts[1::2], parts[2::2])}
    return parts[0].strip(), sections


def shipped_components(entry: str) -> tuple[str, ...]:
    """Which deliverables an entry ships. Entries with neither section — every
    version before the split — shipped both."""
    _, sections = split_sections(entry)
    present = tuple(name for name in COMPONENTS if sections.get(name))
    return present or COMPONENTS


def released_components(readme: str, version: str) -> tuple[str, ...]:
    """Deliverables to build for this release. At least one section is required:
    a release that names neither has nothing to publish."""
    _, sections = split_sections(version_entry(readme, version))
    present = tuple(name for name in COMPONENTS if sections.get(name))
    if not present:
        wanted = ", ".join("#### " + name for name in COMPONENTS)
        raise NotesError(f"version entry has no non-empty {wanted} section — nothing to release")
    return present


def all_versions(readme: str) -> list[str]:
    """Versions in version-history order, newest first."""
    return re.findall(r"^### v(\d+\.\d+\.\d+)\b", readme, re.M)


def previous_release_of(readme: str, version: str, component: str) -> str | None:
    """The newest release older than `version` that shipped `component`."""
    versions = all_versions(readme)
    start = versions.index(version) + 1 if version in versions else len(versions)
    for older in versions[start:]:
        if component in shipped_components(version_entry(readme, older)):
            return older
    return None


def previous_tag(readme: str, version: str) -> str:
    versions = all_versions(readme)
    later = versions.index(version) + 1 if version in versions else len(versions)
    return f"v{versions[later]}" if later < len(versions) else f"v{version}"


def _docker_shipped(version: str, body: str, image_digest: str | None, is_newest: bool) -> list[str]:
    major_minor = ".".join(version.split(".")[:2])
    lines = [
        body,
        "",
        "**Install**",
        "```bash",
        f"docker pull {IMAGE}:{version}",
        "```",
        f"Tags: `{version}`, `{major_minor}`" + (", `latest`" if is_newest else ""),
    ]
    if image_digest:
        lines += [
            f"Digest: `{image_digest}`",
            "",
            f"Verify provenance: `gh attestation verify oci://{IMAGE}@{image_digest} --repo {REPO}`",
        ]
    return lines


def _docker_unchanged(previous: str | None) -> list[str]:
    if not previous:
        return ["No image has been published yet."]
    return [
        f"Docker image unchanged ({previous}) — nothing in this release affects it.",
        "",
        "```bash",
        f"docker pull {IMAGE}:{previous}",
        "```",
    ]


def _exe_shipped(body: str, exe_sha256: str | None) -> list[str]:
    lines = [
        body,
        "",
        "**Download** `CertGenerator.exe` from the assets below (unsigned — Windows SmartScreen will warn).",
    ]
    if exe_sha256:
        lines += [
            "",
            f"SHA-256: `{exe_sha256}`",
            "",
            f"Verify provenance: `gh attestation verify CertGenerator.exe --repo {REPO}`",
        ]
    return lines


def _exe_unchanged(previous: str | None) -> list[str]:
    if not previous:
        return ["No EXE has been published yet."]
    return [
        f"Windows EXE unchanged ({previous}) — nothing in this release affects it.",
        "",
        f"**Download** it from the [v{previous} release]"
        f"(https://github.com/{REPO}/releases/download/v{previous}/CertGenerator.exe).",
    ]


def build_notes(version: str, readme: str, image_digest: str | None, exe_sha256: str | None,
                is_newest: bool = True) -> str:
    shipping = released_components(readme, version)
    intro, sections = split_sections(version_entry(readme, version))

    lines: list[str] = []
    if intro:
        lines += [intro, ""]

    lines += ["## 🐳 Docker (server mode)", ""]
    if DOCKER in shipping:
        lines += _docker_shipped(version, sections[DOCKER], image_digest, is_newest)
    else:
        lines += _docker_unchanged(previous_release_of(readme, version, DOCKER))
    lines += [""]

    lines += ["## 🪟 Windows EXE (desktop)", ""]
    if EXE in shipping:
        lines += _exe_shipped(sections[EXE], exe_sha256)
    else:
        lines += _exe_unchanged(previous_release_of(readme, version, EXE))
    lines += [""]

    for title, body in sections.items():
        if title not in COMPONENTS:
            lines += [f"## {title}", "", body, ""]
    lines += [f"**Full changelog:** https://github.com/{REPO}/compare/{previous_tag(readme, version)}...v{version}"]
    return "\n".join(lines).strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag", help="release tag, e.g. v2.1.0")
    parser.add_argument("--image-digest")
    parser.add_argument("--exe-sha256")
    parser.add_argument("--not-newest", action="store_true", help="an older version: latest tag does not move")
    parser.add_argument("--check", action="store_true", help="only validate the README entry")
    parser.add_argument("--components", action="store_true",
                        help="print 'docker=<bool>' and 'exe=<bool>' for the deliverables this version ships")
    args = parser.parse_args(argv)

    version = args.tag.removeprefix("v")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    try:
        if args.components:
            shipping = released_components(readme, version)
            out = f"docker={str(DOCKER in shipping).lower()}\nexe={str(EXE in shipping).lower()}\n"
        else:
            out = build_notes(version, readme, args.image_digest, args.exe_sha256, is_newest=not args.not_newest)
    except NotesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not args.check:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
