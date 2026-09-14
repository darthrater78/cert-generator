"""Find and remove export files written to EXPORT_DIR by versions before 2.0.0.

Only server mode wrote exports to a server-side folder. Desktop mode saves to
the user's own Downloads folder on purpose, so it is never touched here.
Matching is deliberately narrow: only file names the old export code produced.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_COLLISION_SUFFIX = re.compile(r" \(\d+\)")

_LEGACY_NAME_PATTERNS = (
    re.compile(r"^.+-(certificate\.(pem|der|crt|pfx)|private_key\.(pem|der)|fullchain\.pem)$"),
    re.compile(r"^.+-id_key(\.pem)?$"),
    re.compile(r"^.+\.(crl|pub)$"),
    re.compile(r"^cert-generator-backup\.certbak$"),
)


def legacy_export_dir() -> Path | None:
    """The configured EXPORT_DIR, only when explicitly set (as the Docker image does)."""
    configured = os.environ.get("EXPORT_DIR")
    if not configured:
        return None
    path = Path(configured)
    return path if path.is_dir() else None


def _is_legacy_name(name: str) -> bool:
    # The old code avoided overwrites by inserting " (n)" once, e.g. "x-certificate (1).pem".
    normalized = _COLLISION_SUFFIX.sub("", name, count=1)
    return any(p.match(normalized) for p in _LEGACY_NAME_PATTERNS)


def find_legacy_exports() -> list[Path]:
    directory = legacy_export_dir()
    if directory is None:
        return []
    return sorted(
        entry for entry in directory.iterdir()
        if not entry.is_symlink() and entry.is_file() and _is_legacy_name(entry.name)
    )


def delete_legacy_exports() -> tuple[int, list[str]]:
    """Delete matching files. Returns (deleted count, names that could not be deleted)."""
    deleted = 0
    failed: list[str] = []
    for path in find_legacy_exports():
        try:
            path.unlink()
            deleted += 1
        except OSError:
            failed.append(path.name)
    return deleted, failed
