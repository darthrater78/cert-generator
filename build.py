"""Build a single-file Windows EXE with PyInstaller."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
APP_DIR = ROOT / "app"
TEMPLATES_DIR = APP_DIR / "templates"
ICON_PATH = APP_DIR / "icon.ico"


def main() -> None:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "CertGenerator",
        "--icon", str(ICON_PATH),
        "--add-data", f"{TEMPLATES_DIR}{os.pathsep}{Path('app', 'templates')}",
        "--add-data", f"{ICON_PATH}{os.pathsep}app",
        "--hidden-import", "app",
        "--hidden-import", "app.server",
        "--hidden-import", "app.crypto_engine",
        "--hidden-import", "app.db",
        "--hidden-import", "app.main",
        "--hidden-import", "app.security",
        str(ROOT / "run.py"),
    ]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"\nBuild complete: dist{os.sep}CertGenerator.exe")


if __name__ == "__main__":
    main()
