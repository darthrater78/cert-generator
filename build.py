"""Build a single-file Windows EXE with PyInstaller."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
APP_DIR = ROOT / "app"
TEMPLATES_DIR = APP_DIR / "templates"


def main() -> None:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "CertGenerator",
        "--add-data", f"{TEMPLATES_DIR}{os.pathsep}{Path('app', 'templates')}",
        "--hidden-import", "app",
        "--hidden-import", "app.server",
        "--hidden-import", "app.crypto_engine",
        "--hidden-import", "app.db",
        "--hidden-import", "app.main",
        str(ROOT / "run.py"),
    ]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"\nBuild complete: dist{os.sep}CertGenerator.exe")


if __name__ == "__main__":
    main()
