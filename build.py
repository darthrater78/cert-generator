"""Build a single-file Windows EXE with PyInstaller.

Install the pinned build tooling first:  pip install -r requirements-desktop.txt
Verify the result without opening a window:  dist\\CertGenerator.exe --self-test result.json
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
APP_DIR = ROOT / "app"
ICON_PATH = APP_DIR / "icon.ico"


def _data(source: Path, target: str) -> list[str]:
    return ["--add-data", f"{source}{os.pathsep}{target}"]


def main() -> None:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name", "CertGenerator",
        "--icon", str(ICON_PATH),
        *_data(APP_DIR / "templates", str(Path("app", "templates"))),
        *_data(APP_DIR / "static", str(Path("app", "static"))),
        *_data(ICON_PATH, "app"),
        "--collect-submodules", "app",
        str(ROOT / "run.py"),
    ]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"\nBuild complete: dist{os.sep}CertGenerator.exe")


if __name__ == "__main__":
    main()
