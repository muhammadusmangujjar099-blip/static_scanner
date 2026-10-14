"""
Public entry points for static scanning.
Split modules:
  - rules.py  → patterns / constants
  - engine.py → StaticScanner class
  - scanner.py → ZIP extract + run_scan_on_zip
"""

import zipfile
import shutil
import tempfile
from pathlib import Path

from app.services.engine import StaticScanner  # re-export


def extract_zip(zip_path: str, dest_dir: str) -> str:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                continue
            target = dest / member.filename
            if not str(target.resolve()).startswith(str(dest.resolve())):
                continue
            zf.extract(member, dest)
    children = list(dest.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return str(children[0])
    return str(dest)


def run_scan_on_zip(zip_path: str) -> dict:
    tmp = tempfile.mkdtemp(prefix="scan_")
    try:
        extract_root = extract_zip(zip_path, tmp)
        scanner = StaticScanner(extract_root)
        return scanner.run()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
