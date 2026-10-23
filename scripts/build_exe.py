#!/usr/bin/env python3
"""
Build script to compile win-secret-scanner into a standalone Windows executable (.exe).
Uses PyInstaller to generate a single-file portable binary.

NOTE: Executable outputs in 'dist/' are automatically ignored by .gitignore
and must NOT be committed to Git repositories.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def check_pyinstaller() -> bool:
    try:
        subprocess.run(
            ["pyinstaller", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def build():
    root_dir = Path(__file__).parent.parent.resolve()
    entry_point = root_dir / "win_secret_scanner.py"
    dist_dir = root_dir / "dist"
    build_dir = root_dir / "build"

    print("==================================================")
    print("  win-secret-scanner Executable Build Utility")
    print("==================================================")
    print(f"Working directory: {root_dir}")
    print(f"Entry script:      {entry_point}")

    if not check_pyinstaller():
        print("\n[ERROR] PyInstaller is not installed or not in your PATH.")
        print("To install PyInstaller, run:")
        print("    pip install pyinstaller")
        print("\nAfter installing, run this script again:")
        print(f"    python {Path(__file__).relative_to(root_dir)}")
        sys.exit(1)

    print("\n[1/3] Cleaning previous build artifacts...")
    if dist_dir.exists():
        shutil.rmtree(dist_dir, ignore_errors=True)
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)

    print("\n[2/3] Invoking PyInstaller...")
    cmd = [
        "pyinstaller",
        "--onefile",
        "--name", "win-secret-scanner",
        "--clean",
        "--log-level", "WARN",
        str(entry_point),
    ]
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(root_dir))

    if result.returncode != 0:
        print("\n[ERROR] Build failed! Check the output above.")
        sys.exit(result.returncode)

    output_exe = dist_dir / "win-secret-scanner.exe"
    print("\n[3/3] Build completed successfully!")
    print(f"Generated standalone executable: {output_exe}")
    print("\n[SECURITY NOTICE]")
    print("The generated executable in 'dist/' is excluded by .gitignore.")
    print("Never commit binary executables to source control.")


if __name__ == "__main__":
    build()
