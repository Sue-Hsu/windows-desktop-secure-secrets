"""
Scanning engine for windows-desktop-secure-secrets.
Zero external dependencies.
"""

import os
import time
from pathlib import Path
from typing import List, Set, Optional

from scanner.models import ScanResult, Finding
from scanner.rules import get_scanner_for_file

# Default ignored directories
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "bin",
    "obj",
    "dist",
    "build",
    ".vs",
    ".vscode",
    ".idea",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
}

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    ".py",
    ".cs",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
}


class ScanEngine:
    def __init__(self, ignore_dirs: Optional[Set[str]] = None):
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS

    def scan_path(self, target_path: str) -> ScanResult:
        start_time = time.time()
        p = Path(target_path).resolve()

        if not p.exists():
            raise FileNotFoundError(f"Target path not found: {target_path}")

        files_to_scan: List[Path] = []
        if p.is_file():
            if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                files_to_scan.append(p)
        else:
            for root, dirs, files in os.walk(p):
                # Filter out ignored directories in-place
                dirs[:] = [d for d in dirs if d not in self.ignore_dirs and not d.startswith(".")]
                for file_name in files:
                    ext = os.path.splitext(file_name)[1].lower()
                    if ext in SUPPORTED_EXTENSIONS:
                        files_to_scan.append(Path(root) / file_name)

        all_findings: List[Finding] = []
        for file_path in files_to_scan:
            findings = self._scan_single_file(file_path)
            all_findings.extend(findings)

        duration = time.time() - start_time
        return ScanResult(
            target_path=str(p),
            total_files_scanned=len(files_to_scan),
            total_findings=len(all_findings),
            findings=all_findings,
            scan_duration_seconds=duration,
        )

    def _scan_single_file(self, file_path: Path) -> List[Finding]:
        scanner = get_scanner_for_file(str(file_path))
        if not scanner:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        try:
            return scanner.scan(str(file_path), content)
        except Exception:
            return []
