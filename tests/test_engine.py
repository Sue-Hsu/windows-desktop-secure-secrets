"""
Unit tests for ScanEngine (ignore filters, path traversal).
Zero external dependencies.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from scanner.engine import ScanEngine


class TestScanEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="scanner_test_")
        self.engine = ScanEngine()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_engine_skips_ignored_directories(self):
        """Engine: 驗證引擎自動略過 .git, node_modules, bin, obj 等目錄"""
        p = Path(self.test_dir)
        git_dir = p / ".git"
        node_dir = p / "node_modules"
        bin_dir = p / "bin"
        src_dir = p / "src"

        for d in (git_dir, node_dir, bin_dir, src_dir):
            d.mkdir(parents=True, exist_ok=True)

        # In ignored folders, write files containing violations
        vulnerable_code = 'client_secret = "secret_in_ignored_folder"'
        (git_dir / "hook.py").write_text(vulnerable_code, encoding="utf-8")
        (node_dir / "pkg.js").write_text(vulnerable_code, encoding="utf-8")
        (bin_dir / "app.py").write_text(vulnerable_code, encoding="utf-8")

        # In src, write clean code
        (src_dir / "main.py").write_text("print('hello')", encoding="utf-8")

        result = self.engine.scan_path(self.test_dir)
        self.assertEqual(result.total_files_scanned, 1)
        self.assertEqual(result.total_findings, 0)

    def test_engine_raises_on_nonexistent_path(self):
        """Engine: 驗證給予不存在路徑時拋出 FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            self.engine.scan_path(os.path.join(self.test_dir, "non_existent_folder_xyz"))


if __name__ == "__main__":
    unittest.main()
