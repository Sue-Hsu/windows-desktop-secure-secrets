"""
Unit tests for Engine Robustness, Fuzzing, and Security Defenses.
Covers:
1. Corrupted binary & non-UTF8 decode tolerance (errors="replace")
2. Multi-byte Shift-JIS / GBK encoding compatibility
3. HtmlReporter Stored XSS entity escaping
4. Regex ReDoS catastrophic backtracking resilience (<50ms benchmark)
Zero external dependencies.
"""

import io
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from scanner.engine import ScanEngine
from scanner.models import ScanResult, Finding, Severity
from scanner.reporters import HtmlReporter
from scanner.rules import CLIENT_SECRET_ASSIGNMENT_PATTERN, LOG_SECRET_PATTERN


class TestRobustnessAndSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="robustness_test_")
        self.engine = ScanEngine()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_engine_handles_corrupted_binary_files(self):
        """Robustness: 驗證引擎掃描混雜 \\x00 與非 UTF-8 二進位損毀字元時平穩容錯且不崩潰"""
        p = Path(self.test_dir)
        bin_file = p / "corrupted_binary.py"
        # Write random binary bytes with null bytes and invalid UTF-8 sequences
        bin_file.write_bytes(b"\x00\xFF\xFE\xFD\x80\x81\xFF\n# Comment\npassword = 'test'\n\x00\x01\x02")

        # Scan should complete without raising UnicodeDecodeError
        result = self.engine.scan_path(self.test_dir)
        self.assertEqual(result.total_files_scanned, 1)

    def test_engine_handles_multibyte_encodings(self):
        """Robustness: 驗證引擎能平穩解析日文 Shift-JIS 等多位元組編碼檔案"""
        p = Path(self.test_dir)
        sjis_file = p / "japanese_sjis.py"
        content = "print('こんにちは世界')\nclient_secret = 'dummy_secret'".encode("shift_jis")
        sjis_file.write_bytes(content)

        result = self.engine.scan_path(self.test_dir)
        self.assertEqual(result.total_files_scanned, 1)
        # Should also accurately detect client_secret
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("SEC-002", rule_ids)

    def test_html_reporter_escapes_xss_payloads(self):
        """Security: 驗證 HtmlReporter 嚴格將所有欄位之惡意標籤轉換為實體，防範 Stored XSS"""
        finding = Finding(
            rule_id="XSS-001",
            rule_name="<script>alert('rule')</script>",
            severity=Severity.HIGH,
            cwe="CWE-79",
            owasp="A03:2021",
            file_path="src/<script>alert('path')</script>/test.py",
            line_number=42,
            column=1,
            snippet="<img src=x onerror=alert('snippet')>",
            message="Message with <b onmouseover=alert(1)>bold</b>",
            remediation="Remediation with <iframe src='javascript:alert(1)'></iframe>",
            references=["https://example.com/safe"]
        )
        result = ScanResult(
            target_path=".",
            total_files_scanned=1,
            total_findings=1,
            findings=[finding],
            scan_duration_seconds=0.01,
        )

        buf = io.StringIO()
        reporter = HtmlReporter()
        reporter.report(result, out=buf)
        rendered_html = buf.getvalue()

        # 1. Assert unescaped raw HTML tags DO NOT exist
        forbidden_tags = ["<script>", "<script ", "<img src=", "<b onmouseover=", "<iframe "]
        for tag in forbidden_tags:
            self.assertNotIn(tag, rendered_html, f"Raw XSS tag leaked in HTML: {tag}")

        # 2. Assert safe HTML entities DO exist
        self.assertIn("&lt;script&gt;", rendered_html)
        self.assertIn("&lt;img src=x onerror=", rendered_html)
        self.assertIn("&lt;b onmouseover=", rendered_html)
        self.assertIn("&lt;iframe src=", rendered_html)

    def test_regex_rules_redos_resilience(self):
        """Security: 驗證正則規則處理 20,000 字元長度之極端輸入時在 50ms 內完成，無災難性回溯"""
        # Construct long attack string with repeating prefixes and whitespace
        malicious_input = ("private readonly string " * 500) + ("A" * 10000) + " = 'secret';"

        start_time = time.time()
        CLIENT_SECRET_ASSIGNMENT_PATTERN.search(malicious_input)
        LOG_SECRET_PATTERN.search(malicious_input)
        elapsed = time.time() - start_time

        # Must execute within 50ms (0.05s) to guarantee ReDoS resilience
        self.assertLess(elapsed, 0.05, f"Regex evaluation took too long ({elapsed:.4f}s), potential ReDoS!")


if __name__ == "__main__":
    unittest.main()
