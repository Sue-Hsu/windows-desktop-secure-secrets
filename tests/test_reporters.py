"""
Unit tests for Reporters (JSON, Markdown, Console).
Zero external dependencies.
"""

import io
import json
import unittest
from scanner.models import ScanResult, Finding, Severity
from scanner.reporters import JsonReporter, MarkdownReporter, ConsoleReporter, HtmlReporter


class TestReporters(unittest.TestCase):
    def setUp(self):
        finding = Finding(
            rule_id="SEC-001",
            rule_name="AppData Plaintext Secret Storage",
            severity=Severity.HIGH,
            cwe="CWE-312",
            owasp="A04:2021",
            file_path="app.py",
            line_number=10,
            column=1,
            snippet="json.dump(data, f)",
            message="Plaintext persistence",
            remediation="Use DPAPI",
        )
        self.result = ScanResult(
            target_path=".",
            total_files_scanned=1,
            total_findings=1,
            findings=[finding],
            scan_duration_seconds=0.05,
        )

    def test_json_reporter_valid_syntax(self):
        """Reporter: 驗證 JsonReporter 產出合法的 JSON 格式"""
        buf = io.StringIO()
        reporter = JsonReporter()
        reporter.report(self.result, out=buf)

        output = buf.getvalue()
        data = json.loads(output)
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "SEC-001")

    def test_markdown_reporter_structure(self):
        """Reporter: 驗證 MarkdownReporter 包含摘要表格與詳細清單"""
        buf = io.StringIO()
        reporter = MarkdownReporter()
        reporter.report(self.result, out=buf)

        output = buf.getvalue()
        self.assertIn("# Windows Desktop Secret Security Scan Report", output)
        self.assertIn("| [HIGH]     | 1 |", output)
        self.assertIn("### 1. [High] SEC-001", output)

    def test_console_reporter_executes_without_error(self):
        """Reporter: 驗證 ConsoleReporter 正常寫入且無編碼例外"""
        buf = io.StringIO()
        reporter = ConsoleReporter(use_color=False)
        reporter.report(self.result, out=buf)

        output = buf.getvalue()
        self.assertIn("=== Windows Desktop Secret Scanner ===", output)
        self.assertIn("[HIGH] SEC-001", output)

    def test_html_reporter_structure(self):
        """Reporter: 驗證 HtmlReporter 產出包含精簡摘要卡片與問題代碼框的完整 HTML"""
        buf = io.StringIO()
        reporter = HtmlReporter()
        reporter.report(self.result, out=buf)

        output = buf.getvalue()
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("Windows Desktop Secret Security Scan Report", output)
        self.assertIn("Executive Summary (精簡摘要)", output)
        self.assertIn("SEC-001", output)
        self.assertIn("Remediation Guidance", output)
        self.assertIn("code-box", output)


if __name__ == "__main__":
    unittest.main()
