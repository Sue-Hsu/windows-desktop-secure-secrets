"""
Unit tests for JavaScriptRuleScanner (SEC-001, SEC-002, SEC-005).
Zero external dependencies.
"""

import unittest
from scanner.rules import JavaScriptRuleScanner
from scanner.models import Severity


class TestJavaScriptRuleScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = JavaScriptRuleScanner()

    def test_sec001_fs_write_secret_plaintext(self):
        """SEC-001: 檢測使用 fs.writeFileSync 裸存 API Key"""
        code = """
const fs = require('fs');
function saveToken(token) {
    fs.writeFileSync('config.json', JSON.stringify({ access_token: token }));
}
"""
        findings = self.scanner.scan("storage.js", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sec002_hardcoded_client_secret(self):
        """SEC-002: 檢測前端代碼寫死 Client Secret"""
        code = """
const client_id = "desktop-app-id";
const client_secret = "sec_993848210492810482019482";
"""
        findings = self.scanner.scan("oauth.ts", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_sec005_console_log_secret(self):
        """SEC-005: 檢測 console.log 印出密鑰"""
        code = """
console.log(`[DEBUG] Token received: ${access_token}`);
"""
        findings = self.scanner.scan("logger.ts", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-005")


if __name__ == "__main__":
    unittest.main()
