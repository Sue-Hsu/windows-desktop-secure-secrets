"""
Unit tests for PythonRuleScanner (SEC-001, SEC-002, SEC-005).
Zero external dependencies.
"""

import unittest
from scanner.rules import PythonRuleScanner
from scanner.models import Severity


class TestPythonRuleScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PythonRuleScanner()

    def test_sec001_plaintext_appdata_dict_dump(self):
        """SEC-001: 檢測將包含敏感金鑰的字典透過 json.dump 寫入檔案"""
        code = """
import json

def save_config(api_key):
    data = {"provider_api_key": api_key, "theme": "dark"}
    with open("config.json", "w") as f:
        json.dump(data, f)
"""
        findings = self.scanner.scan("test_app.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sec001_no_false_positive_on_normal_preferences(self):
        """SEC-001 防誤報: 儲存普通 UI 設定時絕不誤報"""
        code = """
import json

def save_preferences(theme, font_size):
    data = {"theme": theme, "font_size": font_size, "window_width": 1024}
    with open("settings.json", "w") as f:
        json.dump(data, f)
"""
        findings = self.scanner.scan("test_settings.py", code)
        self.assertEqual(len(findings), 0)

    def test_sec002_hardcoded_client_secret(self):
        """SEC-002: 檢測原始碼中寫死的 OAuth Client Secret"""
        code = """
class OAuthClient:
    client_id = "my-desktop-client-id"
    client_secret = "prod_sec_993848210492810482019482"
"""
        findings = self.scanner.scan("oauth.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_sec002_no_false_positive_on_client_id_only(self):
        """SEC-002 防誤報: 僅包含公開的 client_id 時絕不誤報"""
        code = """
class OAuthClient:
    client_id = "my-desktop-client-id"
    redirect_uri = "http://127.0.0.1:8080/callback"
"""
        findings = self.scanner.scan("oauth.py", code)
        self.assertEqual(len(findings), 0)

    def test_sec005_sensitive_secret_printed_in_log(self):
        """SEC-005: 檢測在 print 或 logger 中印出金鑰"""
        code = """
def login(token):
    print(f"DEBUG: Authenticating with access_token={token}")
"""
        findings = self.scanner.scan("login.py", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-005")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sec005_no_false_positive_on_normal_logging(self):
        """SEC-005 防誤報: 普通除錯訊息列印不應誤報"""
        code = """
def process():
    print("DEBUG: Processing batch job 42 completed successfully.")
"""
        findings = self.scanner.scan("job.py", code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
