"""
Unit tests for CSharpRuleScanner (SEC-001 through SEC-005).
Zero external dependencies.
"""

import unittest
from scanner.rules import CSharpRuleScanner
from scanner.models import Severity


class TestCSharpRuleScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CSharpRuleScanner()

    def test_sec001_plaintext_file_write(self):
        """SEC-001: 檢測將 token 直接以明文 File.WriteAllText 存檔"""
        code = """
public class InsecureStorage {
    public void Save(string path, string api_key) {
        File.WriteAllText(path, api_key);
    }
}
"""
        findings = self.scanner.scan("Storage.cs", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sec002_hardcoded_client_secret(self):
        """SEC-002: 檢測在桌面 C# 程式碼寫死 Client Secret"""
        code = """
public class OAuthService {
    private const string ClientId = "desktop-client";
    private const string ClientSecret = "prod_sec_993848210492810482019482";
}
"""
        findings = self.scanner.scan("OAuthService.cs", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_sec003_silent_fallback_in_catch_block(self):
        """SEC-003: 檢測加密失敗時在 catch 區塊悄悄改存明文的 Silent Fallback"""
        code = """
try {
    SaveWithDPAPI(token);
} catch (CryptographicException) {
    File.WriteAllText("fallback.txt", token);
}
"""
        findings = self.scanner.scan("FallbackService.cs", code)
        self.assertTrue(any(f.rule_id == "SEC-003" for f in findings))

    def test_sec003_no_false_positive_on_fail_closed_recovery(self):
        """SEC-003 防誤報: 採取 Fail-Closed 或拋出例外時不誤報"""
        code = """
try {
    SaveWithDPAPI(token);
} catch (CryptographicException ex) {
    _logger.LogError("Encryption failed");
    throw;
}
"""
        findings = self.scanner.scan("SecureService.cs", code)
        self.assertFalse(any(f.rule_id == "SEC-003" for f in findings))

    def test_sec004_dpapi_localmachine_scope_abuse(self):
        """SEC-004: 檢測個人桌面應用誤用 DataProtectionScope.LocalMachine"""
        code = """
byte[] cipher = ProtectedData.Protect(plain, null, DataProtectionScope.LocalMachine);
"""
        findings = self.scanner.scan("DpapiService.cs", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-004")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sec004_no_false_positive_on_currentuser_scope(self):
        """SEC-004 防誤報: 正確使用 DataProtectionScope.CurrentUser 不應誤報"""
        code = """
byte[] cipher = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
"""
        findings = self.scanner.scan("DpapiService.cs", code)
        self.assertEqual(len(findings), 0)

    def test_sec005_console_logging_secret(self):
        """SEC-005: 檢測主控台輸出印出敏感金鑰"""
        code = """
Console.WriteLine($"[DEBUG] Exchanging code with ClientSecret={ClientSecret}");
"""
        findings = self.scanner.scan("Auth.cs", code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC-005")


if __name__ == "__main__":
    unittest.main()
