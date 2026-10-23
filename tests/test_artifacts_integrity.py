"""
Unit tests for Artifacts Integrity & Supply Chain metadata.
Covers:
1. SPDX 2.3 SBOM JSON syntax and required properties
2. CHECKSUMS.txt format and executable hash existence
3. .gitleaksignore whitelist structure
Zero external dependencies.
"""

import json
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()


class TestArtifactsIntegrity(unittest.TestCase):
    def test_sbom_spdx_structure_validity(self):
        """SupplyChain: 驗證 sbom.json 符合 SPDX 2.3 標準架構與必要套件描述"""
        sbom_path = PROJECT_ROOT / "sbom.json"
        self.assertTrue(sbom_path.exists(), "sbom.json not found in project root!")

        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Check root SPDX properties
        self.assertEqual(data.get("spdxVersion"), "SPDX-2.3")
        self.assertEqual(data.get("dataLicense"), "CC0-1.0")
        self.assertIn("creationInfo", data)
        self.assertIn("packages", data)

        # 2. Check packages list
        pkg_names = [p.get("name") for p in data.get("packages", [])]
        self.assertIn("windows-desktop-secure-secrets", pkg_names)
        self.assertIn("pyinstaller", pkg_names)
        self.assertIn("semgrep", pkg_names)

    def test_checksums_format_validity(self):
        """Release: 驗證 CHECKSUMS.txt 存在且包含合法的 64 字元 SHA-256 雜湊"""
        checksum_path = PROJECT_ROOT / "CHECKSUMS.txt"
        self.assertTrue(checksum_path.exists(), "CHECKSUMS.txt not found in project root!")

        content = checksum_path.read_text(encoding="utf-8")
        self.assertIn("dist/win-secret-scanner.exe", content)
        self.assertIn("SHA-256", content)

        # Extract 64-character hex strings
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
        self.assertGreaterEqual(len(lines), 1, "No hash entries found in CHECKSUMS.txt!")

        # First entry should be a 64-char hex string followed by space and path
        sha256_line = lines[0]
        hash_part = sha256_line.split()[0]
        self.assertEqual(len(hash_part), 64, f"Invalid SHA-256 hash length ({len(hash_part)} chars)!")

    def test_gitleaksignore_fingerprints_validity(self):
        """Secrets: 驗證 .gitleaksignore 存在且包含已宣告之測試夾具指紋"""
        ignore_path = PROJECT_ROOT / ".gitleaksignore"
        self.assertTrue(ignore_path.exists(), ".gitleaksignore not found in project root!")

        lines = [line.strip() for line in ignore_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        self.assertGreaterEqual(len(lines), 3, "Expected at least 3 whitelisted test fixture fingerprints!")
        for line in lines:
            self.assertIn("generic-api-key", line)


if __name__ == "__main__":
    unittest.main()
