"""
Regression tests against official evals/fixtures based on evals/test-cases.json.
Zero external dependencies.
"""

import json
import unittest
from pathlib import Path
from scanner.engine import ScanEngine
from scanner.models import Severity


class TestEvalsRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_dir = Path(__file__).parent.parent.resolve()
        cls.evals_json = cls.root_dir / "evals" / "test-cases.json"
        cls.engine = ScanEngine()

    def test_case1_python_insecure_storage(self):
        """Regression: EVAL-001 (Case 1) 應精準命中 1 項 SEC-001 (High)"""
        target = self.root_dir / "evals" / "fixtures" / "case1_storage.py"
        result = self.engine.scan_path(str(target))

        self.assertEqual(result.total_findings, 1, f"Expected 1 finding, got {result.total_findings}")
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "SEC-001")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_case2_csharp_insecure_oauth_service(self):
        """Regression: EVAL-002 (Case 2) 應精準命中 SEC-002 (Critical) 與 SEC-005 (High)"""
        target = self.root_dir / "evals" / "fixtures" / "case2_oauth_service.cs"
        result = self.engine.scan_path(str(target))

        self.assertEqual(result.total_findings, 2, f"Expected 2 findings, got {result.total_findings}")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("SEC-002", rule_ids)
        self.assertIn("SEC-005", rule_ids)

        critical_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        self.assertEqual(critical_count, 1)
        self.assertEqual(high_count, 1)

    def test_case3_csharp_secure_dpapi(self):
        """Regression: EVAL-003 (Case 3) 合規 DPAPI 與 Fail-Closed 代碼應完全為 0 誤報"""
        target = self.root_dir / "evals" / "fixtures" / "case3_secure_dpapi.cs"
        result = self.engine.scan_path(str(target))

        self.assertEqual(result.total_findings, 0, f"Expected 0 findings on secure fixture, got {result.total_findings}")


if __name__ == "__main__":
    unittest.main()
