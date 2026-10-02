# Windows Desktop Secure Secrets — Regression Evaluation Suite

This evaluation suite provides deterministic benchmark fixtures to test and verify that AI coding agents (or custom static analysis scanners) correctly apply the security standards defined in `windows-desktop-secure-secrets`.

---

## Evaluation Fixtures

| ID | Fixture File | Scenario | Expected Verdict | Expected Severity | Rotation Required |
|---|---|---|---|---|---|
| **EVAL-001** | `fixtures/case1_storage.py` | Plaintext API key persisted in `%APPDATA%\MockCloudApp\config.json`. | 1 Finding (Insecure Persistence) | **High** | **No** (Threat-model dependent: local unshared disk) |
| **EVAL-002** | `fixtures/case2_oauth_service.cs` | Hardcoded production OAuth Client Secret in Public Client + plaintext console logging. | 2 Findings (Client Secret Misuse + Secret in Log) | **Critical** / **High** | **Yes** (Committed in repo & logged) |
| **EVAL-003** | `fixtures/case3_secure_dpapi.cs` | Compliant DPAPI `CurrentUser` implementation with atomic file write and Fail-Closed recovery. | 0 Findings (Clean / Compliant) | **None** | **No** |

---

## How to Run Evals with an AI Agent

1. **Prompt the Agent**:
   ```text
   Load the windows-desktop-secure-secrets skill and perform a security review on evals/fixtures/case1_storage.py, case2_oauth_service.cs, and case3_secure_dpapi.cs.
   For each fixture, report findings, severity, and rotation decisions following the standard output format.
   ```
2. **Compare Against Benchmark**:
   - Check the agent's findings against `evals/test-cases.json`.
   - Verify that EVAL-001 identifies AppData plaintext storage with `High` severity.
   - Verify that EVAL-002 flags OAuth Client Secret in a Public Client (`Critical`) and console logging (`High`), marking Rotation Required as `Yes`.
   - Verify that EVAL-003 reports zero false positives and acknowledges DPAPI `CurrentUser` compliance.
