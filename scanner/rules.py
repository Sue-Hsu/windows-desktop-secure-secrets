"""
Rule definitions and detection engines for windows-desktop-secure-secrets.
Covers rules SEC-001 through SEC-005 across Python, C#, and JavaScript/TypeScript.
Zero external dependencies.
"""

import ast
import re
from typing import List, Optional
from scanner.models import Finding, Severity

# Secret-related keyword regex
SECRET_KEY_PATTERN = re.compile(
    r"(?:api_?key|client_?secret|app_?secret|access_?token|refresh_?token|password|credential|private_?key)",
    re.IGNORECASE
)

# Rule 002: Hardcoded Client Secret pattern
CLIENT_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?:(?:private|public|protected|internal|static|readonly|const|var|let|const|\b)\s+)*"
    r"(?P<varname>[A-Za-z0-9_]*(?:client_?secret|app_?secret)[A-Za-z0-9_]*)"
    r"\s*[:=]\s*[\"'](?P<val>[^\"']+)[\"']",
    re.IGNORECASE
)

# Rule 004: LocalMachine DPAPI pattern
DPAPI_LOCALMACHINE_PATTERN = re.compile(
    r"DataProtectionScope\.LocalMachine\b"
)

# Rule 005: Secret in logging / Console pattern
LOG_SECRET_PATTERN = re.compile(
    r"(?:Console\.(?:WriteLine|Write)|Debug\.WriteLine|logger\.(?:debug|info|warn|error)|console\.(?:log|debug|info|warn|error)|print)\s*\("
    r"[^\)]*(?:client_?secret|api_?key|password|access_?token|refresh_?token|credential)",
    re.IGNORECASE
)

# Rule 001: Plaintext file write in C# or JS/TS
FILE_WRITE_SECRET_PATTERN_CSHARP = re.compile(
    r"File\.(?:WriteAllText|WriteAllLines|WriteAllBytes)\s*\([^,]+,\s*[^;]*(?:api_?key|client_?secret|token|password|credential)",
    re.IGNORECASE
)
FILE_WRITE_SECRET_PATTERN_JS = re.compile(
    r"fs(?:\.promises)?\.(?:writeFileSync|writeFile)\s*\([^,]+,\s*[^,\)]*(?:api_?key|client_?secret|token|password|credential)",
    re.IGNORECASE
)


class BaseRuleScanner:
    def scan(self, file_path: str, content: str) -> List[Finding]:
        raise NotImplementedError


class PythonRuleScanner(BaseRuleScanner):
    """AST-based and pattern-based scanner for Python desktop apps."""

    def scan(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # 1. AST Analysis for SEC-001 (Dict with secrets dumped to json)
        try:
            tree = ast.parse(content, filename=file_path)
            findings.extend(self._check_python_ast(tree, file_path, lines))
        except SyntaxError:
            # Fallback to regex if syntax error (e.g. template files)
            pass

        # 2. SEC-002: Hardcoded Client Secret
        for idx, line in enumerate(lines, start=1):
            match = CLIENT_SECRET_ASSIGNMENT_PATTERN.search(line)
            if match and match.group("val").strip():
                # Avoid flagging placeholder comments
                if not line.strip().startswith("#"):
                    findings.append(Finding(
                        rule_id="SEC-002",
                        rule_name="Hardcoded OAuth Client Secret in Public Client",
                        severity=Severity.CRITICAL,
                        cwe="CWE-798: Use of Hard-coded Credentials",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        file_path=file_path,
                        line_number=idx,
                        column=match.start() + 1,
                        snippet=line,
                        message=(
                            "[SEC-002] Hardcoded OAuth Client Secret detected in Python desktop application. "
                            "Desktop apps are Public Clients and cannot protect embedded secrets."
                        ),
                        remediation=(
                            "Use OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636). "
                            "Do not store or embed Client Secrets in desktop application source code."
                        ),
                        references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                    ))

        # 3. SEC-005: Sensitive Secret in Logging / Print
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("#"):
                continue
            if LOG_SECRET_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="SEC-005",
                    rule_name="Sensitive Secret Printed in Debug / Console Output",
                    severity=Severity.HIGH,
                    cwe="CWE-532: Insertion of Sensitive Information into Log File",
                    owasp="A09:2021 - Security Logging and Monitoring Failures",
                    file_path=file_path,
                    line_number=idx,
                    column=1,
                    snippet=line,
                    message=(
                        "[SEC-005] Sensitive credential or token printed in debug/console stream. "
                        "May be leaked to telemetry, console scrollback, or unencrypted logs."
                    ),
                    remediation="Remove secret printing or sanitize values with a secure token mask.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

        return findings

    def _check_python_ast(self, tree: ast.AST, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # Track variables that hold dictionary with secret keys
        sensitive_vars = set()

        for node in ast.walk(tree):
            # Check dict assignments: data = {"provider_api_key": ...}
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Dict):
                    has_secret_key = False
                    for key_node in node.value.keys:
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                            if SECRET_KEY_PATTERN.search(key_node.value):
                                has_secret_key = True
                                break
                    if has_secret_key:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                sensitive_vars.add(target.id)

            # Check json.dump(data, f) or json.dump({...}, f)
            if isinstance(node, ast.Call):
                func = node.func
                is_json_dump = False
                if isinstance(func, ast.Attribute) and func.attr == "dump":
                    if isinstance(func.value, ast.Name) and func.value.id == "json":
                        is_json_dump = True

                if is_json_dump and node.args:
                    first_arg = node.args[0]
                    violates = False

                    # Case A: Dumped variable was assigned sensitive dict
                    if isinstance(first_arg, ast.Name) and first_arg.id in sensitive_vars:
                        violates = True
                    # Case B: Literal dict directly in dump: json.dump({"api_key": ...}, f)
                    elif isinstance(first_arg, ast.Dict):
                        for k in first_arg.keys:
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                if SECRET_KEY_PATTERN.search(k.value):
                                    violates = True
                                    break

                    if violates:
                        line_no = node.lineno
                        snippet = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
                        findings.append(Finding(
                            rule_id="SEC-001",
                            rule_name="AppData Plaintext Secret Storage",
                            severity=Severity.HIGH,
                            cwe="CWE-312: Cleartext Storage of Sensitive Information",
                            owasp="A04:2021 - Insecure Design",
                            file_path=file_path,
                            line_number=line_no,
                            column=node.col_offset + 1,
                            snippet=snippet,
                            message=(
                                "[SEC-001] Plaintext persistence of secrets in user storage detected. "
                                "In Windows desktop applications, AppData and user directories are storage locations, NOT security sandboxes."
                            ),
                            remediation=(
                                "Encrypt secrets with Windows DPAPI (CryptProtectData via ctypes) or store in "
                                "Windows Credential Manager (via the 'keyring' package) before writing to disk."
                            ),
                            references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                        ))

        return findings


class CSharpRuleScanner(BaseRuleScanner):
    """Scanner for C# (.NET) desktop applications."""

    def scan(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        in_catch_block = False
        catch_brace_depth = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # SEC-002: Hardcoded Client Secret
            cs_match = CLIENT_SECRET_ASSIGNMENT_PATTERN.search(line)
            if cs_match and cs_match.group("val").strip():
                findings.append(Finding(
                    rule_id="SEC-002",
                    rule_name="Hardcoded OAuth Client Secret in Public Client",
                    severity=Severity.CRITICAL,
                    cwe="CWE-798: Use of Hard-coded Credentials",
                    owasp="A07:2021 - Identification and Authentication Failures",
                    file_path=file_path,
                    line_number=idx,
                    column=cs_match.start() + 1,
                    snippet=line,
                    message=(
                        "[SEC-002] Hardcoded OAuth Client Secret detected in C# desktop application. "
                        "Desktop binaries can be decompiled; client secrets cannot remain confidential."
                    ),
                    remediation=(
                        "Migrate to OAuth 2.0 Authorization Code Flow with PKCE (RFC 7636). "
                        "Revoke the hardcoded secret immediately."
                    ),
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-004: DPAPI LocalMachine Scope Abuse
            if DPAPI_LOCALMACHINE_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="SEC-004",
                    rule_name="DPAPI LocalMachine Scope Abuse",
                    severity=Severity.HIGH,
                    cwe="CWE-276: Incorrect Default Permissions",
                    owasp="A01:2021 - Broken Access Control",
                    file_path=file_path,
                    line_number=idx,
                    column=line.find("DataProtectionScope.LocalMachine") + 1,
                    snippet=line,
                    message=(
                        "[SEC-004] Insecure DPAPI DataProtectionScope.LocalMachine scope used in personal desktop application. "
                        "LocalMachine scope allows any user or unprivileged service on the machine to decrypt secrets."
                    ),
                    remediation="Change scope to DataProtectionScope.CurrentUser to enforce user isolation.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-005: Sensitive Secret in Logging / Console Output
            if LOG_SECRET_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="SEC-005",
                    rule_name="Sensitive Secret Printed in Debug / Console Output",
                    severity=Severity.HIGH,
                    cwe="CWE-532: Insertion of Sensitive Information into Log File",
                    owasp="A09:2021 - Security Logging and Monitoring Failures",
                    file_path=file_path,
                    line_number=idx,
                    column=1,
                    snippet=line,
                    message=(
                        "[SEC-005] Sensitive credential or token logged to Console or debug output. "
                        "Logging secrets causes leaks in console scrollback, crash dumps, and telemetry."
                    ),
                    remediation="Sanitize console/log messages and apply structured log masking.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-001: Plaintext File Write
            if FILE_WRITE_SECRET_PATTERN_CSHARP.search(line):
                findings.append(Finding(
                    rule_id="SEC-001",
                    rule_name="AppData Plaintext Secret Storage",
                    severity=Severity.HIGH,
                    cwe="CWE-312: Cleartext Storage of Sensitive Information",
                    owasp="A04:2021 - Insecure Design",
                    file_path=file_path,
                    line_number=idx,
                    column=1,
                    snippet=line,
                    message=(
                        "[SEC-001] Writing sensitive token or credential directly to file in plaintext. "
                        "In Windows desktop applications, credentials must not be written as unencrypted plaintext."
                    ),
                    remediation=(
                        "Encrypt with System.Security.Cryptography.ProtectedData.Protect (DPAPI CurrentUser) "
                        "or Windows.Security.Credentials.PasswordVault before writing to disk."
                    ),
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-003: Silent Fallback to Plaintext in Catch Block
            if "catch" in line:
                in_catch_block = True
                catch_brace_depth += line.count("{") - line.count("}")
            elif in_catch_block:
                catch_brace_depth += line.count("{") - line.count("}")
                if "File.WriteAll" in line:
                    findings.append(Finding(
                        rule_id="SEC-003",
                        rule_name="Silent Fallback to Plaintext Storage",
                        severity=Severity.HIGH,
                        cwe="CWE-391: Unchecked Error Condition",
                        owasp="A04:2021 - Insecure Design",
                        file_path=file_path,
                        line_number=idx,
                        column=1,
                        snippet=line,
                        message=(
                            "[SEC-003] Silent fallback to unencrypted file writing detected in catch block. "
                            "When secure storage or encryption APIs fail, silently writing plaintext files violates Fail-Closed security."
                        ),
                        remediation="Fail closed by throwing an exception, or retain tokens only in transient session memory.",
                        references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                    ))
                if catch_brace_depth <= 0:
                    in_catch_block = False

        return findings


class JavaScriptRuleScanner(BaseRuleScanner):
    """Scanner for JavaScript / TypeScript / Electron desktop applications."""

    def scan(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # SEC-002: Hardcoded Client Secret
            cs_match = CLIENT_SECRET_ASSIGNMENT_PATTERN.search(line)
            if cs_match and cs_match.group("val").strip():
                findings.append(Finding(
                    rule_id="SEC-002",
                    rule_name="Hardcoded OAuth Client Secret in Public Client",
                    severity=Severity.CRITICAL,
                    cwe="CWE-798: Use of Hard-coded Credentials",
                    owasp="A07:2021 - Identification and Authentication Failures",
                    file_path=file_path,
                    line_number=idx,
                    column=cs_match.start() + 1,
                    snippet=line,
                    message=(
                        "[SEC-002] Hardcoded OAuth Client Secret detected in JavaScript/TypeScript desktop application. "
                        "Desktop applications cannot protect embedded client secrets."
                    ),
                    remediation="Use OAuth 2.0 PKCE flow (RFC 7636). Do not embed Client Secret in desktop frontend code.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-001: Plaintext File Write (fs.writeFileSync / writeFile)
            if FILE_WRITE_SECRET_PATTERN_JS.search(line):
                findings.append(Finding(
                    rule_id="SEC-001",
                    rule_name="AppData Plaintext Secret Storage",
                    severity=Severity.HIGH,
                    cwe="CWE-312: Cleartext Storage of Sensitive Information",
                    owasp="A04:2021 - Insecure Design",
                    file_path=file_path,
                    line_number=idx,
                    column=1,
                    snippet=line,
                    message=(
                        "[SEC-001] Writing sensitive token or credential directly to file via plaintext fs write. "
                        "In Electron and Windows desktop applications, user data directories are not security sandboxes."
                    ),
                    remediation="Encrypt with Electron's official safeStorage API (safeStorage.encryptString) before saving to disk.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

            # SEC-005: Secret printed in console.log
            if LOG_SECRET_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="SEC-005",
                    rule_name="Sensitive Secret Printed in Debug / Console Output",
                    severity=Severity.HIGH,
                    cwe="CWE-532: Insertion of Sensitive Information into Log File",
                    owasp="A09:2021 - Security Logging and Monitoring Failures",
                    file_path=file_path,
                    line_number=idx,
                    column=1,
                    snippet=line,
                    message="[SEC-005] Sensitive credential or token logged to console output.",
                    remediation="Sanitize console output and apply token masking.",
                    references=["https://github.com/Sue-Hsu/windows-desktop-secure-secrets"]
                ))

        return findings


def get_scanner_for_file(file_path: str) -> Optional[BaseRuleScanner]:
    lower = file_path.lower()
    if lower.endswith(".py"):
        return PythonRuleScanner()
    elif lower.endswith(".cs"):
        return CSharpRuleScanner()
    elif lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return JavaScriptRuleScanner()
    return None
