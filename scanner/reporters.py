"""
Reporters for windows-desktop-secure-secrets scanner.
Supports:
1. Terminal Console (ANSI Color, clean layout)
2. Markdown Report (GitHub flavored)
3. Structured JSON (Machine-readable for AI Agent closed-loop remediation)
"""

import json
import sys
from typing import TextIO
from scanner.models import ScanResult, Severity


class AnsiColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


class PlainColors:
    RESET = ""
    BOLD = ""
    DIM = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    WHITE = ""


def format_severity(sev: Severity, use_color: bool = True) -> str:
    text = f"[{sev.value.upper()}]"
    if not use_color:
        return text
    if sev == Severity.CRITICAL:
        return f"{AnsiColors.BOLD}{AnsiColors.RED}{text}{AnsiColors.RESET}"
    elif sev == Severity.HIGH:
        return f"{AnsiColors.RED}{text}{AnsiColors.RESET}"
    elif sev == Severity.MEDIUM:
        return f"{AnsiColors.YELLOW}{text}{AnsiColors.RESET}"
    elif sev == Severity.LOW:
        return f"{AnsiColors.CYAN}{text}{AnsiColors.RESET}"
    return f"{AnsiColors.DIM}{text}{AnsiColors.RESET}"


class ConsoleReporter:
    def __init__(self, use_color: bool = True):
        self.use_color = use_color and sys.stdout.isatty()

    def report(self, result: ScanResult, out: TextIO = sys.stdout):
        c = AnsiColors if self.use_color else PlainColors

        out.write(f"\n{c.BOLD}=== Windows Desktop Secret Scanner ==={c.RESET}\n")
        out.write(f"Target Path: {result.target_path}\n")
        out.write(f"Files Scanned: {result.total_files_scanned} | Total Findings: {result.total_findings}\n")
        out.write(
            f"Severity Breakdown: "
            f"Critical: {result.critical_count} | "
            f"High: {result.high_count} | "
            f"Medium: {result.medium_count} | "
            f"Low: {result.low_count}\n"
        )
        out.write("-" * 72 + "\n\n")

        if result.total_findings == 0:
            out.write(f"{c.GREEN}[PASS] No Windows desktop credential security vulnerabilities found.{c.RESET}\n\n")
            return

        for idx, f in enumerate(result.findings, start=1):
            sev_str = format_severity(f.severity, self.use_color)
            out.write(f"{c.BOLD}Finding #{idx} {sev_str} {f.rule_id}: {f.rule_name}{c.RESET}\n")
            out.write(f"  {c.DIM}Location:{c.RESET} {f.file_path}:{f.line_number}:{f.column}\n")
            out.write(f"  {c.DIM}Standard:{c.RESET} {f.cwe} | {f.owasp}\n")
            out.write(f"  {c.DIM}Message:{c.RESET}  {f.message}\n")
            if f.snippet:
                out.write(f"  {c.DIM}Code:{c.RESET}\n")
                out.write(f"    {c.CYAN}> {f.snippet}{c.RESET}\n")
            out.write(f"  {c.GREEN}Remediation:{c.RESET} {f.remediation}\n")
            out.write("\n")

        out.write("-" * 72 + "\n")
        if result.critical_count > 0 or result.high_count > 0:
            out.write(f"{c.RED}[ACTION REQUIRED] Critical or High severity findings detected. Remediation required.{c.RESET}\n\n")
        else:
            out.write(f"{c.YELLOW}[REVIEW] Medium/Low severity findings detected.{c.RESET}\n\n")


class MarkdownReporter:
    def report(self, result: ScanResult, out: TextIO = sys.stdout):
        lines = [
            "# Windows Desktop Secret Security Scan Report",
            "",
            f"- **Target Path**: `{result.target_path}`",
            f"- **Files Scanned**: {result.total_files_scanned}",
            f"- **Total Findings**: {result.total_findings}",
            f"- **Duration**: {result.scan_duration_seconds:.2f}s",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| [CRITICAL] | {result.critical_count} |",
            f"| [HIGH]     | {result.high_count} |",
            f"| [MEDIUM]   | {result.medium_count} |",
            f"| [LOW]      | {result.low_count} |",
            "",
        ]

        if result.total_findings == 0:
            lines.extend([
                "## Status",
                "",
                "✅ **PASS**: No security vulnerabilities or insecure credential storage patterns detected.",
                ""
            ])
            out.write("\n".join(lines))
            return

        lines.extend([
            "## Detailed Findings",
            ""
        ])

        for idx, f in enumerate(result.findings, start=1):
            lines.extend([
                f"### {idx}. [{f.severity.value}] {f.rule_id} - {f.rule_name}",
                "",
                f"- **File**: `{f.file_path}:{f.line_number}`",
                f"- **Standard**: {f.cwe} / {f.owasp}",
                f"- **Description**: {f.message}",
                "",
                "```text",
                f"> {f.snippet}",
                "```",
                "",
                f"**Remediation Guidance**:",
                f"> {f.remediation}",
                "",
            ])

        out.write("\n".join(lines))


class JsonReporter:
    def __init__(self, indent: int = 2):
        self.indent = indent

    def report(self, result: ScanResult, out: TextIO = sys.stdout):
        payload = result.to_dict()
        out.write(json.dumps(payload, indent=self.indent, ensure_ascii=False) + "\n")
