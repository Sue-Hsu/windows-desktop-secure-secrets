"""
Reporters for windows-desktop-secure-secrets scanner.
Supports:
1. Terminal Console (ANSI Color, clean layout)
2. Markdown Report (GitHub flavored)
3. Structured JSON (Machine-readable for AI Agent closed-loop remediation)
"""

import datetime
import html
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
            "# Windows Desktop Secret Security Scan Report (安全審查報告)",
            "",
            f"- **Target Path (掃描目標)**: `{result.target_path}`",
            f"- **Files Scanned (掃描檔案數)**: {result.total_files_scanned}",
            f"- **Total Findings (檢出風險數)**: {result.total_findings}",
            f"- **Duration (總耗時)**: {result.scan_duration_seconds:.2f}s",
            "",
            "## 1. Executive Summary (精簡摘要)",
            "",
            "| Severity (風險等級) | Count (數量) |",
            "| :--- | :--- |",
            f"| [CRITICAL] | {result.critical_count} |",
            f"| [HIGH]     | {result.high_count} |",
            f"| [MEDIUM]   | {result.medium_count} |",
            f"| [LOW]      | {result.low_count} |",
            "",
        ]

        if result.total_findings == 0:
            lines.extend([
                "## 2. Status (總評狀態)",
                "",
                "✅ **PASS**: No security vulnerabilities or insecure credential storage patterns detected.",
                "(未檢出任何 Windows 桌面機密儲存違規或明文反模式)",
                ""
            ])
            out.write("\n".join(lines))
            return

        lines.extend([
            "## 2. Detailed Findings (詳細審查清單)",
            ""
        ])

        for idx, f in enumerate(result.findings, start=1):
            lines.extend([
                f"### {idx}. [{f.severity.value.capitalize()}] {f.rule_id} - {f.rule_name}",
                "",
                f"- **File Location (檔案位置)**: `{f.file_path}:{f.line_number}:{f.column}`",
                f"- **Standard (安全標準)**: {f.cwe} / {f.owasp}",
                f"- **Description (風險說明)**: {f.message}",
                "",
                "```text",
                f"> {f.snippet}",
                "```",
                "",
                f"**Remediation Guidance (建議修復方式)**:",
                f"> {f.remediation}",
                "",
            ])

        out.write("\n".join(lines))


class HtmlReporter:
    def report(self, result: ScanResult, out: TextIO = sys.stdout):
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_clean = result.total_findings == 0

        if is_clean:
            verdict_badge = "✅ PASS"
            verdict_text = "PASS (安全通過)"
            verdict_color = "#137333"
            verdict_bg = "#e6f4ea"
            status_msg = "未檢出任何 Windows 桌面機密儲存違規或明文反模式 (No security vulnerabilities detected)"
        elif result.critical_count > 0:
            verdict_badge = "❌ CRITICAL"
            verdict_text = "CRITICAL (嚴重風險)"
            verdict_color = "#c5221f"
            verdict_bg = "#fce8e6"
            status_msg = f"檢出 {result.critical_count} 項嚴重風險 (Critical)，二進位檔無法保密客戶端金鑰，必須立即修復。"
        elif result.high_count > 0:
            verdict_badge = "❌ HIGH"
            verdict_text = "HIGH (高危風險)"
            verdict_color = "#c5221f"
            verdict_bg = "#fce8e6"
            status_msg = f"檢出 {result.high_count} 項高危風險 (High)，包含明文落地或日誌外洩，需盡速排除。"
        else:
            verdict_badge = "⚠️ REVIEW"
            verdict_text = "REVIEW (需審閱)"
            verdict_color = "#b06000"
            verdict_bg = "#fef7e0"
            status_msg = "檢出中低風險事項，建議審閱並調整儲存作用域或遮罩處置。"

        findings_rows = []
        findings_cards = []

        sev_class_map = {
            Severity.CRITICAL: "sev-critical",
            Severity.HIGH: "sev-high",
            Severity.MEDIUM: "sev-medium",
            Severity.LOW: "sev-low",
        }

        for idx, f in enumerate(result.findings, start=1):
            sev_cls = sev_class_map.get(f.severity, "sev-low")
            esc_file = html.escape(str(f.file_path))
            esc_rule_id = html.escape(str(f.rule_id))
            esc_rule_name = html.escape(str(f.rule_name))
            esc_msg = html.escape(str(f.message))
            esc_snippet = html.escape(str(f.snippet))
            esc_remediation = html.escape(str(f.remediation))
            esc_standard = html.escape(f"{f.cwe} | {f.owasp}")

            findings_rows.append(f"""
            <tr>
                <td style="text-align: center;">{idx}</td>
                <td style="text-align: center;"><span class="badge {sev_cls}">{f.severity.value.upper()}</span></td>
                <td><code>{esc_rule_id}</code></td>
                <td><strong>{esc_file}</strong>:{f.line_number}</td>
                <td><small style="color: var(--muted);">{esc_standard}</small></td>
                <td>{esc_msg}</td>
            </tr>
            """)

            findings_cards.append(f"""
            <div class="finding-card {sev_cls}">
                <div class="finding-header">
                    <span class="badge {sev_cls}">{f.severity.value.upper()}</span>
                    <span class="finding-title">#{idx} {esc_rule_id}: {esc_rule_name}</span>
                </div>
                <div class="finding-meta">
                    <strong>Location (檔案位置):</strong> <code>{esc_file}:{f.line_number}:{f.column}</code> &nbsp;|&nbsp;
                    <strong>Standard (標準對應):</strong> {esc_standard}
                </div>
                <div class="finding-msg">{esc_msg}</div>
                <div class="code-container">
                    <div class="code-label">Vulnerable Code (問題代碼):</div>
                    <pre class="code-box"><code>&gt; {esc_snippet}</code></pre>
                </div>
                <div class="remediation-box">
                    <div class="remediation-label">💡 Remediation Guidance (建議修復方式):</div>
                    <div>{esc_remediation}</div>
                </div>
            </div>
            """)

        table_rows_html = "".join(findings_rows)
        cards_html = "".join(findings_cards)

        html_content = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Desktop Secret Security Scan Report</title>
    <style>
        :root {{
            --bg: #f8f9fa;
            --surface: #ffffff;
            --text: #212529;
            --muted: #6c757d;
            --border: #dee2e6;
            --critical: #dc3545;
            --high: #e65100;
            --medium: #f57c00;
            --low: #0288d1;
            --pass: #198754;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1140px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: #ffffff;
            padding: 28px 32px;
            border-radius: 10px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
        }}
        .header code {{
            background: rgba(255,255,255,0.15);
            color: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: Consolas, Monaco, monospace;
        }}
        .summary-card {{
            background: var(--surface);
            border-radius: 10px;
            border: 1px solid var(--border);
            padding: 24px 28px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .summary-title {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 16px;
            border-bottom: 2px solid var(--border);
            padding-bottom: 8px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 14px;
            text-align: center;
        }}
        .stat-box {{
            background: var(--bg);
            padding: 14px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-val {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 4px;
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .verdict {{
            background: {verdict_bg};
            color: {verdict_color};
            border: 1px solid {verdict_color};
            padding: 4px 12px;
            border-radius: 20px;
            display: inline-block;
            font-size: 14px;
            font-weight: bold;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}
        .badge.sev-critical {{ background: #fce8e6; color: #c5221f; border: 1px solid #fad2cf; }}
        .badge.sev-high     {{ background: #fff0e6; color: #d84315; border: 1px solid #ffccbc; }}
        .badge.sev-medium   {{ background: #fef7e0; color: #b06000; border: 1px solid #feefc3; }}
        .badge.sev-low      {{ background: #e1f5fe; color: #0277bd; border: 1px solid #b3e5fc; }}
        .badge.pass         {{ background: #e6f4ea; color: #137333; border: 1px solid #ceead6; }}

        .table-card {{
            background: var(--surface);
            border-radius: 10px;
            border: 1px solid var(--border);
            overflow: hidden;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            background: #f1f5f9;
            padding: 12px 16px;
            text-align: left;
            border-bottom: 2px solid var(--border);
            font-weight: 600;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background: #f8fafc; }}

        .clean-state {{
            background: #e6f4ea;
            border: 1px solid #ceead6;
            color: #137333;
            padding: 24px;
            border-radius: 8px;
            text-align: center;
            font-size: 16px;
            font-weight: 600;
        }}

        .finding-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 24px;
            margin-bottom: 18px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .finding-card.sev-critical {{ border-left: 5px solid var(--critical); }}
        .finding-card.sev-high     {{ border-left: 5px solid var(--high); }}
        .finding-card.sev-medium   {{ border-left: 5px solid var(--medium); }}
        .finding-card.sev-low      {{ border-left: 5px solid var(--low); }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-size: 17px;
            font-weight: 700;
        }}
        .finding-meta {{
            font-size: 13px;
            color: var(--muted);
            margin-bottom: 10px;
        }}
        .finding-msg {{
            font-size: 14px;
            margin-bottom: 12px;
            color: #334155;
        }}
        .code-container {{
            margin: 12px 0;
        }}
        .code-label {{
            font-size: 12px;
            font-weight: 600;
            color: var(--muted);
            margin-bottom: 4px;
            text-transform: uppercase;
        }}
        .code-box {{
            background: #1e1e1e;
            color: #f8f9fa;
            padding: 14px 18px;
            border-radius: 6px;
            font-size: 13px;
            line-height: 1.6;
            font-family: Consolas, Monaco, "Courier New", monospace;
            border-left: 4px solid var(--critical);
            margin: 0;
            overflow-x: auto;
            word-break: break-all;
        }}
        .remediation-box {{
            background: #e8f5e9;
            border: 1px solid #c8e6c9;
            border-left: 4px solid #2e7d32;
            color: #1b5e20;
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 13px;
            line-height: 1.6;
            margin-top: 12px;
        }}
        .remediation-label {{
            font-weight: bold;
            margin-bottom: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows Desktop Secret Security Scan Report</h1>
            <p>Windows 桌面憑證與機密安全審查報告 | 產出時間: <code>{now_str}</code> | 掃描目標: <code>{html.escape(str(result.target_path))}</code></p>
        </div>

        <div class="summary-card">
            <div class="summary-title">Executive Summary (精簡摘要)</div>
            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Overall Verdict (總評結果)</div>
                    <div class="stat-val"><span class="verdict">{verdict_badge}</span></div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Files Scanned (掃描總檔數)</div>
                    <div class="stat-val">{result.total_files_scanned}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Findings (檢出風險數)</div>
                    <div class="stat-val" style="color: {'var(--pass)' if is_clean else 'var(--critical)'};">{result.total_findings}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Critical (嚴重)</div>
                    <div class="stat-val" style="color: var(--critical);">{result.critical_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">High (高危)</div>
                    <div class="stat-val" style="color: var(--high);">{result.high_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Medium (中危)</div>
                    <div class="stat-val" style="color: var(--medium);">{result.medium_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Low (低危)</div>
                    <div class="stat-val" style="color: var(--low);">{result.low_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Duration (總耗時)</div>
                    <div class="stat-val">{result.scan_duration_seconds:.3f}s</div>
                </div>
            </div>
        </div>

        {'''
        <div class="clean-state">
            ✅ PASS: 未檢出任何 Windows 桌面機密儲存違規或明文反模式。<br>
            <small style="font-weight: normal; color: #2e7d32;">No security vulnerabilities or insecure credential storage patterns detected.</small>
        </div>
        ''' if is_clean else f'''
        <div class="table-card">
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px; text-align: center;">#</th>
                        <th style="width: 120px; text-align: center;">Severity (等級)</th>
                        <th style="width: 110px;">Rule (規則)</th>
                        <th>File Location (檔案位置)</th>
                        <th>Standard (標準)</th>
                        <th>Description (風險說明)</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>
        </div>

        <h2 style="font-size: 20px; font-weight: 700; margin: 30px 0 16px 0;">Detailed Findings & Remediations (詳細審查與修復建議)</h2>
        {cards_html}
        '''}
    </div>
</body>
</html>
"""
        out.write(html_content)


class JsonReporter:
    def __init__(self, indent: int = 2):
        self.indent = indent

    def report(self, result: ScanResult, out: TextIO = sys.stdout):
        payload = result.to_dict()
        out.write(json.dumps(payload, indent=self.indent, ensure_ascii=False) + "\n")
