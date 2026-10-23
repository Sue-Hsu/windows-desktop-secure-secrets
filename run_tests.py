#!/usr/bin/env python3
"""
Test runner and report generator for windows-desktop-secure-secrets.
Executes unit tests and regression tests, then outputs timestamped
Markdown and standalone HTML reports.

Naming convention: test-report_yyyymmddhhmm.html / .md
Zero external dependencies.
"""

import argparse
import datetime
import os
import sys
import time
import unittest
from pathlib import Path
from typing import List, Dict, Any

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))


class DetailedTestResult(unittest.TestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records: List[Dict[str, Any]] = []
        self._test_start_time = 0.0

    def startTest(self, test):
        super().startTest(test)
        self._test_start_time = time.time()

    def addSuccess(self, test):
        super().addSuccess(test)
        elapsed = time.time() - self._test_start_time
        self._record(test, "PASS", elapsed)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        elapsed = time.time() - self._test_start_time
        self._record(test, "FAIL", elapsed, err=err)

    def addError(self, test, err):
        super().addError(test, err)
        elapsed = time.time() - self._test_start_time
        self._record(test, "ERROR", elapsed, err=err)

    def _record(self, test, status: str, elapsed: float, err=None):
        test_id = test.id()
        module_name = test.__class__.__module__
        class_name = test.__class__.__name__
        method_name = test._testMethodName
        description = test.shortDescription() or ""

        err_msg = ""
        if err:
            err_msg = self._exc_info_to_string(err, test)

        self.records.append({
            "test_id": test_id,
            "module": module_name,
            "class": class_name,
            "method": method_name,
            "description": description,
            "status": status,
            "duration": round(elapsed, 4),
            "error": err_msg,
        })


def generate_markdown_report(summary: Dict[str, Any], records: List[Dict[str, Any]]) -> str:
    lines = [
        f"# Windows Desktop Secure Secrets - Test Report (單元測試報告)",
        f"",
        f"Generated (產出時間): `{summary['timestamp_str']}`",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary (精簡摘要)",
        f"",
        f"| Metric (指標) | Value (數值) |",
        f"| :--- | :--- |",
        f"| **Overall Verdict (總評結果)** | **{summary['verdict_badge']}** |",
        f"| **Total Tests (總測試數)** | `{summary['total']}` |",
        f"| **Passed (通過數)** | `{summary['passed']}` |",
        f"| **Failed (失敗數)** | `{summary['failed']}` |",
        f"| **Errors (錯誤數)** | `{summary['errors']}` |",
        f"| **Pass Rate (通過率)** | **{summary['pass_rate']}%** |",
        f"| **Total Duration (總耗時)** | `{summary['total_duration']:.3f}s` |",
        f"",
        f"---",
        f"",
        f"## 2. Detailed Test Results (完整詳細報告)",
        f"",
        f"| Status (狀態) | Module / Class (模組 / 類別) | Test Case (測試案例) | Description (測試說明) | Duration (耗時) |",
        f"| :---: | :--- | :--- | :--- | :---: |",
    ]

    for r in records:
        status_badge = f"`[{r['status']}]`" if r['status'] == 'PASS' else f"**[{r['status']}]**"
        lines.append(
            f"| {status_badge} | `{r['module']}.{r['class']}` | `{r['method']}` | {r['description']} | {r['duration']}s |"
        )

    # Detailed traceback for any failure
    failures = [r for r in records if r["status"] in ("FAIL", "ERROR")]
    if failures:
        lines.extend([
            "",
            "---",
            "",
            "## 3. Failure & Error Details (失敗與錯誤詳情)",
            "",
        ])
        for idx, f in enumerate(failures, start=1):
            lines.extend([
                f"### {idx}. {f['test_id']} ({f['status']})",
                f"- **Description (測試說明)**: {f['description']}",
                f"- **Duration (耗時)**: {f['duration']}s",
                f"",
                "```text",
                f"{f['error'].strip()}",
                "```",
                "",
            ])

    return "\n".join(lines)


def generate_html_report(summary: Dict[str, Any], records: List[Dict[str, Any]]) -> str:
    verdict_color = "#28a745" if summary["failed"] == 0 and summary["errors"] == 0 else "#dc3545"
    verdict_text = "ALL TESTS PASSED (全部通過)" if summary["failed"] == 0 and summary["errors"] == 0 else "FAILURES DETECTED (檢出失敗)"

    rows_html = []
    for r in records:
        if r["status"] == "PASS":
            badge_html = '<span class="badge pass">PASS</span>'
        elif r["status"] == "FAIL":
            badge_html = '<span class="badge fail">FAIL</span>'
        else:
            badge_html = '<span class="badge error">ERROR</span>'

        desc = r["description"] or "-"
        err_div = ""
        if r["error"]:
            err_div = f'<div class="err-container"><pre class="err-box">{r["error"]}</pre></div>'

        rows_html.append(f"""
        <tr>
            <td style="text-align: center;">{badge_html}</td>
            <td><code>{r['module']}</code><br><small style="color: var(--muted);">{r['class']}</small></td>
            <td><strong><code>{r['method']}</code></strong>{err_div}</td>
            <td>{desc}</td>
            <td style="text-align: right;">{r['duration']:.4f}s</td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unit Test Report - windows-desktop-secure-secrets</title>
    <style>
        :root {{
            --bg: #f8f9fa;
            --surface: #ffffff;
            --text: #212529;
            --muted: #6c757d;
            --border: #dee2e6;
            --pass: #28a745;
            --fail: #dc3545;
            --primary: #0066cc;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: var(--surface);
            padding: 24px 30px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: #111;
        }}
        .timestamp {{
            color: var(--muted);
            font-size: 14px;
            margin: 0;
        }}
        .summary-card {{
            background: var(--surface);
            border-radius: 8px;
            border: 1px solid var(--border);
            padding: 24px 30px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .summary-title {{
            font-size: 18px;
            font-weight: 700;
            margin-top: 0;
            margin-bottom: 16px;
            border-bottom: 2px solid var(--border);
            padding-bottom: 8px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            text-align: center;
        }}
        .stat-box {{
            background: var(--bg);
            padding: 16px;
            border-radius: 6px;
            border: 1px solid var(--border);
        }}
        .stat-val {{
            font-size: 26px;
            font-weight: bold;
            margin-top: 4px;
        }}
        .stat-label {{
            font-size: 13px;
            color: var(--muted);
            letter-spacing: 0.3px;
        }}
        .verdict {{
            background: {verdict_color};
            color: white;
            padding: 4px 14px;
            border-radius: 20px;
            display: inline-block;
            font-size: 13px;
            font-weight: bold;
        }}
        .table-card {{
            background: var(--surface);
            border-radius: 8px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            background: #f1f3f5;
            padding: 14px 16px;
            text-align: left;
            border-bottom: 2px solid var(--border);
            font-weight: 600;
            color: #333;
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover {{
            background: #fbfcfd;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}
        .badge.pass {{
            background: #e6f4ea;
            color: #137333;
            border: 1px solid #ceead6;
        }}
        .badge.fail {{
            background: #fce8e6;
            color: #c5221f;
            border: 1px solid #fad2cf;
        }}
        .badge.error {{
            background: #fef7e0;
            color: #b06000;
            border: 1px solid #feefc3;
        }}
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 13px;
            font-family: Consolas, Monaco, monospace;
        }}
        .err-container {{
            margin-top: 10px;
            margin-bottom: 6px;
        }}
        .err-box {{
            background: #1e1e1e;
            color: #f8f9fa;
            padding: 14px 18px;
            border-radius: 6px;
            border-left: 4px solid #dc3545;
            font-size: 12.5px;
            line-height: 1.6;
            margin: 0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows Desktop Secure Secrets - Test Report (單元測試報告)</h1>
            <p class="timestamp">Execution Time (執行時間): {summary['timestamp_str']} | Project Root (專案目錄): <code>{PROJECT_ROOT}</code></p>
        </div>

        <div class="summary-card">
            <div class="summary-title">Executive Summary (精簡摘要)</div>
            <div class="grid">
                <div class="stat-box">
                    <div class="stat-label">Overall Verdict (總評結果)</div>
                    <div class="stat-val"><span class="verdict">{verdict_text}</span></div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Tests (總測試數)</div>
                    <div class="stat-val">{summary['total']}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Passed (通過數)</div>
                    <div class="stat-val" style="color: var(--pass);">{summary['passed']}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Failed (失敗數)</div>
                    <div class="stat-val" style="color: {'var(--fail)' if summary['failed'] > 0 else 'var(--muted)'};">{summary['failed']}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Pass Rate (通過率)</div>
                    <div class="stat-val" style="color: var(--primary);">{summary['pass_rate']}%</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Duration (總耗時)</div>
                    <div class="stat-val">{summary['total_duration']:.3f}s</div>
                </div>
            </div>
        </div>

        <div class="table-card">
            <div class="summary-title" style="margin: 20px 24px 12px 24px; padding-bottom: 8px;">Detailed Test Results (完整詳細報告)</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px; text-align: center;">Status (狀態)</th>
                        <th style="width: 220px;">Module / Class (模組 / 類別)</th>
                        <th>Test Case (測試案例)</th>
                        <th>Description (測試目的說明)</th>
                        <th style="width: 110px; text-align: right;">Duration (耗時)</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows_html)}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Test runner for windows-desktop-secure-secrets.")
    parser.add_argument("--unit-only", action="store_true", help="Run only internal unit tests.")
    parser.add_argument("--regression-only", action="store_true", help="Run only fixtures regression tests.")
    parser.add_argument("--output-dir", type=str, default="tests/reports", help="Directory to save reports.")
    args = parser.parse_args()

    tests_dir = PROJECT_ROOT / "tests"
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    if args.unit_only:
        print("[Mode] Running unit tests only...")
        for pattern in ["test_rules_*.py", "test_engine.py", "test_reporters.py"]:
            suite.addTests(loader.discover(start_dir=str(tests_dir), pattern=pattern))
    elif args.regression_only:
        print("[Mode] Running regression tests only...")
        suite.addTests(loader.discover(start_dir=str(tests_dir), pattern="test_evals_regression.py"))
    else:
        print("[Mode] Running full suite (Unit Tests + Fixtures Regression)...")
        suite.addTests(loader.discover(start_dir=str(tests_dir), pattern="test_*.py"))

    start_time = time.time()
    runner_result = DetailedTestResult()
    suite.run(runner_result)
    total_duration = time.time() - start_time

    total_tests = runner_result.testsRun
    failed_count = len(runner_result.failures)
    error_count = len(runner_result.errors)
    passed_count = total_tests - failed_count - error_count
    pass_rate = round((passed_count / total_tests * 100), 1) if total_tests > 0 else 0.0

    now = datetime.datetime.now()
    timestamp_filename = now.strftime("%Y%m%d%H%M")
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

    verdict_badge = "✅ PASS" if (failed_count == 0 and error_count == 0) else "❌ FAIL"

    summary = {
        "timestamp_filename": timestamp_filename,
        "timestamp_str": timestamp_str,
        "total": total_tests,
        "passed": passed_count,
        "failed": failed_count,
        "errors": error_count,
        "pass_rate": pass_rate,
        "total_duration": total_duration,
        "verdict_badge": verdict_badge,
    }

    # Print summary to console
    print("\n" + "=" * 60)
    print("  Test Execution Summary")
    print("=" * 60)
    print(f"Overall Verdict: {verdict_badge}")
    print(f"Total Tests:     {total_tests}")
    print(f"Passed:          {passed_count}")
    print(f"Failed:          {failed_count}")
    print(f"Errors:          {error_count}")
    print(f"Pass Rate:       {pass_rate}%")
    print(f"Execution Time:  {total_duration:.3f}s")
    print("=" * 60)

    # Output reports
    out_dir = PROJECT_ROOT / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    md_content = generate_markdown_report(summary, runner_result.records)
    html_content = generate_html_report(summary, runner_result.records)

    md_file = out_dir / f"test-report_{timestamp_filename}.md"
    html_file = out_dir / f"test-report_{timestamp_filename}.html"

    md_file.write_text(md_content, encoding="utf-8")
    html_file.write_text(html_content, encoding="utf-8")

    print(f"\n[Reports Generated]")
    print(f"Markdown Report: {md_file.relative_to(PROJECT_ROOT)}")
    print(f"HTML Report:     {html_file.relative_to(PROJECT_ROOT)}")

    sys.exit(0 if failed_count == 0 and error_count == 0 else 1)


if __name__ == "__main__":
    main()
