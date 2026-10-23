#!/usr/bin/env python3
"""
win-secret-scanner: Windows Desktop Secret & Credential Security Scanner
A lightweight, zero-dependency static analysis tool for detecting insecure credential
persistence, hardcoded OAuth secrets, silent plaintext fallbacks, and DPAPI misconfigurations.

Part of the windows-desktop-secure-secrets Agent Skill.
Repository: https://github.com/Sue-Hsu/windows-desktop-secure-secrets
"""

import argparse
import sys
from pathlib import Path

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

# Add project root to sys.path to enable direct execution
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from scanner.engine import ScanEngine
from scanner.models import Severity
from scanner.reporters import ConsoleReporter, MarkdownReporter, JsonReporter

VERSION = "1.3.0"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="win-secret-scanner",
        description="Static security scanner for Windows desktop credentials & secrets.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "markdown", "json"],
        default="console",
        help="Output report format (default: console).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional file path to write the scan report.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Fail exit code (1) threshold (default: high).",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


def should_fail(result, threshold: str) -> bool:
    if threshold == "none":
        return False
    if threshold == "critical":
        return result.critical_count > 0
    if threshold == "high":
        return (result.critical_count + result.high_count) > 0
    if threshold == "medium":
        return (result.critical_count + result.high_count + result.medium_count) > 0
    if threshold == "low":
        return result.total_findings > 0
    return False


def run_interactive_mode():
    """Interactive GUI-like console mode for users who double-click the .exe."""
    print("=" * 72)
    print("  Windows Desktop Secret & Credential Security Scanner (v1.3.0)")
    print("  https://github.com/Sue-Hsu/windows-desktop-secure-secrets")
    print("=" * 72)
    print("[說明] 本工具專為檢測 Windows 桌面應用中的機密儲存與憑證安全而設計。")
    print("       支援 Python (.py), C# (.cs), JavaScript/TypeScript (.js, .ts) 等。\n")

    while True:
        try:
            raw_path = input("請輸入欲掃描的專案目錄或檔案路徑\n(可直接從檔案總管將資料夾拖曳進此視窗，按 Enter 預設掃描當前目錄):\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n已取消作業。")
            return

        # Strip surrounding quotes if dragged & dropped from Windows Explorer
        clean_path = raw_path.strip("\"'")
        if not clean_path:
            clean_path = "."

        target_path = Path(clean_path).resolve()
        if not target_path.exists():
            print(f"\n[錯誤] 找不到指定路徑: {clean_path}，請重新輸入。\n")
            continue
        break

    print(f"\n開始掃描目標: {target_path}")
    print("掃描進行中，請稍候...\n")

    engine = ScanEngine()
    try:
        result = engine.scan_path(str(target_path))
    except Exception as err:
        print(f"[錯誤] 掃描時發生例外: {err}")
        input("\n請按 Enter 鍵關閉視窗...")
        return

    # Display console report
    reporter = ConsoleReporter(use_color=True)
    reporter.report(result, out=sys.stdout)

    # Offer to export Markdown report if findings exist
    if result.total_findings > 0:
        try:
            choice = input("是否將詳細報告另存為 audit-report.md？(y/N): ").strip().lower()
            if choice in ("y", "yes"):
                report_file = target_path / "audit-report.md" if target_path.is_dir() else target_path.parent / "audit-report.md"
                with open(report_file, "w", encoding="utf-8") as f:
                    MarkdownReporter().report(result, out=f)
                print(f"[已儲存] 審查報告已產出至: {report_file}")
        except Exception:
            pass

    print("\n" + "=" * 72)
    input("[掃描完成] 請按 Enter 鍵關閉視窗...")


def main():
    # If launched with no arguments and stdin is an interactive terminal,
    # enter friendly interactive mode to prevent instant window closing on double-click.
    if len(sys.argv) == 1 and sys.stdin.isatty():
        run_interactive_mode()
        sys.exit(0)

    # Standard CLI mode for command line, scripts, and CI/CD pipelines
    args = parse_args()

    engine = ScanEngine()
    try:
        result = engine.scan_path(args.target)
    except FileNotFoundError as err:
        sys.stderr.write(f"Error: {err}\n")
        sys.exit(2)

    # Determine reporter
    if args.format == "json":
        reporter = JsonReporter()
    elif args.format == "markdown":
        reporter = MarkdownReporter()
    else:
        reporter = ConsoleReporter(use_color=not args.no_color)

    # Render output
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            reporter.report(result, out=f)
        if args.format == "console":
            print(f"Report written to {out_path}")
    else:
        reporter.report(result, out=sys.stdout)

    if should_fail(result, args.fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
