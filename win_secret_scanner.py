#!/usr/bin/env python3
"""
win-secret-scanner: Windows Desktop Secret & Credential Security Scanner
A lightweight, zero-dependency static analysis tool for detecting insecure credential
persistence, hardcoded OAuth secrets, silent plaintext fallbacks, and DPAPI misconfigurations.

Part of the windows-desktop-secure-secrets Agent Skill.
Repository: https://github.com/Sue-Hsu/windows-desktop-secure-secrets
"""

import argparse
import datetime
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
from scanner.reporters import ConsoleReporter, MarkdownReporter, JsonReporter, HtmlReporter

VERSION = "1.4.0"


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
        choices=["console", "markdown", "json", "html"],
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
    print(f"  Windows Desktop Secret & Credential Security Scanner ({VERSION})")
    print("  https://github.com/Sue-Hsu/windows-desktop-secure-secrets")
    print("=" * 72)
    print("[說明] 本工具專為檢測 Windows 桌面應用中的機密儲存與憑證安全而設計。")
    print("       支援 Python (.py), C# (.cs), JavaScript/TypeScript (.js, .ts) 等。\n")

    while True:
        while True:
            try:
                raw_path = input("請輸入欲掃描的專案目錄或檔案路徑\n(可直接從檔案總管將資料夾拖曳進此視窗，按 Enter 預設掃描當前目錄):\n> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n已離開程式。")
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
            result = None

        if result:
            # Display console report
            reporter = ConsoleReporter(use_color=True)
            reporter.report(result, out=sys.stdout)

            # Offer to export HTML & Markdown report
            now_str = datetime.datetime.now().strftime("%Y%m%d%H%M")
            default_dir = target_path if target_path.is_dir() else target_path.parent
            html_file = default_dir / f"audit-report_{now_str}.html"
            md_file = default_dir / f"audit-report_{now_str}.md"

            prompt_msg = "是否匯出審查報告 (HTML 與 Markdown)？(Y/n): "
            try:
                choice = input(prompt_msg).strip().lower()
                if choice in ("", "y", "yes"):
                    with open(html_file, "w", encoding="utf-8") as f:
                        HtmlReporter().report(result, out=f)
                    with open(md_file, "w", encoding="utf-8") as f:
                        MarkdownReporter().report(result, out=f)
                    print(f"\n[已儲存] HTML 審查報告: {html_file}")
                    print(f"[已儲存] Markdown 報告: {md_file}")
            except Exception as err:
                print(f"[警告] 匯出報告失敗: {err}")

        # Post-scan options: Continue scanning or Exit
        print("\n" + "=" * 72)
        print("請選擇下一步操作：")
        print("  [1] 繼續掃描其他資料夾 (預設，按 Enter 直接繼續)")
        print("  [2] 離開程式 (輸入 2 或 q)")
        try:
            next_action = input("> ").strip().lower()
            if next_action in ("2", "q", "quit", "exit"):
                print("\n感謝使用，程式已關閉。")
                break
            print("\n" + "-" * 72 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\n已離開程式。")
            break


def main():
    # If launched with no arguments and stdin is an interactive terminal,
    # enter friendly interactive mode to prevent instant window closing on double-click.
    if len(sys.argv) == 1 and sys.stdin.isatty():
        run_interactive_mode()
        sys.exit(0)

    # Standard CLI mode for command line, scripts, and CI/CD pipelines
    args = parse_args()
    now_str = datetime.datetime.now().strftime("%Y%m%d%H%M")

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
    elif args.format == "html":
        reporter = HtmlReporter()
    else:
        reporter = ConsoleReporter(use_color=not args.no_color)

    # Render output
    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            reporter.report(result, out=f)
        if args.format != "console":
            print(f"Report written to {out_path}")
    elif args.format in ("markdown", "html", "json"):
        # Auto timestamp filename when format requested without -o
        ext = "html" if args.format == "html" else ("md" if args.format == "markdown" else "json")
        out_path = Path(f"audit-report_{now_str}.{ext}").resolve()
        with open(out_path, "w", encoding="utf-8") as f:
            reporter.report(result, out=f)
        print(f"Report written to {out_path}")
    else:
        reporter.report(result, out=sys.stdout)

    if should_fail(result, args.fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
