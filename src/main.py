import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from analyzer import analyze_email, AnalysisResult


RISK_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[94m",
    "CLEAN":  "\033[92m",
}
RESET = "\033[0m"


def print_report(result: AnalysisResult, filename: str):
    color = RISK_COLORS.get(result.risk_level, "")
    print(f"\n{'='*60}")
    print(f"  File : {filename}")
    print(f"  Risk : {color}{result.risk_level}{RESET}  (score: {result.raw_score}/100)")
    print(f"  Flags: {result.total_findings} finding(s)")
    print(f"{'='*60}")

    if result.header_findings:
        print("\n[HEADER ANALYSIS]")
        for f in result.header_findings:
            print(f"  [{f.score:+3d}]  {f.reason}")

    if result.dns_findings:
        print("\n[LIVE DNS ANALYSIS]")
        for f in result.dns_findings:
            marker = f"[{f.score:+3d}]" if f.score > 0 else "[ ---]"
            print(f"  {marker}  {f.reason}")

    if result.url_findings:
        print("\n[URL ANALYSIS]")
        for f in result.url_findings:
            url_display = f.url[:70] + "..." if len(f.url) > 70 else f.url
            print(f"  [{f.score:+3d}]  {f.reason}")
            if url_display:
                print(f"         {url_display}")

    if result.vt_findings:
        print("\n[VIRUSTOTAL REPUTATION]")
        for f in result.vt_findings:
            marker = f"[{f.score:+3d}]" if f.score > 0 else "[ ---]"
            url_display = f.url[:70] + "..." if len(f.url) > 70 else f.url
            print(f"  {marker}  {f.reason}")
            if url_display:
                print(f"         {url_display}")

    if result.content_findings:
        print("\n[CONTENT ANALYSIS]")
        for f in result.content_findings:
            print(f"  [{f.score:+3d}]  {f.reason}")

    if result.total_findings == 0:
        print("\n  No suspicious indicators detected.")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detector — analyze .eml files for phishing indicators"
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help=".eml file(s) to analyze, or '-' to read from stdin",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the graphical interface",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a one-line summary per file instead of full report",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Enable live DNS checks for SPF/DKIM/DMARC (requires dnspython)",
    )
    parser.add_argument(
        "--vt-key",
        metavar="API_KEY",
        default=os.environ.get("VT_API_KEY"),
        help="VirusTotal API key for URL reputation checks (or set VT_API_KEY env var)",
    )
    args = parser.parse_args()

    if args.gui:
        from gui import launch
        launch()
        return

    if not args.files:
        parser.print_help()
        sys.exit(0)

    if args.vt_key:
        print(f"[*] VirusTotal integration enabled")
    if args.dns:
        print(f"[*] Live DNS analysis enabled")

    exit_code = 0

    for filepath in args.files:
        if filepath == "-":
            raw = sys.stdin.read()
            filename = "<stdin>"
        else:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
                filename = os.path.basename(filepath)
            except FileNotFoundError:
                print(f"Error: file not found: {filepath}", file=sys.stderr)
                exit_code = 1
                continue

        result = analyze_email(raw, vt_api_key=args.vt_key, live_dns=args.dns)

        if args.summary:
            color = RISK_COLORS.get(result.risk_level, "")
            print(f"{color}{result.risk_level:6}{RESET}  {result.raw_score:3}/100  {filename}")
        else:
            print_report(result, filename)

        if result.risk_level in ("HIGH", "MEDIUM"):
            exit_code = max(exit_code, 1)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
