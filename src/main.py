import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from analyzer import analyze_email, AnalysisResult


RISK_COLORS = {
    "HIGH":   "\033[91m",  # red
    "MEDIUM": "\033[93m",  # yellow
    "LOW":    "\033[94m",  # blue
    "CLEAN":  "\033[92m",  # green
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

    if result.url_findings:
        print("\n[URL ANALYSIS]")
        for f in result.url_findings:
            url_display = f.url[:70] + "..." if len(f.url) > 70 else f.url
            print(f"  [{f.score:+3d}]  {f.reason}")
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
        nargs="+",
        metavar="FILE",
        help=".eml file(s) to analyze, or '-' to read from stdin",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a one-line summary per file instead of the full report",
    )
    args = parser.parse_args()

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

        result = analyze_email(raw)

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
