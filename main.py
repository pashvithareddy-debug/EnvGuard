#!/usr/bin/env python3
"""
main.py
-------

EnvGuard CLI entry point.

Usage:
    python main.py <path>                    Scan a project directory
    python main.py <path> --severity high     Only show HIGH and above
    python main.py <path> --json              Machine-readable JSON report
    python main.py <path> --staged            Only scan git-staged files (used by the pre-commit hook)
    python main.py <path> --no-color          Disable ANSI colors
"""

import argparse
import subprocess
import sys
from pathlib import Path

from envguard.scanner import Scanner
from envguard.detector import Detector
from envguard.reporter import print_terminal_report, to_json_report, highest_severity
from envguard.rules import SEVERITY_ORDER


def get_staged_files(root: Path):
    """Return paths (relative to root) of files staged in git, for --staged mode."""
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: could not read staged files (is this a git repo?)", file=sys.stderr)
        sys.exit(2)
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Scan a project for exposed secrets and sensitive files before they reach GitHub.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory to scan (default: current directory)")
    parser.add_argument(
        "--severity",
        choices=[s.lower() for s in SEVERITY_ORDER],
        default=None,
        help="Only report findings at or above this severity",
    )
    parser.add_argument("--json", action="store_true", help="Output a JSON report instead of terminal output")
    parser.add_argument("--staged", action="store_true", help="Only scan files currently staged in git (for pre-commit use)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument(
        "--fail-on",
        choices=[s.lower() for s in SEVERITY_ORDER],
        default="high",
        help="Exit with a non-zero status if a finding at or above this severity exists (default: high). "
             "Useful for CI and git hooks.",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 2

    scanner = Scanner(str(root), detector=Detector())

    specific_files = None
    if args.staged:
        specific_files = get_staged_files(root)
        if not specific_files:
            print("No staged files to scan.")
            return 0

    result = scanner.scan(specific_files=specific_files)

    if args.json:
        print(to_json_report(result))
    else:
        min_sev = args.severity.upper() if args.severity else None
        print_terminal_report(result, min_severity=min_sev, use_color=not args.no_color)

    # Decide exit code based on --fail-on threshold, so this composes with
    # git hooks / CI without needing to parse output.
    worst = highest_severity(result)
    if worst is not None:
        threshold_rank = SEVERITY_ORDER.index(args.fail_on.upper())
        if SEVERITY_ORDER.index(worst) >= threshold_rank:
            return 1
    if result.sensitive_files:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
