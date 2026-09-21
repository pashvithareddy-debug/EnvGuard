"""
reporter.py
-----------

Turns a ScanResult into human-readable terminal output (Phase 8) or a
machine-readable JSON report (Phase 9), plus the severity summary
(Phase 7).
"""

import json
from .rules import SEVERITY_ORDER
from .scanner import ScanResult

# ANSI colors, kept minimal and safe to ignore on terminals that don't support them.
_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH": "\033[93m",       # yellow
    "MEDIUM": "\033[96m",     # cyan
    "LOW": "\033[90m",        # grey
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def _c(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(code, '')}{text}{_COLORS['RESET']}"


def severity_summary(result: ScanResult) -> dict:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in result.findings:
        counts[finding.severity] += 1
    counts["TOTAL"] = len(result.findings)
    return counts


def highest_severity(result: ScanResult) -> str:
    """Returns the most severe level found, or None if clean."""
    present = [f.severity for f in result.findings]
    if not present:
        return None
    return max(present, key=lambda s: SEVERITY_ORDER.index(s))


def print_terminal_report(result: ScanResult, min_severity: str = None, use_color: bool = True):
    print(_c("EnvGuard Security Scan", "BOLD", use_color))
    print("─" * 40)
    print(f"Root: {result.root}")
    print(f"Files scanned: {result.files_scanned}  |  skipped: {result.files_skipped}")
    print()

    if result.sensitive_files:
        print(_c("⚠ SENSITIVE FILES", "HIGH", use_color))
        for f in result.sensitive_files:
            print(f"  {f}")
        print()

    min_rank = SEVERITY_ORDER.index(min_severity) if min_severity else 0
    shown = [f for f in result.findings if SEVERITY_ORDER.index(f.severity) >= min_rank]

    if shown:
        print(_c("FINDINGS", "BOLD", use_color))
        print("─" * 40)
        # group by file for readability
        by_file = {}
        for f in shown:
            by_file.setdefault(f.file, []).append(f)

        for file, findings in by_file.items():
            print(f"\n{file}")
            for f in sorted(findings, key=lambda x: x.line):
                sev = _c(f.severity, f.severity, use_color)
                print(f"  Line {f.line:<5} [{sev}] {f.rule} — {f.description}")
                print(f"           matched: {f.matched_text}")
    else:
        print(_c("No findings at or above the selected severity.", "LOW", use_color))

    print()
    print(_c("SECURITY SUMMARY", "BOLD", use_color))
    print("─" * 40)
    summary = severity_summary(result)
    for level in SEVERITY_ORDER:
        print(f"{level:<9}: {summary[level]}")
    print(f"{'Sensitive files':<9}: {len(result.sensitive_files)}")
    print(f"{'Total findings':<9}: {summary['TOTAL']}")


def to_json_report(result: ScanResult) -> str:
    payload = result.to_dict()
    payload["summary"] = severity_summary(result)
    return json.dumps(payload, indent=2)
