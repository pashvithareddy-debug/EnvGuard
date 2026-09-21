"""
detector.py
-----------

The secret-detection engine. Runs each Rule against file content line by
line and produces structured Finding objects (Phase 4 + Phase 6).
"""

from dataclasses import dataclass, field
from typing import List
from .rules import Rule, all_rules
from .utils import mask_secret


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    description: str
    matched_text: str  # already masked before storage

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "matched_text": self.matched_text,
        }


class Detector:
    """Applies the rule set to file contents."""

    def __init__(self, rules: List[Rule] = None):
        self.rules = rules if rules is not None else all_rules()

    def scan_text(self, file_label: str, text: str) -> List[Finding]:
        """
        Scan a block of text (the contents of one file) line by line against
        every rule. Returns a list of Finding objects, secrets pre-masked.
        """
        findings: List[Finding] = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for rule in self.rules:
                match = rule.pattern.search(line)
                if not match:
                    continue

                matched_raw = match.group(0)
                masked = mask_secret(matched_raw.strip())

                findings.append(
                    Finding(
                        file=file_label,
                        line=line_no,
                        rule=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        matched_text=masked,
                    )
                )
        return findings
