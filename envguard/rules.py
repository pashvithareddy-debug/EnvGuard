"""
rules.py
--------

Defines the Rule data structure and the built-in library of secret-detection
rules used by the detector. Rules are intentionally data (not hardcoded
if/else logic) so new patterns can be added without touching scanner code.
"""

from dataclasses import dataclass
import re
from typing import Pattern


# Severity levels, ordered from least to most severe.
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class Rule:
    name: str                # short machine-friendly identifier, e.g. "AWS_ACCESS_KEY"
    pattern: Pattern         # compiled regex
    severity: str            # one of SEVERITY_ORDER
    description: str         # human-readable explanation shown in reports

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity)


def _rx(pattern: str) -> Pattern:
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# Built-in rules
#
# These are intentionally broad, readable regexes rather than an attempt at
# perfectly precise secret detection (a genuinely production-grade scanner
# would use entropy analysis, provider-specific formats, etc. in addition
# to this). Good enough to catch common accidental leaks and to demonstrate
# the architecture end-to-end.
# ---------------------------------------------------------------------------

RULES = [
    Rule(
        name="AWS_ACCESS_KEY_ID",
        pattern=_rx(r"\bAKIA[0-9A-Z]{16}\b"),
        severity="CRITICAL",
        description="Possible AWS Access Key ID",
    ),
    Rule(
        name="AWS_SECRET_ACCESS_KEY",
        pattern=_rx(
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        severity="CRITICAL",
        description="Possible AWS Secret Access Key",
    ),
    Rule(
        name="PRIVATE_KEY_BLOCK",
        pattern=_rx(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        severity="CRITICAL",
        description="Embedded private key block",
    ),
    Rule(
        name="GENERIC_API_KEY",
        pattern=_rx(
            r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"
        ),
        severity="HIGH",
        description="Possible API key assignment",
    ),
    Rule(
        name="OPENAI_STYLE_KEY",
        pattern=_rx(r"\bsk-[A-Za-z0-9]{16,}\b"),
        severity="HIGH",
        description="Possible OpenAI-style secret key (sk-...)",
    ),
    Rule(
        name="SLACK_TOKEN",
        pattern=_rx(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        severity="HIGH",
        description="Possible Slack token",
    ),
    Rule(
        name="GITHUB_TOKEN",
        pattern=_rx(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        severity="HIGH",
        description="Possible GitHub personal access token",
    ),
    Rule(
        name="JWT_TOKEN",
        pattern=_rx(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity="MEDIUM",
        description="Possible JSON Web Token (JWT)",
    ),
    Rule(
        name="PASSWORD_ASSIGNMENT",
        pattern=_rx(
            r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"
        ),
        severity="HIGH",
        description="Hardcoded password assignment",
    ),
    Rule(
        name="GENERIC_SECRET",
        pattern=_rx(
            r"(?i)\b(secret|token|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{8,})['\"]"
        ),
        severity="MEDIUM",
        description="Generic secret / token assignment",
    ),
    Rule(
        name="DB_CONNECTION_STRING",
        pattern=_rx(
            r"(?i)\b(postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^:\s]+:[^@\s]+@[^\s'\"]+"
        ),
        severity="HIGH",
        description="Database connection string with embedded credentials",
    ),
    Rule(
        name="SUSPICIOUS_ENV_ASSIGNMENT",
        pattern=_rx(
            r"(?im)^\s*[A-Z_][A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD|PWD)\s*=\s*.+$"
        ),
        severity="LOW",
        description="Env-style variable name suggests it may hold a credential",
    ),
]


def all_rules():
    """Return the built-in rule list."""
    return list(RULES)
