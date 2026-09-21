import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from envguard.detector import Detector


def test_detects_aws_access_key():
    detector = Detector()
    findings = detector.scan_text("config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"')
    aws_findings = [f for f in findings if f.rule == "AWS_ACCESS_KEY_ID"]
    assert len(aws_findings) == 1
    assert aws_findings[0].severity == "CRITICAL"


def test_detects_generic_api_key():
    detector = Detector()
    findings = detector.scan_text("config.py", 'api_key = "abcdef1234567890abcd"')
    assert any(f.rule == "GENERIC_API_KEY" for f in findings)


def test_detects_password_assignment():
    detector = Detector()
    findings = detector.scan_text("settings.py", 'password = "SuperSecret123"')
    assert any(f.rule == "PASSWORD_ASSIGNMENT" for f in findings)


def test_detects_private_key_block():
    detector = Detector()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIExampleKeyData\n-----END RSA PRIVATE KEY-----"
    findings = detector.scan_text("id_rsa", text)
    assert any(f.rule == "PRIVATE_KEY_BLOCK" and f.severity == "CRITICAL" for f in findings)


def test_no_false_positive_on_plain_code():
    detector = Detector()
    findings = detector.scan_text("app.py", "def add(a, b):\n    return a + b\n")
    assert findings == []


def test_masking_applied_to_matched_text():
    detector = Detector()
    findings = detector.scan_text("config.py", 'api_key = "abcdef1234567890abcd"')
    match = next(f for f in findings if f.rule == "GENERIC_API_KEY")
    assert "abcdef1234567890abcd" not in match.matched_text
    assert "*" in match.matched_text


def test_line_numbers_are_correct():
    detector = Detector()
    text = "line1\nline2\napi_key = \"abcdef1234567890abcd\"\nline4"
    findings = detector.scan_text("config.py", text)
    assert findings[0].line == 3
