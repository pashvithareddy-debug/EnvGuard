import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from envguard.rules import all_rules, SEVERITY_ORDER


def test_all_rules_have_valid_severity():
    for rule in all_rules():
        assert rule.severity in SEVERITY_ORDER


def test_all_rules_have_unique_names():
    names = [r.name for r in all_rules()]
    assert len(names) == len(set(names))


def test_severity_order_is_ascending():
    assert SEVERITY_ORDER == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
