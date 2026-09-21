import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from envguard.scanner import Scanner


def make_project(files: dict) -> Path:
    """Create a temp directory populated with the given {relative_path: content} files."""
    tmp = Path(tempfile.mkdtemp())
    for rel_path, content in files.items():
        full = tmp / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
    return tmp


def test_scan_finds_secret_in_python_file():
    root = make_project({"config.py": 'api_key = "abcdef1234567890abcd"\n'})
    result = Scanner(str(root)).scan()
    assert result.files_scanned == 1
    assert any(f.rule == "GENERIC_API_KEY" for f in result.findings)


def test_scan_detects_sensitive_env_file():
    root = make_project({".env": "SECRET=whatever\n"})
    result = Scanner(str(root)).scan()
    assert ".env" in result.sensitive_files


def test_scan_ignores_excluded_directories():
    root = make_project({
        "node_modules/pkg/index.js": 'api_key = "abcdef1234567890abcd"\n',
        "app.js": "console.log('hello');\n",
    })
    result = Scanner(str(root)).scan()
    assert result.files_scanned == 1  # only app.js
    assert result.findings == []


def test_envguardignore_excludes_matching_paths():
    root = make_project({
        "tests/fixture.py": 'password = "not_a_real_secret"\n',
        ".envguardignore": "tests/\n",
    })
    result = Scanner(str(root)).scan()
    assert result.findings == []


def test_empty_project_has_no_findings():
    root = make_project({})
    result = Scanner(str(root)).scan()
    assert result.files_scanned == 0
    assert result.findings == []
    assert result.sensitive_files == []


def test_multiple_secrets_in_one_file():
    content = (
        'api_key = "abcdef1234567890abcd"\n'
        'password = "SuperSecret123"\n'
    )
    root = make_project({"config.py": content})
    result = Scanner(str(root)).scan()
    rules_found = {f.rule for f in result.findings}
    assert "GENERIC_API_KEY" in rules_found
    assert "PASSWORD_ASSIGNMENT" in rules_found
