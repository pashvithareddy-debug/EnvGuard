"""
utils.py
--------

Small shared helpers: masking secret values before they're printed,
loading ignore patterns, and deciding whether a file is safe/worth scanning.
"""

from pathlib import Path
import fnmatch

# Extensions EnvGuard will actually read and scan.
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".json", ".yml", ".yaml", ".xml", ".properties", ".env", ".txt",
    ".ini", ".cfg", ".toml", ".sh", ".bash", ".md",
}

# Directories that are never scanned, regardless of .envguardignore.
DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "target", "dist", "build", ".mypy_cache", ".pytest_cache", "env",
}

# Files that are themselves sensitive just by existing (Phase 3).
SENSITIVE_FILENAME_PATTERNS = [
    ".env", ".env.*", "credentials.json", "secrets.yaml", "secrets.yml",
    "id_rsa", "id_rsa.pub", "id_dsa", "id_ecdsa", "id_ed25519",
    "*.pem", "*.pfx", "*.p12", "*.key", "known_hosts", ".npmrc", ".netrc",
]

# Max file size (bytes) EnvGuard will read into memory. Avoids choking on huge files.
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def is_probably_binary(path: Path, sniff_bytes: int = 1024) -> bool:
    """Cheap binary detector: look for a NUL byte in the first chunk."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sniff_bytes)
        return b"\x00" in chunk
    except OSError:
        return True


def is_sensitive_filename(filename: str) -> bool:
    """Phase 3: does the filename itself indicate a sensitive file?"""
    return any(fnmatch.fnmatch(filename, pat) for pat in SENSITIVE_FILENAME_PATTERNS)


def load_ignore_patterns(root: Path) -> list:
    """
    Phase 12: read .envguardignore from the project root, if present.
    Each non-empty, non-comment line is treated as an fnmatch-style pattern
    matched against the file's path relative to root.
    """
    ignore_file = root / ".envguardignore"
    patterns = []
    if ignore_file.exists():
        for line in ignore_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(rel_path: str, patterns: list) -> bool:
    for pat in patterns:
        pat_norm = pat.rstrip("/")
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(rel_path, f"{pat_norm}/*"):
            return True
        # allow matching a bare directory name anywhere in the path
        if pat_norm and f"/{pat_norm}/" in f"/{rel_path}/":
            return True
    return False


def mask_secret(value: str, keep: int = 4) -> str:
    """
    Phase 13: never print a full secret. Keep a small prefix and mask the rest.
    'abc123456789' -> 'abc1********'
    """
    if not value:
        return value
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * max(4, len(value) - keep)
