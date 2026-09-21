#!/usr/bin/env python3
"""
install_hook.py
----------------

Copies hooks/pre-commit into the current git repository's .git/hooks
directory and makes it executable, wiring EnvGuard into `git commit`.
"""

import shutil
import stat
import subprocess
import sys
from pathlib import Path


def main():
    try:
        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: not inside a git repository.", file=sys.stderr)
        return 1

    repo_root = Path(repo_root)
    source = Path(__file__).parent / "hooks" / "pre-commit"
    dest = repo_root / ".git" / "hooks" / "pre-commit"

    shutil.copy(source, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed EnvGuard pre-commit hook at {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
