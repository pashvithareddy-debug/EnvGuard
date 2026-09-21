"""
scanner.py
----------

Phase 2 (file traversal) + Phase 3 (sensitive file detection), wired up to
the Detector (Phase 4) to produce a full ScanResult.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from .detector import Detector, Finding
from .utils import (
    SCANNABLE_EXTENSIONS,
    DEFAULT_EXCLUDED_DIRS,
    MAX_FILE_SIZE,
    is_probably_binary,
    is_sensitive_filename,
    load_ignore_patterns,
    is_ignored,
)


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    files_skipped: int = 0
    sensitive_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "sensitive_files": self.sensitive_files,
            "findings": [f.to_dict() for f in self.findings],
        }


class Scanner:
    def __init__(self, root: str, detector: Detector = None):
        self.root = Path(root).resolve()
        self.detector = detector or Detector()
        self.ignore_patterns = load_ignore_patterns(self.root)

    def _iter_candidate_files(self):
        for path in self.root.rglob("*"):
            if path.is_dir():
                continue

            rel_parts = path.relative_to(self.root).parts
            if any(part in DEFAULT_EXCLUDED_DIRS for part in rel_parts[:-1]):
                continue

            rel_path = str(path.relative_to(self.root))
            if is_ignored(rel_path, self.ignore_patterns):
                continue

            yield path, rel_path

    def scan(self, specific_files: List[str] = None) -> ScanResult:
        """
        Run a full scan of the project. If `specific_files` is given (a list
        of paths relative to root), only those files are scanned — this is
        what the git pre-commit hook uses to check only staged files.
        """
        result = ScanResult(root=str(self.root))

        if specific_files is not None:
            candidates = []
            for rel in specific_files:
                p = self.root / rel
                if p.exists() and p.is_file():
                    candidates.append((p, rel))
        else:
            candidates = list(self._iter_candidate_files())

        for path, rel_path in candidates:
            filename = path.name

            # Phase 3: sensitive filename check happens regardless of extension.
            if is_sensitive_filename(filename):
                result.sensitive_files.append(rel_path)

            if path.suffix not in SCANNABLE_EXTENSIONS and not filename.startswith(".env"):
                result.files_skipped += 1
                continue

            if is_probably_binary(path):
                result.files_skipped += 1
                continue

            try:
                size = path.stat().st_size
            except OSError:
                result.files_skipped += 1
                continue

            if size > MAX_FILE_SIZE:
                result.files_skipped += 1
                continue

            try:
                text = path.read_text(errors="ignore")
            except OSError:
                result.files_skipped += 1
                continue

            findings = self.detector.scan_text(rel_path, text)
            result.findings.extend(findings)
            result.files_scanned += 1

        return result
