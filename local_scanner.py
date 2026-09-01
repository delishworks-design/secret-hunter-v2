import os
from typing import List, Dict, Optional
from patterns import scan_text, ALL_PATTERNS, Pattern
from config import SCAN_EXTENSIONS, EXCLUDE_DIRS, config


class LocalScanner:
    def __init__(self, max_file_size: int = None, max_depth: int = None):
        self.max_file_size = max_file_size or config.MAX_FILE_SIZE
        self.max_depth = max_depth or config.MAX_DEPTH
        self.scanned_files = 0
        self.scanned_lines = 0
        self.findings = []
        self._seen = set()

    def scan_directory(
        self,
        path: str,
        extensions: List[str] = None,
        exclude: List[str] = None,
        patterns: List[Pattern] = None,
    ) -> Dict:
        if extensions is None:
            extensions = SCAN_EXTENSIONS
        if exclude is None:
            exclude = EXCLUDE_DIRS
        if patterns is None:
            patterns = ALL_PATTERNS

        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return {
                "error": f"Not a directory: {path}",
                "findings": [],
                "stats": self.get_stats(),
            }

        for root, dirs, files in os.walk(path):
            depth = root.replace(path, "").count(os.sep)
            if depth > self.max_depth:
                dirs.clear()
                continue

            dirs[:] = [d for d in dirs if d not in exclude]

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue

                filepath = os.path.join(root, fname)

                if self._should_skip(filepath):
                    continue

                file_findings = self._scan_file(filepath, patterns)
                self.findings.extend(file_findings)
                self.scanned_files += 1

        return {
            "scan_type": "local",
            "target": path,
            "findings": self.findings,
            "stats": self.get_stats(),
        }

    def _scan_file(self, filepath: str, patterns: List[Pattern] = None) -> List[Dict]:
        if patterns is None:
            patterns = ALL_PATTERNS

        findings = []
        try:
            size = os.path.getsize(filepath)
            if size > self.max_file_size:
                return findings

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            self.scanned_lines += content.count("\n") + 1

            raw_findings = scan_text(content, patterns)

            for finding in raw_findings:
                line_num = content[: finding["start"]].count("\n") + 1
                line_start = content.rfind("\n", 0, finding["start"]) + 1
                line_end = content.find("\n", finding["start"])
                if line_end == -1:
                    line_end = len(content)
                line_content = content[line_start:line_end].strip()

                dedup_key = (filepath, line_num, finding["pattern"], finding["match"])
                if dedup_key in self._seen:
                    continue
                self._seen.add(dedup_key)

                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "line_content": line_content,
                    "pattern": finding["pattern"],
                    "severity": finding["severity"],
                    "description": finding["description"],
                    "group": finding["group"],
                    "match": finding["match"],
                    "start": finding["start"],
                    "end": finding["end"],
                })

        except (PermissionError, FileNotFoundError, OSError):
            pass

        return findings

    def _should_skip(self, path: str) -> bool:
        if not os.path.exists(path):
            return True

        try:
            if os.path.getsize(path) > self.max_file_size:
                return True
        except OSError:
            return True

        parts = path.split(os.sep)
        for part in parts:
            if part in EXCLUDE_DIRS:
                return True

        return False

    def get_stats(self) -> Dict:
        return {
            "files_scanned": self.scanned_files,
            "lines_scanned": self.scanned_lines,
            "findings": len(self.findings),
        }
