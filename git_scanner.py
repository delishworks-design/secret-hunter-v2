import os
import tempfile
import shutil
import git
from typing import Dict, List, Optional
from patterns import scan_text, ALL_PATTERNS, Pattern
from config import config


class GitScanner:
    def __init__(self):
        self.findings = []
        self._seen = set()

    def scan_local_repo(self, path: str, branches: List[str] = None, depth: int = 100) -> Dict:
        self.findings = []
        self._seen = set()

        path = os.path.abspath(path)
        if not os.path.isdir(os.path.join(path, ".git")):
            return {"error": f"Not a git repository: {path}", "findings": [], "stats": self._get_stats()}

        try:
            repo = git.Repo(path)
        except git.InvalidGitRepositoryError as e:
            return {"error": f"Invalid git repository: {e}", "findings": [], "stats": self._get_stats()}

        config_findings = self._scan_git_config(path)
        self.findings.extend(config_findings)

        branch_names = branches or [b.name for b in repo.branches]
        for branch_name in branch_names:
            try:
                branch_findings = self._scan_commit_history(repo, branch_name, depth)
                self.findings.extend(branch_findings)
            except Exception:
                continue

        branch_findings = self._scan_branches(repo)
        self.findings.extend(branch_findings)

        deleted_findings = self._scan_deleted_files(repo)
        self.findings.extend(deleted_findings)

        return {
            "scan_type": "git",
            "target": path,
            "findings": self.findings,
            "stats": self._get_stats(),
        }

    def scan_remote_repo(self, url: str, depth: int = 100) -> Dict:
        self.findings = []
        self._seen = set()
        tmpdir = tempfile.mkdtemp(prefix="secrethunter_")
        try:
            repo = git.Repo.clone_from(url, tmpdir, depth=depth)
            local_result = self.scan_local_repo(tmpdir, depth=depth)
            local_result["scan_type"] = "git_remote"
            local_result["target"] = url
            return local_result
        except git.GitCommandError as e:
            return {"error": f"Failed to clone repo: {e}", "findings": [], "stats": self._get_stats()}
        finally:
            self._cleanup(tmpdir)

    def _scan_commit_history(self, repo, branch: str, depth: int) -> List[Dict]:
        findings = []
        try:
            repo.git.checkout(branch, force=True)
        except git.GitCommandError:
            return findings

        try:
            commits = list(repo.iter_commits(branch, max_count=depth))
        except git.GitCommandError:
            return findings

        for commit in commits:
            message = commit.message or ""
            msg_findings = scan_text(message, ALL_PATTERNS)
            for finding in msg_findings:
                dedup_key = ("commit_msg", commit.hexsha[:8], finding["pattern"], finding["match"])
                if dedup_key not in self._seen:
                    self._seen.add(dedup_key)
                    findings.append({
                        "file": f"commit:{commit.hexsha[:8]}",
                        "line": 0,
                        "line_content": message[:200],
                        "pattern": finding["pattern"],
                        "severity": finding["severity"],
                        "description": finding["description"],
                        "group": finding["group"],
                        "match": finding["match"],
                    })

            try:
                if commit.parents:
                    parent = commit.parents[0]
                    diff = parent.diff(commit, create_patch=False)
                    for d in diff:
                        try:
                            blob = d.blob
                            content = blob.data_stream.read().decode("utf-8", errors="ignore")
                            content_findings = scan_text(content, ALL_PATTERNS)
                            for finding in content_findings:
                                line_num = content[: finding["start"]].count("\n") + 1
                                dedup_key = (d.a_blob.path if d.a_blob else "unknown", line_num, finding["pattern"], finding["match"])
                                if dedup_key not in self._seen:
                                    self._seen.add(dedup_key)
                                    findings.append({
                                        "file": d.a_blob.path if d.a_blob else "unknown",
                                        "line": line_num,
                                        "line_content": "",
                                        "pattern": finding["pattern"],
                                        "severity": finding["severity"],
                                        "description": finding["description"],
                                        "group": finding["group"],
                                        "match": finding["match"],
                                    })
                        except Exception:
                            continue
            except Exception:
                continue

        return findings

    def _scan_branches(self, repo) -> List[Dict]:
        findings = []
        current_branch = repo.active_branch.name if not repo.head.is_detached else repo.head.commit.hexsha

        for branch in repo.branches:
            if branch.name == current_branch:
                continue
            try:
                repo.git.checkout(branch.name, force=True)
                branch_findings = self._scan_commit_history(repo, branch.name, 10)
                for finding in branch_findings:
                    finding["file"] = f"branch:{branch.name}/{finding['file']}"
                findings.extend(branch_findings)
            except Exception:
                continue

        try:
            repo.git.checkout(current_branch, force=True)
        except Exception:
            pass

        return findings

    def _scan_deleted_files(self, repo) -> List[Dict]:
        findings = []
        for commit in repo.iter_commits():
            try:
                if not commit.parents:
                    continue
                parent = commit.parents[0]
                deleted_files = parent.diff(commit, diff_filter="D")
                for d in deleted_files:
                    try:
                        blob = d.blob
                        content = blob.data_stream.read().decode("utf-8", errors="ignore")
                        content_findings = scan_text(content, ALL_PATTERNS)
                        for finding in content_findings:
                            line_num = content[: finding["start"]].count("\n") + 1
                            dedup_key = (f"deleted:{d.a_blob.path}", line_num, finding["pattern"], finding["match"])
                            if dedup_key not in self._seen:
                                self._seen.add(dedup_key)
                                findings.append({
                                    "file": f"deleted:{d.a_blob.path}",
                                    "line": line_num,
                                    "line_content": "",
                                    "pattern": finding["pattern"],
                                    "severity": finding["severity"],
                                    "description": f"[DELETED] {finding['description']}",
                                    "group": finding["group"],
                                    "match": finding["match"],
                                })
                    except Exception:
                        continue
            except Exception:
                continue
        return findings

    def _scan_git_config(self, repo_path: str) -> List[Dict]:
        findings = []
        git_config_path = os.path.join(repo_path, ".git", "config")
        if not os.path.isfile(git_config_path):
            return findings

        try:
            with open(git_config_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            config_findings = scan_text(content, ALL_PATTERNS)
            for finding in config_findings:
                line_num = content[: finding["start"]].count("\n") + 1
                line_start = content.rfind("\n", 0, finding["start"]) + 1
                line_end = content.find("\n", finding["start"])
                if line_end == -1:
                    line_end = len(content)
                line_content = content[line_start:line_end].strip()

                dedup_key = (".git/config", line_num, finding["pattern"], finding["match"])
                if dedup_key not in self._seen:
                    self._seen.add(dedup_key)
                    findings.append({
                        "file": ".git/config",
                        "line": line_num,
                        "line_content": line_content,
                        "pattern": finding["pattern"],
                        "severity": finding["severity"],
                        "description": finding["description"],
                        "group": finding["group"],
                        "match": finding["match"],
                    })
        except (FileNotFoundError, PermissionError):
            pass

        git_credentials_path = os.path.join(repo_path, ".git", "credentials")
        if os.path.isfile(git_credentials_path):
            try:
                with open(git_credentials_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                cred_findings = scan_text(content, ALL_PATTERNS)
                for finding in cred_findings:
                    dedup_key = (".git/credentials", 1, finding["pattern"], finding["match"])
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": ".git/credentials",
                            "line": 1,
                            "line_content": content[:200],
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })
            except (FileNotFoundError, PermissionError):
                pass

        return findings

    def _cleanup(self, path: str):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass

    def _get_stats(self) -> Dict:
        return {"findings": len(self.findings)}
