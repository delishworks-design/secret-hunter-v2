import time
from typing import Dict, List, Optional
from github import Github, GithubException, RateLimitExceededException
from patterns import scan_text, ALL_PATTERNS, Pattern
from config import config


class GitHubScanner:
    def __init__(self, token: str = None):
        self.token = token or config.get_github_token()
        self.github = Github(self.token) if self.token else Github()
        self.findings = []
        self.api_calls = 0
        self._seen = set()

    def scan_repo(
        self,
        repo_name: str,
        branch: str = None,
        scan_history: bool = True,
        history_depth: int = 100,
    ) -> Dict:
        try:
            repo = self.github.get_repo(repo_name)
        except GithubException as e:
            return {"error": f"Failed to access repo: {e.data.get('message', str(e))}", "findings": [], "stats": self._get_stats()}

        if branch is None:
            branch = repo.default_branch

        self.findings = []
        self._seen = set()

        file_findings = self._scan_files(repo, branch)
        self.findings.extend(file_findings)

        if scan_history:
            commit_findings = self._scan_commits(repo, branch, history_depth)
            self.findings.extend(commit_findings)

        pr_findings = self._scan_prs(repo)
        self.findings.extend(pr_findings)

        issue_findings = self._scan_issues(repo)
        self.findings.extend(issue_findings)

        workflow_findings = self._scan_workflows(repo)
        self.findings.extend(workflow_findings)

        return {
            "scan_type": "github",
            "target": repo_name,
            "branch": branch,
            "findings": self.findings,
            "stats": self._get_stats(),
        }

    def _scan_files(self, repo, branch: str) -> List[Dict]:
        findings = []
        try:
            tree = repo.get_git_tree(branch, recursive=True)
            for item in tree.tree:
                if item.type != "blob":
                    continue
                ext = "." + item.path.rsplit(".", 1)[-1].lower() if "." in item.path else ""
                if ext not in config.SCAN_EXTENSIONS and ext:
                    continue
                try:
                    self._check_rate_limit()
                    content = repo.get_contents(item.path, ref=branch)
                    if isinstance(content, list):
                        continue
                    file_content = content.decoded_content.decode("utf-8", errors="ignore")
                    raw_findings = scan_text(file_content, ALL_PATTERNS)

                    for finding in raw_findings:
                        line_num = file_content[: finding["start"]].count("\n") + 1
                        line_start = file_content.rfind("\n", 0, finding["start"]) + 1
                        line_end = file_content.find("\n", finding["start"])
                        if line_end == -1:
                            line_end = len(file_content)
                        line_content = file_content[line_start:line_end].strip()

                        dedup_key = (item.path, line_num, finding["pattern"], finding["match"])
                        if dedup_key in self._seen:
                            continue
                        self._seen.add(dedup_key)

                        findings.append({
                            "file": item.path,
                            "line": line_num,
                            "line_content": line_content,
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })
                except GithubException:
                    continue
        except GithubException:
            pass
        return findings

    def _scan_commits(self, repo, branch: str, depth: int) -> List[Dict]:
        findings = []
        try:
            commits = repo.get_commits(sha=branch)
            count = 0
            for commit in commits:
                if count >= depth:
                    break
                count += 1
                try:
                    self._check_rate_limit()
                    commit_data = commit.commit
                    message = commit_data.message or ""
                    msg_findings = scan_text(message, ALL_PATTERNS)
                    for finding in msg_findings:
                        dedup_key = ("commit_msg", commit.sha[:8], finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": f"commit:{commit.sha[:8]}",
                                "line": 0,
                                "line_content": message[:200],
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "group": finding["group"],
                                "match": finding["match"],
                            })

                    if commit_data.author and commit_data.author.login:
                        author_info = f"{commit_data.author.login}"
                        author_findings = scan_text(author_info, ALL_PATTERNS)
                        for finding in author_findings:
                            dedup_key = ("commit_author", commit.sha[:8], finding["pattern"], finding["match"])
                            if dedup_key not in self._seen:
                                self._seen.add(dedup_key)
                                findings.append({
                                    "file": f"commit_author:{commit.sha[:8]}",
                                    "line": 0,
                                    "line_content": author_info,
                                    "pattern": finding["pattern"],
                                    "severity": finding["severity"],
                                    "description": finding["description"],
                                    "group": finding["group"],
                                    "match": finding["match"],
                                })
                except GithubException:
                    continue
        except GithubException:
            pass
        return findings

    def _scan_prs(self, repo) -> List[Dict]:
        findings = []
        try:
            prs = repo.get_pulls(state="all", sort="updated", direction="desc")
            count = 0
            for pr in prs:
                if count >= 50:
                    break
                count += 1
                try:
                    self._check_rate_limit()
                    pr_text = f"{pr.title}\n{pr.body or ''}"
                    pr_findings = scan_text(pr_text, ALL_PATTERNS)
                    for finding in pr_findings:
                        dedup_key = (f"pr_{pr.number}", finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": f"pr:#{pr.number}",
                                "line": 0,
                                "line_content": (pr.body or "")[:200],
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "group": finding["group"],
                                "match": finding["match"],
                            })
                except GithubException:
                    continue
        except GithubException:
            pass
        return findings

    def _scan_issues(self, repo) -> List[Dict]:
        findings = []
        try:
            issues = repo.get_issues(state="all", sort="updated", direction="desc")
            count = 0
            for issue in issues:
                if count >= 50:
                    break
                count += 1
                try:
                    self._check_rate_limit()
                    issue_text = f"{issue.title}\n{issue.body or ''}"
                    issue_findings = scan_text(issue_text, ALL_PATTERNS)
                    for finding in issue_findings:
                        dedup_key = (f"issue_{issue.number}", finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": f"issue:#{issue.number}",
                                "line": 0,
                                "line_content": (issue.body or "")[:200],
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "group": finding["group"],
                                "match": finding["match"],
                            })
                except GithubException:
                    continue
        except GithubException:
            pass
        return findings

    def _scan_workflows(self, repo) -> List[Dict]:
        findings = []
        try:
            workflows = repo.get_workflows()
            for workflow in workflows:
                try:
                    self._check_rate_limit()
                    contents = repo.get_contents(f".github/workflows/{workflow.path}")
                    if isinstance(contents, list):
                        continue
                    wf_content = contents.decoded_content.decode("utf-8", errors="ignore")
                    wf_findings = scan_text(wf_content, ALL_PATTERNS)
                    for finding in wf_findings:
                        line_num = wf_content[: finding["start"]].count("\n") + 1
                        line_start = wf_content.rfind("\n", 0, finding["start"]) + 1
                        line_end = wf_content.find("\n", finding["start"])
                        if line_end == -1:
                            line_end = len(wf_content)
                        line_content = wf_content[line_start:line_end].strip()

                        dedup_key = (f".github/workflows/{workflow.path}", line_num, finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": f".github/workflows/{workflow.path}",
                                "line": line_num,
                                "line_content": line_content,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "group": finding["group"],
                                "match": finding["match"],
                            })
                except GithubException:
                    continue
        except GithubException:
            pass
        return findings

    def _check_rate_limit(self):
        self.api_calls += 1
        if self.api_calls % 30 == 0:
            try:
                rate_limit = self.github.get_rate_limit()
                remaining = rate_limit.core.remaining
                if remaining < 10:
                    reset_time = rate_limit.core.reset.timestamp()
                    wait_time = max(reset_time - time.time(), 1)
                    time.sleep(min(wait_time, 60))
            except Exception:
                time.sleep(1)

    def _get_stats(self) -> Dict:
        return {
            "findings": len(self.findings),
            "api_calls": self.api_calls,
        }
