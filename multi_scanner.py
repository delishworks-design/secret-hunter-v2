import yaml
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from local_scanner import LocalScanner
from github_scanner import GitHubScanner
from website_scanner import WebsiteScanner
from git_scanner import GitScanner
from config import config


class MultiScanner:
    def __init__(self, threads: int = None):
        self.threads = threads or config.MAX_THREADS
        self.local = LocalScanner()
        self.github = GitHubScanner()
        self.website = WebsiteScanner()
        self.git = GitScanner()

    def scan_from_config(self, config_path: str) -> Dict:
        with open(config_path, "r") as f:
            if config_path.endswith((".yml", ".yaml")):
                scan_config = yaml.safe_load(f)
            else:
                scan_config = json.load(f)

        targets = []
        if isinstance(scan_config, dict):
            if "targets" in scan_config:
                targets = scan_config["targets"]
            else:
                targets = [scan_config]
        elif isinstance(scan_config, list):
            targets = scan_config

        return self.scan_multiple(targets)

    def scan_multiple(self, targets: List[Dict]) -> Dict:
        all_results = []
        all_findings = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {}
            for target in targets:
                future = executor.submit(self._scan_target, target)
                future_to_target[future] = target

            for future in as_completed(future_to_target):
                try:
                    result = future.result()
                    all_results.append(result)
                    all_findings.extend(result.get("findings", []))
                except Exception as e:
                    target = future_to_target[future]
                    all_results.append({
                        "target": target.get("target", "unknown"),
                        "scan_type": target.get("type", "unknown"),
                        "error": str(e),
                        "findings": [],
                    })

        return {
            "scan_type": "multi",
            "results": all_results,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "stats": self._aggregate_stats(all_results),
        }

    def _scan_target(self, target: Dict) -> Dict:
        scan_type = target.get("type", "").lower()
        target_url = target.get("target", "")
        branches = target.get("branches", None)
        depth = target.get("depth", 3)
        history_depth = target.get("history_depth", 100)
        scan_history = target.get("scan_history", True)
        extensions = target.get("extensions", None)
        exclude = target.get("exclude", None)

        if scan_type == "local":
            return self.local.scan_directory(
                target_url,
                extensions=extensions,
                exclude=exclude,
            )
        elif scan_type == "github":
            return self.github.scan_repo(
                target_url,
                scan_history=scan_history,
                history_depth=history_depth,
            )
        elif scan_type == "website":
            return self.website.scan_url(
                target_url,
                depth=depth,
            )
        elif scan_type == "git":
            if target_url.startswith(("http://", "https://", "git@")):
                return self.git.scan_remote_repo(target_url, depth=history_depth)
            else:
                return self.git.scan_local_repo(target_url, branches=branches, depth=history_depth)
        else:
            return {"error": f"Unknown scan type: {scan_type}", "findings": [], "stats": {}}

    def _aggregate_stats(self, results: List[Dict]) -> Dict:
        total_findings = 0
        total_files = 0
        scan_types = {}
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for result in results:
            findings = result.get("findings", [])
            total_findings += len(findings)

            scan_type = result.get("scan_type", "unknown")
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1

            stats = result.get("stats", {})
            total_files += stats.get("files_scanned", 0)

            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            "total_findings": total_findings,
            "total_files_scanned": total_files,
            "scan_types": scan_types,
            "severity_distribution": severity_counts,
            "scans_completed": len(results),
        }
