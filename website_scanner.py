import re
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import requests
from typing import Dict, List, Optional
from patterns import scan_text, ALL_PATTERNS, Pattern
from config import config


class WebsiteScanner:
    def __init__(self, proxy: str = None, timeout: int = None, auth: str = None, headers: Dict[str, str] = None):
        self.timeout = timeout or config.TIMEOUT
        self.proxies = (
            {"http": proxy or config.PROXY_URL, "https": proxy or config.PROXY_URL}
            if proxy or config.PROXY_URL
            else None
        )
        self.session = requests.Session()
        self.findings = []
        self.visited = set()
        self._seen = set()

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        if headers:
            self.session.headers.update(headers)
        if auth:
            self.session.headers["Authorization"] = auth

    def scan_url(self, url: str, depth: int = 3) -> Dict:
        self.findings = []
        self.visited = set()
        self._seen = set()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        page_findings = self._scan_page(url)
        self.findings.extend(page_findings)

        security_findings = self._check_security_headers(url)
        self.findings.extend(security_findings)

        path_findings = self._scan_common_paths(url)
        self.findings.extend(path_findings)

        if depth > 0:
            urls_to_crawl = self._crawl(url, 0, depth, set())
            for crawl_url in urls_to_crawl:
                if crawl_url not in self.visited:
                    self.visited.add(crawl_url)
                    crawl_findings = self._scan_page(crawl_url)
                    self.findings.extend(crawl_findings)

        return {
            "scan_type": "website",
            "target": url,
            "findings": self.findings,
            "stats": self._get_stats(),
        }

    def _scan_page(self, url: str) -> List[Dict]:
        findings = []
        try:
            response = self.session.get(url, timeout=self.timeout, proxies=self.proxies, verify=False, allow_redirects=True)
            header_findings = self._scan_headers(response)
            findings.extend(header_findings)

            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                body_findings = scan_text(response.text, ALL_PATTERNS)
                for finding in body_findings:
                    line_num = response.text[: finding["start"]].count("\n") + 1
                    dedup_key = (url, line_num, finding["pattern"], finding["match"])
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": url,
                            "line": line_num,
                            "line_content": "",
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })

                js_findings = self._scan_javascript(url, response.text)
                findings.extend(js_findings)

            if "javascript" in content_type:
                body_findings = scan_text(response.text, ALL_PATTERNS)
                for finding in body_findings:
                    line_num = response.text[: finding["start"]].count("\n") + 1
                    dedup_key = (url, line_num, finding["pattern"], finding["match"])
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": url,
                            "line": line_num,
                            "line_content": "",
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })

        except requests.RequestException:
            pass
        return findings

    def _scan_headers(self, response) -> List[Dict]:
        findings = []
        sensitive_headers = [
            "X-API-Key", "Authorization", "Set-Cookie", "X-Auth-Token",
            "X-Access-Token", "X-Debug-Token", "X-Trace-Id",
            "X-Backend-Server", "X-Powered-By", "Server",
        ]
        for header_name in sensitive_headers:
            value = response.headers.get(header_name, "")
            if value:
                header_text = f"{header_name}: {value}"
                header_findings = scan_text(header_text, ALL_PATTERNS)
                for finding in header_findings:
                    dedup_key = (response.url, header_name, finding["pattern"], finding["match"])
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": f"header:{header_name}",
                            "line": 0,
                            "line_content": header_text[:200],
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })

        all_headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        header_scan_findings = scan_text(all_headers_text, ALL_PATTERNS)
        for finding in header_scan_findings:
            dedup_key = (response.url, "all_headers", finding["pattern"], finding["match"])
            if dedup_key not in self._seen:
                self._seen.add(dedup_key)
                findings.append({
                    "file": "response_headers",
                    "line": 0,
                    "line_content": all_headers_text[:200],
                    "pattern": finding["pattern"],
                    "severity": finding["severity"],
                    "description": finding["description"],
                    "group": finding["group"],
                    "match": finding["match"],
                })
        return findings

    def _scan_javascript(self, page_url: str, html_content: str) -> List[Dict]:
        findings = []
        soup = BeautifulSoup(html_content, "html.parser")
        script_tags = soup.find_all("script", src=True)
        js_urls = []
        for tag in script_tags:
            src = tag.get("src", "")
            if src:
                full_url = urljoin(page_url, src)
                js_urls.append(full_url)

        for js_url in js_urls[:20]:
            try:
                resp = self.session.get(js_url, timeout=self.timeout, proxies=self.proxies, verify=False)
                js_findings = scan_text(resp.text, ALL_PATTERNS)
                for finding in js_findings:
                    line_num = resp.text[: finding["start"]].count("\n") + 1
                    dedup_key = (js_url, line_num, finding["pattern"], finding["match"])
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": js_url,
                            "line": line_num,
                            "line_content": "",
                            "pattern": finding["pattern"],
                            "severity": finding["severity"],
                            "description": finding["description"],
                            "group": finding["group"],
                            "match": finding["match"],
                        })
            except requests.RequestException:
                continue
        return findings

    def _scan_common_paths(self, base_url: str) -> List[Dict]:
        findings = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in config.SENSITIVE_PATHS:
            try:
                url = urljoin(base, path)
                resp = self.session.get(url, timeout=self.timeout, proxies=self.proxies, verify=False, allow_redirects=False)
                if resp.status_code not in (404, 405, 403):
                    body_findings = scan_text(resp.text, ALL_PATTERNS)
                    for finding in body_findings:
                        line_num = resp.text[: finding["start"]].count("\n") + 1
                        dedup_key = (url, line_num, finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": url,
                                "line": line_num,
                                "line_content": "",
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "group": finding["group"],
                                "match": finding["match"],
                            })
            except requests.RequestException:
                continue
        return findings

    def _crawl(self, url: str, depth: int, max_depth: int, visited: set) -> List[str]:
        if depth > max_depth:
            return []

        urls = []
        try:
            resp = self.session.get(url, timeout=self.timeout, proxies=self.proxies, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                if parsed.netloc and parsed.netloc == urlparse(url).netloc:
                    clean_url = urlunparse(parsed._replace(fragment=""))
                    if clean_url not in visited:
                        visited.add(clean_url)
                        urls.append(clean_url)
                        child_urls = self._crawl(clean_url, depth + 1, max_depth, visited)
                        urls.extend(child_urls)
        except requests.RequestException:
            pass
        return urls

    def _check_security_headers(self, url: str) -> List[Dict]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout, proxies=self.proxies, verify=False)
            headers = resp.headers

            security_checks = {
                "CORS": {
                    "headers": ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"],
                    "description": "CORS header analysis",
                },
                "CSP": {
                    "headers": ["Content-Security-Policy", "Content-Security-Policy-Report-Only"],
                    "description": "Content Security Policy analysis",
                },
                "HSTS": {
                    "headers": ["Strict-Transport-Security"],
                    "description": "HTTP Strict Transport Security analysis",
                },
            }

            for check_name, check_info in security_checks.items():
                found_header = False
                for header_name in check_info["headers"]:
                    value = headers.get(header_name, "")
                    if value:
                        found_header = True
                        dedup_key = (url, header_name, value)
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            findings.append({
                                "file": f"security_header:{header_name}",
                                "line": 0,
                                "line_content": f"{header_name}: {value}",
                                "pattern": f"{check_name} Header Present",
                                "severity": "INFO",
                                "description": f"{check_info['description']} - {header_name} found",
                                "group": "security_headers",
                                "match": value[:100],
                            })

                if not found_header:
                    dedup_key = (url, f"missing_{check_name}", "")
                    if dedup_key not in self._seen:
                        self._seen.add(dedup_key)
                        findings.append({
                            "file": f"security_header:missing_{check_name}",
                            "line": 0,
                            "line_content": f"Missing {check_name} headers",
                            "pattern": f"Missing {check_name}",
                            "severity": "MEDIUM",
                            "description": f"{check_info['description']} - No {check_name} headers found",
                            "group": "security_headers",
                            "match": "",
                        })

        except requests.RequestException:
            pass
        return findings

    def _get_stats(self) -> Dict:
        return {
            "urls_scanned": len(self.visited) + 1,
            "findings": len(self.findings),
        }
