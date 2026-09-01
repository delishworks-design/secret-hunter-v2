import requests
from typing import Dict, List, Optional
from patterns import scan_text, ALL_PATTERNS
from config import config


class SecretAcquirer:
    def __init__(self, timeout: int = None, proxy: str = None):
        self.timeout = timeout or config.TIMEOUT
        self.proxy = proxy or config.PROXY_URL
        self.results = []
        self._seen = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

    def acquire_from_debug(self, url: str) -> Dict:
        self.results = []
        self._seen = set()
        base_url = url.rstrip("/")

        debug_endpoints = [
            "/debug", "/debug/vars", "/debug/pprof/",
            "/trace", "/trace/requests",
            "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
            "/actuator/configprops", "/actuator/mappings", "/actuator/beans",
            "/manage", "/manage/env", "/manage/health",
            "/jolokia", "/jolokia/list",
            "/console", "/console/login",
            "/phpinfo.php", "/info.php", "/test.php",
            "/.env", "/env.php",
            "/debug/default/view", "/debug/default/toolbar",
            "/_profiler", "/_profiler/phpinfo",
            "/__debug__/", "/__debug__/toolbar",
            "/telescope", "/telescope/requests",
            "/horizon", "/horizon/dashboard",
            "/clockwork", "/clockwork/latest",
        ]

        for endpoint in debug_endpoints:
            test_url = f"{base_url}{endpoint}"
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code in (200, 301, 302, 401):
                    findings = scan_text(response.text, ALL_PATTERNS)
                    for finding in findings:
                        dedup_key = (test_url, finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            self.results.append({
                                "source": "debug_endpoint",
                                "url": test_url,
                                "endpoint": endpoint,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "match": finding["match"],
                                "status_code": response.status_code,
                            })

                    if len(response.text) > 100:
                        env_findings = scan_text(response.text, ALL_PATTERNS)
                        for finding in env_findings:
                            dedup_key = (test_url, "env_" + finding["pattern"], finding["match"])
                            if dedup_key not in self._seen:
                                self._seen.add(dedup_key)
                                self.results.append({
                                    "source": "debug_env",
                                    "url": test_url,
                                    "endpoint": endpoint,
                                    "pattern": finding["pattern"],
                                    "severity": finding["severity"],
                                    "description": finding["description"],
                                    "match": finding["match"],
                                    "status_code": response.status_code,
                                })
            except requests.RequestException:
                continue

        return {
            "scan_type": "secret_acquire_debug",
            "target": url,
            "endpoints_tested": len(debug_endpoints),
            "secrets_found": len(self.results),
            "results": self.results,
        }

    def acquire_from_env(self, url: str) -> Dict:
        self.results = []
        self._seen = set()
        base_url = url.rstrip("/")

        env_paths = [
            "/.env", "/.env.local", "/.env.dev", "/.env.development",
            "/.env.staging", "/.env.production", "/.env.test",
            "/.env.bak", "/.env.backup", "/.env.old", "/.env.save",
            "/env", "/env.local", "/env.dev",
            "/.env.example", "/.env.sample", "/.env.template",
            "/.environment", "/environment",
            "/config/.env", "/config/env",
            "/app/.env", "/src/.env",
            "/public/.env", "/private/.env",
            "/var/.env", "/tmp/.env",
        ]

        for path in env_paths:
            test_url = f"{base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code == 200:
                    findings = scan_text(response.text, ALL_PATTERNS)
                    for finding in findings:
                        dedup_key = (test_url, finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            self.results.append({
                                "source": "env_file",
                                "url": test_url,
                                "path": path,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "match": finding["match"],
                                "status_code": response.status_code,
                            })
            except requests.RequestException:
                continue

        return {
            "scan_type": "secret_acquire_env",
            "target": url,
            "paths_tested": len(env_paths),
            "secrets_found": len(self.results),
            "results": self.results,
        }

    def acquire_from_config(self, url: str) -> Dict:
        self.results = []
        self._seen = set()
        base_url = url.rstrip("/")

        config_paths = [
            "/config", "/config.json", "/config.yml", "/config.yaml",
            "/config.xml", "/config.ini", "/config.php", "/config.py",
            "/settings", "/settings.json", "/settings.yml",
            "/configuration", "/configuration.json",
            "/app.json", "/app.yml", "/app.yaml",
            "/application.yml", "/application.yaml", "/application.properties",
            "/application.json", "/application.toml",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
            "/wp-config.php~", "/wp-config.php.swp",
            "/.config", "/.config.json",
            "/database.yml", "/database.json", "/database.php",
            "/database.cfg", "/database.ini",
            "/credentials", "/credentials.json", "/credentials.yml",
            "/secrets.json", "/secrets.yml", "/secrets.yaml",
            "/keys.json", "/keys.yml",
            "/docker-compose.yml", "/docker-compose.yaml",
            "/Dockerfile", "/.dockerignore",
            "/terraform.tfvars", "/terraform.tfstate",
            "/vars.yml", "/vars.json",
        ]

        for path in config_paths:
            test_url = f"{base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if response.status_code == 200 and len(response.text) > 10:
                    findings = scan_text(response.text, ALL_PATTERNS)
                    for finding in findings:
                        dedup_key = (test_url, finding["pattern"], finding["match"])
                        if dedup_key not in self._seen:
                            self._seen.add(dedup_key)
                            self.results.append({
                                "source": "config_file",
                                "url": test_url,
                                "path": path,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"],
                                "description": finding["description"],
                                "match": finding["match"],
                                "status_code": response.status_code,
                            })
            except requests.RequestException:
                continue

        return {
            "scan_type": "secret_acquire_config",
            "target": url,
            "paths_tested": len(config_paths),
            "secrets_found": len(self.results),
            "results": self.results,
        }

    def acquire_from_backup(self, url: str) -> Dict:
        self.results = []
        self._seen = set()
        base_url = url.rstrip("/")

        backup_paths = [
            "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
            "/backup.sql.gz", "/backup.bak", "/backup.old",
            "/db_backup", "/db_backup.sql", "/db_backup.zip",
            "/database_backup.sql", "/database_backup.zip",
            "/bak", "/bak/", "/.bak",
            "/old", "/old/", "/.old",
            "/tmp", "/tmp/", "/temp",
            "/archive", "/archives",
            "/dump", "/dump.sql", "/dump.json",
            "/export", "/export.sql",
            "/data.sql", "/data.sql.gz",
            "/users.sql", "/users.csv",
            "/site.tar.gz", "/site.zip", "/site.bak",
            "/www", "/www.zip", "/www.tar.gz",
            "/html.zip", "/html.tar.gz",
            "/public.zip", "/public.tar.gz",
            "/source.zip", "/source.tar.gz",
            "/code.zip", "/code.tar.gz",
            "/web.zip", "/web.tar.gz",
            "/app.zip", "/app.tar.gz",
            "/dist.zip", "/dist.tar.gz",
            "/build.zip", "/build.tar.gz",
            "/release.zip", "/release.tar.gz",
            "/snapshot.zip", "/snapshot.tar.gz",
            "/backup/", "/backups/", "/backups",
        ]

        for path in backup_paths:
            test_url = f"{base_url}{path}"
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False, stream=True)
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    content_length = int(response.headers.get("Content-Length", 0))

                    if content_length > 0 and content_length < 50 * 1024 * 1024:
                        content = response.text[:1024 * 1024]
                        findings = scan_text(content, ALL_PATTERNS)
                        for finding in findings:
                            dedup_key = (test_url, finding["pattern"], finding["match"])
                            if dedup_key not in self._seen:
                                self._seen.add(dedup_key)
                                self.results.append({
                                    "source": "backup_file",
                                    "url": test_url,
                                    "path": path,
                                    "pattern": finding["pattern"],
                                    "severity": finding["severity"],
                                    "description": finding["description"],
                                    "match": finding["match"],
                                    "status_code": response.status_code,
                                    "content_type": content_type,
                                    "size": content_length,
                                })
            except requests.RequestException:
                continue

        return {
            "scan_type": "secret_acquire_backup",
            "target": url,
            "paths_tested": len(backup_paths),
            "secrets_found": len(self.results),
            "results": self.results,
        }
