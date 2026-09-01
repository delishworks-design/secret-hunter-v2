import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from config import config


class BruteForcer:
    def __init__(self, threads: int = None, timeout: int = None, proxy: str = None, rate_limit: int = None):
        self.threads = threads or config.MAX_THREADS
        self.timeout = timeout or config.TIMEOUT
        self.proxy = proxy or config.PROXY_URL
        self.rate_limit = rate_limit or config.RATE_LIMIT
        self.results = []
        self._request_times = []
        self._lock = __import__("threading").Lock()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

    def brute_force_login(self, url: str, username_list: List[str], password_list: List[str]) -> Dict:
        self.results = []
        total = len(username_list) * len(password_list)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for username in username_list:
                for password in password_list:
                    future = executor.submit(self._test_login, url, username, password)
                    futures[future] = (username, password)

            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception:
                    continue

        return {
            "scan_type": "bruteforce_login",
            "target": url,
            "total_attempts": total,
            "successful": len(self.results),
            "results": self.results,
        }

    def _test_login(self, url: str, username: str, password: str) -> Optional[Dict]:
        self._rate_limit_wait()
        try:
            data = {"username": username, "password": password, "user": username, "pass": password}
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

            is_success = (
                response.status_code in (200, 302)
                and "invalid" not in response.text.lower()
                and "error" not in response.text.lower()
                and "failed" not in response.text.lower()
            )

            if is_success and response.status_code == 200:
                if "login" in response.url.lower() or "signin" in response.url.lower():
                    is_success = False

            if is_success:
                return {
                    "type": "login_success",
                    "url": url,
                    "username": username,
                    "password": password,
                    "status_code": response.status_code,
                    "response_size": len(response.text),
                }
            return None
        except requests.RequestException:
            return None

    def brute_force_directories(self, url: str, directory_list: List[str]) -> Dict:
        self.results = []
        total = len(directory_list)
        completed = 0
        base_url = url.rstrip("/")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for directory in directory_list:
                future = executor.submit(self._test_directory, base_url, directory)
                futures[future] = directory

            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception:
                    continue

        return {
            "scan_type": "bruteforce_directories",
            "target": url,
            "total_tested": total,
            "found": len(self.results),
            "results": self.results,
        }

    def _test_directory(self, base_url: str, directory: str) -> Optional[Dict]:
        self._rate_limit_wait()
        directory = directory.strip("/")
        test_url = f"{base_url}/{directory}"
        try:
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

            if response.status_code in (200, 301, 302, 403):
                return {
                    "type": "directory_found",
                    "url": test_url,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "response_size": len(response.content),
                    "directory": directory,
                }
            return None
        except requests.RequestException:
            return None

    def brute_force_api_key(self, url: str, key_list: List[str]) -> Dict:
        self.results = []
        total = len(key_list)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for key in key_list:
                future = executor.submit(self._test_api_key, url, key)
                futures[future] = key

            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception:
                    continue

        return {
            "scan_type": "bruteforce_api_key",
            "target": url,
            "total_tested": total,
            "found": len(self.results),
            "results": self.results,
        }

    def _test_api_key(self, url: str, key: str) -> Optional[Dict]:
        self._rate_limit_wait()
        try:
            headers = {"Authorization": f"Bearer {key}", "X-API-Key": key}
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
            )

            is_valid = response.status_code not in (401, 403, 429)
            if is_valid:
                return {
                    "type": "api_key_valid",
                    "url": url,
                    "key": key,
                    "status_code": response.status_code,
                    "response_size": len(response.text),
                }
            return None
        except requests.RequestException:
            return None

    def _rate_limit_wait(self):
        with self._lock:
            now = time.time()
            self._request_times = [t for t in self._request_times if now - t < 1.0]
            if len(self._request_times) >= self.rate_limit:
                sleep_time = 1.0 - (now - self._request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            self._request_times.append(time.time())
