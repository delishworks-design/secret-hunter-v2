import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from config import config

app = FastAPI(title="Secret Hunter V2 API", version="2.0.0")
api_key_header = APIKeyHeader(name="X-API-Key")


def verify_api_key(api_key: str = Depends(api_key_header)):
    if not config.AUTH_API_KEY:
        raise HTTPException(status_code=500, detail="API key not configured on server")
    if api_key != config.AUTH_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


class ScanRequest(BaseModel):
    mode: str
    target: str
    severity: str = "LOW"
    threads: int = 10
    timeout: int = 30
    depth: int = 3
    history_depth: int = 100
    extensions: Optional[List[str]] = None
    exclude: Optional[List[str]] = None


class BruteForceRequest(BaseModel):
    type: str
    target: str
    wordlist: str
    threads: int = 10
    timeout: int = 30
    rate_limit: int = 10
    proxy: Optional[str] = None


class StuffRequest(BaseModel):
    type: str
    target: str
    credentials: List[Dict[str, str]]
    threads: int = 10
    timeout: int = 30
    rate_limit: int = 10
    proxy: Optional[str] = None


class BypassRequest(BaseModel):
    type: str
    target: str
    token: Optional[str] = None
    proxy: Optional[str] = None


class AcquireRequest(BaseModel):
    type: str
    target: str
    timeout: int = 30
    proxy: Optional[str] = None


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/api/v1/scan")
def scan(request: ScanRequest, api_key: str = Depends(verify_api_key)):
    from local_scanner import LocalScanner
    from github_scanner import GitHubScanner
    from website_scanner import WebsiteScanner
    from git_scanner import GitScanner
    from multi_scanner import MultiScanner

    try:
        if request.mode == "local":
            scanner = LocalScanner()
            results = scanner.scan_directory(
                request.target,
                extensions=request.extensions,
                exclude=request.exclude,
            )
        elif request.mode == "github":
            scanner = GitHubScanner()
            results = scanner.scan_repo(
                request.target,
                scan_history=True,
                history_depth=request.history_depth,
            )
        elif request.mode == "website":
            scanner = WebsiteScanner(timeout=request.timeout)
            results = scanner.scan_url(request.target, depth=request.depth)
        elif request.mode == "git":
            if request.target.startswith(("http://", "https://", "git@")):
                scanner = GitScanner()
                results = scanner.scan_remote_repo(request.target, depth=request.history_depth)
            else:
                scanner = GitScanner()
                results = scanner.scan_local_repo(request.target, depth=request.history_depth)
        elif request.mode == "multi":
            scanner = MultiScanner(threads=request.threads)
            targets = [{"type": "local", "target": request.target}]
            results = scanner.scan_multiple(targets)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid scan mode: {request.mode}")

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        min_severity = severity_order.get(request.severity.upper(), 0)
        findings = results.get("findings", [])
        filtered_findings = [
            f for f in findings
            if severity_order.get(f.get("severity", "INFO").upper(), 0) >= min_severity
        ]
        results["findings"] = filtered_findings

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/bruteforce")
def bruteforce(request: BruteForceRequest, api_key: str = Depends(verify_api_key)):
    from bruteforcer import BruteForcer

    try:
        wordlist_path = request.wordlist
        if not os.path.isfile(wordlist_path):
            raise HTTPException(status_code=400, detail=f"Wordlist not found: {wordlist_path}")

        with open(wordlist_path, "r") as f:
            wordlist_items = [line.strip() for line in f if line.strip()]

        scanner = BruteForcer(
            threads=request.threads,
            timeout=request.timeout,
            proxy=request.proxy,
            rate_limit=request.rate_limit,
        )

        if request.type == "login":
            results = scanner.brute_force_login(request.target, wordlist_items, wordlist_items[:50])
        elif request.type == "directories":
            results = scanner.brute_force_directories(request.target, wordlist_items)
        elif request.type == "api_key":
            results = scanner.brute_force_api_key(request.target, wordlist_items)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid brute force type: {request.type}")

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/stuff")
def stuff(request: StuffRequest, api_key: str = Depends(verify_api_key)):
    from credential_stuffer import CredentialStuffer

    try:
        scanner = CredentialStuffer(
            threads=request.threads,
            timeout=request.timeout,
            proxy=request.proxy,
            rate_limit=request.rate_limit,
        )

        if request.type == "login":
            results = scanner.credential_stuff_login(request.target, request.credentials)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid stuffing type: {request.type}")

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/bypass")
def bypass(request: BypassRequest, api_key: str = Depends(verify_api_key)):
    from auth_bypass import AuthBypass

    try:
        scanner = AuthBypass(proxy=request.proxy)

        if request.type == "header":
            results = scanner.bypass_header_manipulation(request.target)
        elif request.type == "jwt":
            if not request.token:
                raise HTTPException(status_code=400, detail="JWT token is required for jwt bypass")
            results = scanner.bypass_jwt_none(request.target, request.token)
        elif request.type == "path":
            results = scanner.bypass_path_traversal(request.target)
        elif request.type == "method":
            results = scanner.bypass_method_override(request.target)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid bypass type: {request.type}")

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/acquire")
def acquire(request: AcquireRequest, api_key: str = Depends(verify_api_key)):
    from secret_acquirer import SecretAcquirer

    try:
        scanner = SecretAcquirer(timeout=request.timeout, proxy=request.proxy)

        if request.type == "debug":
            results = scanner.acquire_from_debug(request.target)
        elif request.type == "env":
            results = scanner.acquire_from_env(request.target)
        elif request.type == "config":
            results = scanner.acquire_from_config(request.target)
        elif request.type == "backup":
            results = scanner.acquire_from_backup(request.target)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid acquire type: {request.type}")

        return results

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.SERVER_HOST, port=config.SERVER_PORT)
