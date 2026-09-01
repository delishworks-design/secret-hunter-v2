import hashlib
import re
import os
import uuid
from datetime import datetime
from urllib.parse import urlparse


def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_string(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https", "ftp"), result.netloc])
    except Exception:
        return False


def is_valid_github_token(token: str) -> bool:
    if not token:
        return False
    pattern = r"^(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}$"
    return bool(re.match(pattern, token))


def truncate(text: str, max_length: int = 100) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    if not secret:
        return ""
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return "*" * (len(secret) - visible_chars) + secret[-visible_chars:]


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {int(secs)}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m {int(secs)}s"


def get_scan_id() -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    short_uuid = uuid.uuid4().hex[:8]
    return f"scan_{timestamp}_{short_uuid}"


# ANSI color codes
COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "gray": "\033[90m",
}


def colorize(text: str, color: str) -> str:
    code = COLORS.get(color, "")
    if not code:
        return text
    return f"{code}{text}{COLORS['reset']}"


def severity_color(severity: str) -> str:
    severity_map = {
        "CRITICAL": "red",
        "HIGH": "magenta",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "gray",
    }
    return severity_map.get(severity.upper(), "white")
