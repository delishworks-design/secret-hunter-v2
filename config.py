import os
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # General
    AUTH_API_KEY: str = os.getenv("AUTH_API_KEY", "")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    MAX_THREADS: int = int(os.getenv("MAX_THREADS", "10"))
    TIMEOUT: int = int(os.getenv("TIMEOUT", "30"))
    SERVER_HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))

    # Scanner settings
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_DEPTH: int = 10
    RATE_LIMIT: int = 10  # requests per second

    # Proxy
    PROXY_URL: str = os.getenv("PROXY_URL", "")

    # Output
    OUTPUT_DIR: str = os.getenv("OUTPUT_DIR", "./output")

    # Scan extensions
    SCAN_EXTENSIONS: List[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
        ".env", ".config", ".cfg", ".ini", ".yml", ".yaml", ".json", ".xml",
        ".toml", ".properties", ".sh", ".bash", ".zsh", ".sql", ".md", ".txt",
        ".html", ".css", ".scss", ".less", ".c", ".cpp", ".h", ".cs",
        ".rs", ".swift", ".kt", ".scala", ".pl", ".lua", ".r", ".dart",
    ])

    # Exclude directories
    EXCLUDE_DIRS: List[str] = field(default_factory=lambda: [
        ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
        ".idea", ".vscode", "dist", "build", ".next", ".nuxt",
        "vendor", "target", "bin", "obj", ".tox", ".eggs",
    ])

    # Sensitive paths for website scanning
    SENSITIVE_PATHS: List[str] = field(default_factory=lambda: [
        "/.env", "/env", "/config", "/configuration", "/settings",
        "/admin", "/administrator", "/login", "/wp-admin",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/backup", "/backups", "/bak", "/old", "/temp", "/tmp",
        "/debug", "/trace", "/status", "/health", "/info",
        "/api", "/api/v1", "/api/v2", "/graphql",
        "/swagger", "/docs", "/redoc", "/openapi.json",
        "/robots.txt", "/sitemap.xml", "/.well-known/",
        "/wp-config.php.bak", "/config.php.bak", "/web.config",
        "/phpinfo.php", "/test", "/test.php",
        "/.DS_Store", "/Thumbs.db", "/web.config",
        "/server-status", "/server-info",
    ])

    # Common login paths
    LOGIN_PATHS: List[str] = field(default_factory=lambda: [
        "/login", "/signin", "/auth", "/authenticate",
        "/wp-login.php", "/admin/login", "/user/login",
        "/api/login", "/api/auth", "/api/v1/login",
    ])

    # Debug endpoints
    DEBUG_ENDPOINTS: List[str] = field(default_factory=lambda: [
        "/debug", "/trace", "/actuator", "/actuator/env",
        "/actuator/health", "/actuator/info", "/actuator/configprops",
        "/manage", "/manage/env", "/manage/health",
        "/jolokia", "/jmx", "/console",
        "/phpinfo.php", "/info.php", "/test.php",
        "/.env", "/env.php",
    ])

    def get_github_token(self) -> Optional[str]:
        token = self.GITHUB_TOKEN
        return token if token else None


config = Config()
