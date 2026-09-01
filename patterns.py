import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable


@dataclass
class Pattern:
    name: str
    regex: str
    severity: str = "HIGH"
    description: str = ""
    group: str = "generic"
    flags: int = re.IGNORECASE

    def __post_init__(self):
        self._compiled = re.compile(self.regex, self.flags)

    def match(self, text: str) -> List[Dict]:
        matches = []
        for m in self._compiled.finditer(text):
            matches.append({
                "pattern": self.name,
                "severity": self.severity,
                "description": self.description,
                "group": self.group,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "groups": m.groups(),
            })
        return matches


# ─── Generic Secret Patterns ────────────────────────────────────────────────────

PATTERNS_GENERIC = [
    Pattern(
        name="Generic API Key",
        regex=r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        severity="HIGH",
        description="Potential generic API key detected",
        group="generic",
    ),
    Pattern(
        name="Generic Secret",
        regex=r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
        severity="HIGH",
        description="Potential generic secret or password detected",
        group="generic",
    ),
    Pattern(
        name="Generic Token",
        regex=r"(?i)(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?",
        severity="HIGH",
        description="Potential authentication token detected",
        group="generic",
    ),
]

# ─── Cloud Provider Patterns ────────────────────────────────────────────────────

PATTERNS_CLOUD = [
    Pattern(
        name="AWS Access Key",
        regex=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="CRITICAL",
        description="AWS Access Key ID detected",
        group="cloud",
    ),
    Pattern(
        name="AWS Secret Key",
        regex=r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        severity="CRITICAL",
        description="AWS Secret Access Key detected",
        group="cloud",
    ),
    Pattern(
        name="AWS MWS Key",
        regex=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="CRITICAL",
        description="Amazon MWS Auth Token detected",
        group="cloud",
    ),
    Pattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="CRITICAL",
        description="Google API Key detected",
        group="cloud",
    ),
    Pattern(
        name="Google OAuth ID",
        regex=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity="HIGH",
        description="Google OAuth Client ID detected",
        group="cloud",
    ),
    Pattern(
        name="Google Service Account",
        regex=r'"type"\s*:\s*"service_account"',
        severity="CRITICAL",
        description="Google Service Account key detected",
        group="cloud",
    ),
    Pattern(
        name="Azure Storage Account Key",
        regex=r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        severity="CRITICAL",
        description="Azure Storage Account Key detected",
        group="cloud",
    ),
    Pattern(
        name="Azure AD Client Secret",
        regex=r"(?i)client[_\-]?secret\s*[:=]\s*['\"]?([a-zA-Z0-9_\-~\.]{34,40})['\"]?",
        severity="HIGH",
        description="Azure AD Client Secret detected",
        group="cloud",
    ),
    Pattern(
        name="GCP Service Account Key",
        regex=r'"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----\\n[a-zA-Z0-9+/=\s]+\\n-----END (?:RSA )?PRIVATE KEY-----"',
        severity="CRITICAL",
        description="GCP Service Account private key detected",
        group="cloud",
    ),
]

# ─── Platform Patterns ─────────────────────────────────────────────────────────

PATTERNS_PLATFORM = [
    Pattern(
        name="GitHub Token",
        regex=r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}",
        severity="CRITICAL",
        description="GitHub personal access token detected",
        group="platform",
    ),
    Pattern(
        name="GitHub OAuth",
        regex=r"gho_[a-zA-Z0-9]{36,}",
        severity="CRITICAL",
        description="GitHub OAuth access token detected",
        group="platform",
    ),
    Pattern(
        name="GitLab Token",
        regex=r"glpat-[a-zA-Z0-9\-_]{20,}",
        severity="CRITICAL",
        description="GitLab personal access token detected",
        group="platform",
    ),
    Pattern(
        name="Slack Token",
        regex=r"xox[baprs]-[a-zA-Z0-9\-]{10,}",
        severity="CRITICAL",
        description="Slack token detected",
        group="platform",
    ),
    Pattern(
        name="Slack Webhook",
        regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}",
        severity="CRITICAL",
        description="Slack webhook URL detected",
        group="platform",
    ),
    Pattern(
        name="Stripe API Key",
        regex=r"(?:r|s)k_(?:live|test)_[a-zA-Z0-9]{24,}",
        severity="CRITICAL",
        description="Stripe API key detected",
        group="platform",
    ),
    Pattern(
        name="Stripe Restricted Key",
        regex=r"rk_(?:live|test)_[a-zA-Z0-9]{24,}",
        severity="CRITICAL",
        description="Stripe restricted API key detected",
        group="platform",
    ),
    Pattern(
        name="Twilio API Key",
        regex=r"SK[a-f0-9]{32}",
        severity="CRITICAL",
        description="Twilio API key detected",
        group="platform",
    ),
    Pattern(
        name="SendGrid API Key",
        regex=r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}",
        severity="CRITICAL",
        description="SendGrid API key detected",
        group="platform",
    ),
    Pattern(
        name="Heroku API Key",
        regex=r"(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
        severity="CRITICAL",
        description="Heroku API key detected",
        group="platform",
    ),
    Pattern(
        name="PyPI Token",
        regex=r"pypi-[a-zA-Z0-9\-_]{50,}",
        severity="CRITICAL",
        description="PyPI API token detected",
        group="platform",
    ),
    Pattern(
        name="npm Token",
        regex=r"npm_[a-zA-Z0-9]{36}",
        severity="CRITICAL",
        description="npm access token detected",
        group="platform",
    ),
    Pattern(
        name="Atlassian Token",
        regex=r"(?i)atlassian[_\-]?api[_\-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9]{24})['\"]?",
        severity="CRITICAL",
        description="Atlassian API token detected",
        group="platform",
    ),
]

# ─── Cryptographic Patterns ─────────────────────────────────────────────────────

PATTERNS_CRYPTO = [
    Pattern(
        name="Private Key",
        regex=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        severity="CRITICAL",
        description="Private key detected",
        group="crypto",
    ),
    Pattern(
        name="SSH Private Key",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="CRITICAL",
        description="SSH private key detected",
        group="crypto",
    ),
    Pattern(
        name="PGP Private Key",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="CRITICAL",
        description="PGP private key block detected",
        group="crypto",
    ),
    Pattern(
        name="JWT Token",
        regex=r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+/=]+",
        severity="HIGH",
        description="JSON Web Token detected",
        group="crypto",
    ),
]

# ─── Connection String Patterns ─────────────────────────────────────────────────

PATTERNS_CONNECTION = [
    Pattern(
        name="Database URL",
        regex=r"(?:mysql|postgresql|postgres|mongodb|redis|amqp|mssql|oracle|sqlite):\/\/[^\s'\"]+",
        severity="CRITICAL",
        description="Database connection string detected",
        group="connection",
    ),
    Pattern(
        name="MongoDB URL",
        regex=r"mongodb(\+srv)?:\/\/[^\s'\"]+",
        severity="CRITICAL",
        description="MongoDB connection string detected",
        group="connection",
    ),
    Pattern(
        name="Redis URL",
        regex=r"redis:\/\/[^\s'\"]+",
        severity="CRITICAL",
        description="Redis connection string detected",
        group="connection",
    ),
    Pattern(
        name="MySQL Connection",
        regex=r"(?i)mysql:\/\/[^\s'\"]+",
        severity="CRITICAL",
        description="MySQL connection string detected",
        group="connection",
    ),
    Pattern(
        name="PostgreSQL Connection",
        regex=r"(?i)postgres(?:ql)?:\/\/[^\s'\"]+",
        severity="CRITICAL",
        description="PostgreSQL connection string detected",
        group="connection",
    ),
    Pattern(
        name="LDAP Bind DN",
        regex=r"(?i)ldap[s]?:\/\/[^:]+:[^@]+@[^\s'\"]+",
        severity="HIGH",
        description="LDAP connection with credentials detected",
        group="connection",
    ),
]

# ─── High Entropy Patterns ──────────────────────────────────────────────────────

PATTERNS_ENTROPY = [
    Pattern(
        name="High Entropy String",
        regex=r"(?<![a-zA-Z0-9])[a-zA-Z0-9+/]{40,}={0,2}(?![a-zA-Z0-9+/])",
        severity="MEDIUM",
        description="High entropy string detected (possible encoded secret)",
        group="entropy",
    ),
    Pattern(
        name="Hex Token",
        regex=r"(?<![a-f0-9])[a-f0-9]{32,}(?![a-f0-9])",
        severity="MEDIUM",
        description="Long hex string detected (possible token)",
        group="entropy",
    ),
]

# ─── Env/Config Patterns ────────────────────────────────────────────────────────

PATTERNS_ENV = [
    Pattern(
        name="Env Assignment",
        regex=r"(?i)^(?:export\s+)?([A-Z_]{3,})\s*=\s*(.+)$",
        severity="HIGH",
        description="Environment variable assignment detected",
        group="env",
    ),
    Pattern(
        name="Password in URL",
        regex=r"(?i)(?:https?|ftp):\/\/[^:]+:([^\s@]+)@[^\s]+",
        severity="CRITICAL",
        description="Password embedded in URL detected",
        group="env",
    ),
    Pattern(
        name="Hardcoded Password",
        regex=r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]",
        severity="HIGH",
        description="Hardcoded password detected",
        group="env",
    ),
    Pattern(
        name="Hardcoded IP with Credentials",
        regex=r"(?:\d{1,3}\.){3}\d{1,3}:[^\s]+:[^\s]+",
        severity="CRITICAL",
        description="IP address with credentials detected",
        group="env",
    ),
]

# ─── All patterns ───────────────────────────────────────────────────────────────

ALL_PATTERNS: List[Pattern] = (
    PATTERNS_GENERIC
    + PATTERNS_CLOUD
    + PATTERNS_PLATFORM
    + PATTERNS_CRYPTO
    + PATTERNS_CONNECTION
    + PATTERNS_ENTROPY
    + PATTERNS_ENV
)


def scan_text(text: str, patterns: Optional[List[Pattern]] = None) -> List[Dict]:
    if patterns is None:
        patterns = ALL_PATTERNS
    all_findings = []
    seen = set()
    for pattern in patterns:
        for match in pattern.match(text):
            key = (match["pattern"], match["match"])
            if key not in seen:
                seen.add(key)
                all_findings.append(match)
    return all_findings


def get_patterns_by_group(group: str) -> List[Pattern]:
    return [p for p in ALL_PATTERNS if p.group == group]


def get_pattern_by_name(name: str) -> Optional[Pattern]:
    for p in ALL_PATTERNS:
        if p.name == name:
            return p
    return None
