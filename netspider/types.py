"""Core type definitions for NetSpider-Max v3 engine."""
from __future__ import annotations
from dataclasses import dataclass, field
from netspider._lib.types import FindingType, NetworkError  # canonical source

# Re-export for v3 consumers
__all__ = ["FindingType", "NetworkError", "ScanResult", "Asset", "Credential",
           "NmapContext", "AssetFindings"]


@dataclass
class ScanResult:
    """Result of a single credential test against one asset."""
    success: bool
    finding_type: FindingType = FindingType.WEAK_PASSWORD
    detail: str = ""

    def __bool__(self):
        return self.success


@dataclass
class Asset:
    """A discovered network service on a target host, enriched with Nmap context."""
    ip: str
    port: int
    service: str                      # normalized fingerprint: ssh, mysql, http, ...
    product: str = ""                 # product name from Nmap (e.g. "H3C SecPath F1000")
    version: str = ""                 # version string
    extrainfo: str = ""               # extra info from Nmap
    os_family: str = ""               # e.g. "Windows", "Linux", "embedded"
    os_gen: str = ""                  # e.g. "Windows Server 2019", "Ubuntu 20.04"
    hostname: str = ""                # hostname from Nmap or reverse DNS
    # Risk priority for burst ordering (higher = test first)
    risk_priority: int = 0

    def __post_init__(self):
        if not self.risk_priority:
            self.risk_priority = _default_priority(self.service)

    @property
    def addr(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class Credential:
    """A username/password pair with provenance metadata."""
    username: str
    password: str
    source: str = "custom"           # "top100" | "mfr" | "mutation" | "custom"
    priority: int = 0                 # 0 = highest priority

    def __hash__(self):
        return hash((self.username, self.password))

    def __eq__(self, other):
        if isinstance(other, Credential):
            return self.username == other.username and self.password == other.password
        return False


@dataclass
class NmapContext:
    """Per-host context extracted from Nmap XML for dictionary building."""
    hostname: str = ""
    os_family: str = ""
    os_gen: str = ""
    domain_hint: str = ""             # derived from hostname (e.g. "h3c-sw-01.corp.baidu.com" → "baidu")


@dataclass
class AssetFindings:
    """Aggregated findings for a single IP — the asset risk topology."""
    ip: str
    findings: list[dict] = field(default_factory=list)
    open_services: list[dict] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        has_critical = any(
            f.get('finding_type') in ('weak_password', 'default_password', 'no_auth')
            for f in self.findings
        )
        if has_critical:
            return "high"
        if self.findings:
            return "medium"
        return "low"


def _default_priority(service: str) -> int:
    """Risk-ordered default priority: critical services tested first."""
    ordering = {
        "ssh": 100, "rdp": 100, "smb": 95, "winrm": 95,
        "mysql": 90, "mssql": 90, "oracle": 90, "postgresql": 90,
        "redis": 85, "mongodb": 85, "elasticsearch": 85,
        "telnet": 80, "ftp": 80, "snmp": 75, "ldap": 70,
        "vnc": 60, "rtsp": 50,
        "http": 30, "https": 30,
        "smtp": 20, "imap": 20, "pop3": 20,
    }
    return ordering.get(service, 10)
