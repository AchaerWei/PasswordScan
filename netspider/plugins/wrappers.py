"""Plugin wrappers — adapt v2 protocol testers to v3 BasePlugin interface.

Each wrapper delegates to the existing test_xxx(ip, port, user, pwd) → bool
functions.  The v2 function signatures are preserved, ensuring backward
compatibility with the verification gate (verify_weakpass.py / mock servers).
"""
from __future__ import annotations
from netspider.plugins.base import BasePlugin, PLUGIN_REGISTRY
from netspider.types import ScanResult, FindingType

# Import all v2 testers
from netspider.protocols.http import test_http, test_elasticsearch
from netspider.protocols.network import test_ssh, test_telnet, test_ftp, HAS_PARAMIKO
from netspider.protocols.mail import test_smtp, test_imap, test_pop3
from netspider.protocols.database import (
    test_redis, test_mysql, test_postgresql, test_mssql, test_oracle, test_mongodb,
)
from netspider.protocols.snmp import test_snmp
from netspider.protocols.smb import test_smb
from netspider.protocols.ldap import test_ldap
from netspider.protocols.rdp import test_rdp
from netspider.protocols.winrm import test_winrm
from netspider.protocols.rtsp import test_rtsp
from netspider.protocols.vnc import test_vnc


# ===============================================================
# Synchronous (threaded) plugins for native protocols
# ===============================================================

class _SyncPlugin(BasePlugin):
    """Base for plugins that wrap a sync tester function (ip, port, user, pwd) → bool."""
    is_async = False

    def __init__(self, fn, name: str, service_type: str):
        self._fn = fn
        self.name = name
        self.service_type = service_type

    def test(self, asset, cred) -> ScanResult:
        from netspider._lib.types import _get_finding_type as _v2_get
        try:
            ok = self._fn(asset.ip, asset.port, cred.username, cred.password)
            if ok:
                ft = _v2_get()
                return ScanResult(True, FindingType(ft.value) if hasattr(ft, 'value') else FindingType.WEAK_PASSWORD)
            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: call underlying tester with empty credentials.
        Returns NO_AUTH if the protocol tester reports no auth required."""
        from netspider._lib.types import _get_finding_type as _v2_get
        try:
            ok = self._fn(asset.ip, asset.port, "", "")
            if ok:
                ft = _v2_get()
                if ft.value == FindingType.NO_AUTH.value:
                    return ScanResult(True, FindingType.NO_AUTH)
            return ScanResult(False)
        except Exception:
            return ScanResult(False)


class _HttpPlugin(BasePlugin):
    """Async-capable HTTP plugin — wraps test_http but also supports test_async."""
    is_async = True

    def __init__(self):
        self.name = "http"
        self.service_type = "http"
        self._has_httpx = False
        try:
            import httpx
            self._has_httpx = True
        except ImportError:
            pass
        self._client = None

    def test(self, asset, cred) -> ScanResult:
        """Sync fallback: delegate to v2 test_http."""
        from netspider._lib.types import _get_finding_type as _v2_get
        try:
            ok = test_http(asset.ip, asset.port, cred.username, cred.password)
            if ok:
                ft = _v2_get()
                return ScanResult(True, FindingType(ft.value) if hasattr(ft, 'value') else FindingType.WEAK_PASSWORD)
            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    async def test_async(self, client, asset, cred) -> ScanResult:
        """Async path using httpx for Basic Auth."""
        import base64
        scheme = 'https' if asset.service == 'https' else 'http'
        url = f"{scheme}://{asset.ip}:{asset.port}/"
        try:
            auth = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
            headers = {"Authorization": f"Basic {auth}"}
            resp = await client.get(url, headers=headers, follow_redirects=False)
            if resp.status_code in (200, 301, 302, 303, 307, 308):
                # Check: did we actually authenticate, or is it just a redirect?
                if resp.status_code == 200:
                    return ScanResult(True, FindingType.WEAK_PASSWORD)
                # Redirect could mean success or "redirect to login" — be conservative
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('location', '')
                    if 'login' in location.lower() or 'auth' in location.lower():
                        return ScanResult(False)
                return ScanResult(True, FindingType.WEAK_PASSWORD)
            elif resp.status_code == 401:
                return ScanResult(False)
            elif resp.status_code == 403:
                return ScanResult(False)
            else:
                return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: HTTP GET without credentials."""
        import urllib.request, ssl
        from netspider.security import create_ssl_context
        scheme = 'https' if asset.service == 'https' else 'http'
        url = f"{scheme}://{asset.ip}:{asset.port}/"
        try:
            ssl_ctx = create_ssl_context()
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl_ctx),
            )
            req = urllib.request.Request(url)
            with opener.open(req, timeout=5) as resp:
                if resp.status == 200:
                    return ScanResult(True, FindingType.NO_AUTH)
        except Exception:
            pass
        return ScanResult(False)

    async def test_noauth_async(self, client, asset) -> ScanResult:
        """Async Phase 0 probe: HTTP GET without credentials."""
        scheme = 'https' if asset.service == 'https' else 'http'
        url = f"{scheme}://{asset.ip}:{asset.port}/"
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code == 200:
                return ScanResult(True, FindingType.NO_AUTH)
        except Exception:
            pass
        return ScanResult(False)


# ===============================================================
# Register all plugins
# ===============================================================

_REGISTERED = False


def _register_all():
    """Register all v2→v3 plugin wrappers.  Idempotent."""
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True

    # HTTP — async plugin
    PLUGIN_REGISTRY.register(_HttpPlugin())
    # 'https' is the same plugin (already registered as 'http')
    # The matcher routes both http and https to the same registry lookup

    # Database protocols
    PLUGIN_REGISTRY.register(_SyncPlugin(test_redis, "redis", "redis"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_mysql, "mysql", "mysql"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_postgresql, "postgresql", "postgresql"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_mssql, "mssql", "mssql"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_oracle, "oracle", "oracle"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_mongodb, "mongodb", "mongodb"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_elasticsearch, "elasticsearch", "elasticsearch"))

    # Network protocols
    PLUGIN_REGISTRY.register(_SyncPlugin(test_ssh, "ssh", "ssh"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_telnet, "telnet", "telnet"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_ftp, "ftp", "ftp"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_smb, "smb", "smb"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_ldap, "ldap", "ldap"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_rdp, "rdp", "rdp"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_vnc, "vnc", "vnc"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_winrm, "winrm", "winrm"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_rtsp, "rtsp", "rtsp"))

    # SNMP — community string based (uses password field as community)
    PLUGIN_REGISTRY.register(_SyncPlugin(test_snmp, "snmp", "snmp"))

    # Mail protocols
    PLUGIN_REGISTRY.register(_SyncPlugin(test_smtp, "smtp", "smtp"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_imap, "imap", "imap"))
    PLUGIN_REGISTRY.register(_SyncPlugin(test_pop3, "pop3", "pop3"))

    # ---- Vendor-specific web plugins ----
    from netspider.plugins.web.h3c import H3cWebPlugin, HuaweiWebPlugin, CiscoWebPlugin
    PLUGIN_REGISTRY.register(H3cWebPlugin())
    PLUGIN_REGISTRY.register(HuaweiWebPlugin())
    PLUGIN_REGISTRY.register(CiscoWebPlugin())

    # ---- NAS web plugins ----
    from netspider.plugins.web.nas import SynologyWebPlugin, QnapWebPlugin
    PLUGIN_REGISTRY.register(SynologyWebPlugin())
    PLUGIN_REGISTRY.register(QnapWebPlugin())

    # ---- IPMI plugin (moved from self-registration) ----
    from netspider.plugins.ipmi import IpmiPlugin
    PLUGIN_REGISTRY.register(IpmiPlugin())


# Auto-register on import
_register_all()


def _populate_supported_fingerprints():
    """Sync SUPPORTED_FINGERPRINTS with the plugin registry."""
    from netspider.discovery.matcher import SUPPORTED_FINGERPRINTS
    SUPPORTED_FINGERPRINTS.update(PLUGIN_REGISTRY.supported_services)
    SUPPORTED_FINGERPRINTS.add("https")  # alias


_populate_supported_fingerprints()
