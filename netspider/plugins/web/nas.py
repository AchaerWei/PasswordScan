"""NAS web management credential testers — Synology DSM and QNAP QTS."""
from __future__ import annotations
from netspider.plugins.base import BasePlugin
from netspider.types import ScanResult, FindingType
from netspider.security import create_ssl_context

SYNOLOGY_SIGNATURES = [
    b"Synology", b"DSM", b"DiskStation", b"webman",
    b"synology_redirect", b"synology_token",
]

QNAP_SIGNATURES = [
    b"QNAP", b"QTS", b"Turbo NAS", b"qnap_redirect",
    b"QNAPVersion", b"nasAdmin",
]

SYNOLOGY_PATHS = ["/webman/index.cgi", "/webman/login.cgi"]
QNAP_PATHS = ["/cgi-bin/", "/cgi-bin/login.cgi", "/cgi-bin/index.cgi"]


class SynologyWebPlugin(BasePlugin):
    """Synology DSM web management credential tester."""

    name = "synology_web"
    service_type = "synology_web"
    is_async = True

    async def test_async(self, client, asset, cred) -> ScanResult:
        scheme = "https" if asset.service == "https" else "http"
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            resp = await client.get(base + "/", follow_redirects=True)
            content = resp.content
            is_synology = any(sig in content for sig in SYNOLOGY_SIGNATURES)
            if not is_synology and asset.product:
                is_synology = "synology" in asset.product.lower()
            if not is_synology:
                return ScanResult(False)

            for path in SYNOLOGY_PATHS:
                try:
                    data = {
                        "username": cred.username,
                        "password": cred.password,
                        "stay_login": "1",
                    }
                    auth_resp = await client.post(
                        base + path, data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=False,
                    )
                    if auth_resp.status_code in (301, 302, 303):
                        loc = auth_resp.headers.get("location", "").lower()
                        if "login" not in loc and "error" not in loc:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                    if auth_resp.status_code == 200:
                        body = auth_resp.text.lower()
                        if "synology" in body and "desktop" in body:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: check if Synology DSM is accessible without auth."""
        import urllib.request, ssl
        scheme = "https" if asset.service == "https" else "http"
        url = f"{scheme}://{asset.ip}:{asset.port}/"
        try:
            ssl_ctx = create_ssl_context()
            req = urllib.request.Request(url)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl_ctx),
            )
            with opener.open(req, timeout=5) as resp:
                if resp.status == 200:
                    if any(sig in resp.read() for sig in SYNOLOGY_SIGNATURES):
                        return ScanResult(True, FindingType.NO_AUTH)
        except Exception:
            pass
        return ScanResult(False)

    def test(self, asset, cred) -> ScanResult:
        import urllib.request, urllib.error, ssl, urllib.parse

        ssl_ctx = create_ssl_context()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl_ctx),
        )
        scheme = "https" if asset.service == "https" else "http"
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            req = urllib.request.Request(base + "/")
            with opener.open(req, timeout=5) as resp:
                content = resp.read()
            is_synology = any(sig in content for sig in SYNOLOGY_SIGNATURES)
            if not is_synology and asset.product:
                is_synology = "synology" in asset.product.lower()
            if not is_synology:
                return ScanResult(False)

            for path in SYNOLOGY_PATHS:
                try:
                    data = urllib.parse.urlencode({
                        "username": cred.username,
                        "password": cred.password,
                        "stay_login": "1",
                    }).encode()
                    req = urllib.request.Request(base + path, data=data)
                    req.method = "POST"
                    with opener.open(req, timeout=5) as auth_resp:
                        if auth_resp.status in (301, 302, 303):
                            loc = auth_resp.headers.get("location", "").lower()
                            if "login" not in loc and "error" not in loc:
                                return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                        if auth_resp.status == 200:
                            body = auth_resp.read().decode("utf-8", errors="ignore").lower()
                            if "synology" in body and "desktop" in body:
                                return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)


class QnapWebPlugin(BasePlugin):
    """QNAP QTS web management credential tester."""

    name = "qnap_web"
    service_type = "qnap_web"
    is_async = True

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: check if QNAP web management is accessible without auth."""
        import urllib.request, ssl
        scheme = "https" if asset.service == "https" else "http"
        url = f"{scheme}://{asset.ip}:{asset.port}/"
        try:
            ssl_ctx = create_ssl_context()
            req = urllib.request.Request(url)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl_ctx),
            )
            with opener.open(req, timeout=5) as resp:
                if resp.status == 200:
                    if any(sig in resp.read() for sig in QNAP_SIGNATURES):
                        return ScanResult(True, FindingType.NO_AUTH)
        except Exception:
            pass
        return ScanResult(False)

    async def test_async(self, client, asset, cred) -> ScanResult:
        scheme = "https" if asset.service == "https" else "http"
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            resp = await client.get(base + "/", follow_redirects=True)
            content = resp.content
            is_qnap = any(sig in content for sig in QNAP_SIGNATURES)
            if not is_qnap and asset.product:
                is_qnap = "qnap" in asset.product.lower()
            if not is_qnap:
                return ScanResult(False)

            for path in QNAP_PATHS:
                try:
                    data = {
                        "username": cred.username,
                        "password": cred.password,
                    }
                    auth_resp = await client.post(
                        base + path, data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=False,
                    )
                    if auth_resp.status_code in (301, 302, 303):
                        loc = auth_resp.headers.get("location", "").lower()
                        if "login" not in loc and "error" not in loc:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                    if auth_resp.status_code == 200:
                        body = auth_resp.text.lower()
                        if "qnap" in body and "desktop" in body:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test(self, asset, cred) -> ScanResult:
        import urllib.request, urllib.error, ssl, urllib.parse

        ssl_ctx = create_ssl_context()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl_ctx),
        )
        scheme = "https" if asset.service == "https" else "http"
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            req = urllib.request.Request(base + "/")
            with opener.open(req, timeout=5) as resp:
                content = resp.read()
            is_qnap = any(sig in content for sig in QNAP_SIGNATURES)
            if not is_qnap and asset.product:
                is_qnap = "qnap" in asset.product.lower()
            if not is_qnap:
                return ScanResult(False)

            for path in QNAP_PATHS:
                try:
                    data = urllib.parse.urlencode({
                        "username": cred.username,
                        "password": cred.password,
                    }).encode()
                    req = urllib.request.Request(base + path, data=data)
                    req.method = "POST"
                    with opener.open(req, timeout=5) as auth_resp:
                        if auth_resp.status in (301, 302, 303):
                            loc = auth_resp.headers.get("location", "").lower()
                            if "login" not in loc and "error" not in loc:
                                return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                        if auth_resp.status == 200:
                            body = auth_resp.read().decode("utf-8", errors="ignore").lower()
                            if "qnap" in body and "desktop" in body:
                                return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)
