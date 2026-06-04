"""H3C device web login plugin — detects and tests H3C management interfaces.

H3C devices (switches, routers, firewalls, AC, CAS, iMC) use various web
management patterns. This plugin:
  1. Probes common H3C management URLs
  2. Tests the H3C-specific defaults from the MFR database
  3. Handles H3C-specific login response patterns (302 redirects, JS redirects)

Common H3C web management URL patterns:
  - / (root — redirects to login)
  - /login.cgi, /login.html
  - /userLogin.asp
  - /imc (iMC platform)
  - /cas (CAS virtualization)
"""
from __future__ import annotations
from netspider.plugins.base import BasePlugin
from netspider.types import ScanResult, FindingType
from netspider.security import create_ssl_context

# H3C-specific login URLs to probe
H3C_PATHS = [
    "/", "/login.cgi", "/login.html", "/userLogin.asp",
    "/wnm/login", "/imc", "/cas", "/cloudos",
]

# H3C-specific response markers (content signatures)
H3C_SIGNATURES = [
    b"H3C", b"h3c", b"SecPath", b"Comware",
    b"H3C Technologies", b"iMC", b"CloudOS",
]


class H3cWebPlugin(BasePlugin):
    """H3C device web management credential tester."""

    name = "h3c_web"
    service_type = "h3c_web"
    is_async = True

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: check if H3C web management is accessible without auth."""
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
                    content = resp.read()
                    if any(sig in content for sig in H3C_SIGNATURES):
                        return ScanResult(True, FindingType.NO_AUTH)
        except Exception:
            pass
        return ScanResult(False)

    async def test_async(self, client, asset, cred) -> ScanResult:
        scheme = "https" if asset.service == "https" else "http"
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            # First, check if this is recognizably an H3C device
            resp = await client.get(base + "/", follow_redirects=True)
            content = resp.content
            is_h3c = any(sig in content for sig in H3C_SIGNATURES)

            if not is_h3c and asset.product:
                is_h3c = "h3c" in asset.product.lower()

            if not is_h3c:
                return ScanResult(False)

            # Try each common H3C login path
            for path in H3C_PATHS:
                if path == "/":
                    continue  # already probed

                try:
                    login_resp = await client.get(base + path, follow_redirects=False)
                except Exception:
                    continue

                if login_resp.status_code in (200, 401):
                    # Try to login
                    try:
                        # H3C often uses form-encoded POST with username/password
                        data = {"username": cred.username, "password": cred.password}
                        auth_resp = await client.post(
                            base + path, data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            follow_redirects=False,
                        )
                        # Success indicators:
                        # - 302 redirect to a non-login page
                        # - 200 with no login form
                        if auth_resp.status_code in (301, 302, 303):
                            loc = auth_resp.headers.get("location", "").lower()
                            if "login" not in loc and "error" not in loc:
                                return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                    except Exception:
                        pass

            return ScanResult(False)

        except Exception:
            return ScanResult(False)

    def test(self, asset, cred) -> ScanResult:
        import urllib.request, urllib.error, ssl, base64

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
            is_h3c = any(sig in content for sig in H3C_SIGNATURES)
            if not is_h3c and asset.product:
                is_h3c = "h3c" in asset.product.lower()
            if not is_h3c:
                return ScanResult(False)

            # Try form POST with credentials
            data = f"username={urllib.parse.quote(cred.username)}&password={urllib.parse.quote(cred.password)}"
            for path in ["/login.cgi", "/userLogin.asp"]:
                try:
                    req = urllib.request.Request(
                        base + path, data=data.encode(),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    with opener.open(req, timeout=5) as auth_resp:
                        if auth_resp.status in (301, 302, 303):
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                        body = auth_resp.read()
                        if b"login" not in body.lower() and len(body) > 100:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except urllib.error.HTTPError:
                    continue
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)


class HuaweiWebPlugin(BasePlugin):
    """Huawei device web management — detects USG, AC, AP interfaces."""

    name = "huawei_web"
    service_type = "huawei_web"
    is_async = True

    HUAWEI_SIGS = [b"Huawei", b"USG", b"AR", b"V200R", b"VRP"]

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: check if Huawei web management is accessible without auth."""
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
                    if any(sig in resp.read() for sig in self.HUAWEI_SIGS):
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
            is_huawei = any(sig in content for sig in self.HUAWEI_SIGS)
            if not is_huawei and asset.product:
                is_huawei = "huawei" in asset.product.lower() or "usg" in asset.product.lower()
            if not is_huawei:
                return ScanResult(False)

            for path in ["/login.cgi", "/login.html", "/"]:
                try:
                    data = {"username": cred.username, "password": cred.password}
                    auth_resp = await client.post(
                        base + path, data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=False,
                    )
                    if auth_resp.status_code in (301, 302, 303):
                        loc = auth_resp.headers.get("location", "").lower()
                        if "login" not in loc:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test(self, asset, cred) -> ScanResult:
        import urllib.request, urllib.parse, ssl
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
            is_huawei = any(sig in content for sig in self.HUAWEI_SIGS)
            if not is_huawei:
                return ScanResult(False)

            data = f"username={urllib.parse.quote(cred.username)}&password={urllib.parse.quote(cred.password)}"
            req = urllib.request.Request(
                base + "/login.cgi", data=data.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                with opener.open(req, timeout=5) as r:
                    if r.status in (301, 302, 303):
                        return ScanResult(True, FindingType.DEFAULT_PASSWORD)
            except urllib.error.HTTPError:
                pass
            return ScanResult(False)
        except Exception:
            return ScanResult(False)


class CiscoWebPlugin(BasePlugin):
    """Cisco device web management — IOS, ASA, Catalyst interfaces."""

    name = "cisco_web"
    service_type = "cisco_web"
    is_async = True

    CISCO_SIGS = [b"Cisco", b"cisco", b"IOS", b"ASA", b"Catalyst", b"Nexus"]

    def test_noauth(self, asset) -> ScanResult:
        """Phase 0 probe: check if Cisco web management is accessible without auth."""
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
                    if any(sig in resp.read() for sig in self.CISCO_SIGS):
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
            is_cisco = any(sig in content for sig in self.CISCO_SIGS)
            if not is_cisco and asset.product:
                is_cisco = any(x in asset.product.lower()
                              for x in ("cisco", "ios", "asa", "catalyst", "nexus"))
            if not is_cisco:
                return ScanResult(False)

            for path in ["/webui/", "/admin/", "/"]:
                try:
                    data = {"username": cred.username, "password": cred.password}
                    auth_resp = await client.post(
                        base + path, data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=False,
                    )
                    if auth_resp.status_code in (301, 302, 303):
                        loc = auth_resp.headers.get("location", "").lower()
                        if "login" not in loc:
                            return ScanResult(True, FindingType.DEFAULT_PASSWORD)
                except Exception:
                    continue

            return ScanResult(False)
        except Exception:
            return ScanResult(False)

    def test(self, asset, cred) -> ScanResult:
        import urllib.request, urllib.parse, ssl
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
            is_cisco = any(sig in content for sig in self.CISCO_SIGS)
            if not is_cisco:
                return ScanResult(False)

            data = f"username={urllib.parse.quote(cred.username)}&password={urllib.parse.quote(cred.password)}"
            req = urllib.request.Request(
                base + "/webui/", data=data.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                with opener.open(req, timeout=5) as r:
                    if r.status in (301, 302, 303):
                        return ScanResult(True, FindingType.DEFAULT_PASSWORD)
            except urllib.error.HTTPError:
                pass
            return ScanResult(False)
        except Exception:
            return ScanResult(False)
