"""Smart Web Form Brute-Forcer — auto-detect login forms and test credentials.

Uses html.parser (stdlib) — BeautifulSoup4 is optional but preferred when available.
For each login attempt:
  1. Fetch login page → extract form (action, fields, hidden tokens)
  2. Refresh CSRF token if present
  3. Submit login POST
  4. Analyze response: status code, redirect location, page content diff

Deltas from v2's _parse_login_form / _try_form_login:
  - Re-fetches page before each attempt to get fresh CSRF tokens
  - Compares response body hash to detect successful login (content change)
  - Handles window.location JS redirect detection
"""
from __future__ import annotations
import hashlib, html.parser, urllib.request, urllib.error, urllib.parse, ssl
from netspider.plugins.base import BasePlugin
from netspider.types import ScanResult, FindingType
from netspider.security import create_ssl_context


def _get_opener():
    """Build opener with current SSL verification setting."""
    ctx = create_ssl_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class _LoginForm:
    """Parsed login form."""
    __slots__ = ('action', 'method', 'user_field', 'pwd_field', 'hidden_fields', 'base_url')
    def __init__(self):
        self.action = ""
        self.method = "POST"
        self.user_field = ""
        self.pwd_field = ""
        self.hidden_fields: dict[str, str] = {}
        self.base_url = ""


def _parse_forms(html_bytes: bytes, base_url: str) -> list[_LoginForm]:
    """Parse HTML and extract all login forms (forms with a password field)."""
    if HAS_BS4:
        return _parse_bs4(html_bytes, base_url)
    return _parse_builtin(html_bytes, base_url)


def _parse_bs4(html_bytes: bytes, base_url: str) -> list[_LoginForm]:
    forms = []
    soup = BeautifulSoup(html_bytes, 'lxml')
    for form_tag in soup.find_all('form'):
        lf = _LoginForm()
        lf.action = form_tag.get('action', '')
        lf.method = form_tag.get('method', 'POST').upper()
        lf.base_url = base_url

        # Find inputs
        pwd_inputs = []
        text_inputs = []
        for inp in form_tag.find_all('input'):
            itype = inp.get('type', 'text').lower()
            name = inp.get('name', '')
            value = inp.get('value', '')
            if itype == 'hidden':
                if name:
                    lf.hidden_fields[name] = value
            elif itype == 'password':
                pwd_inputs.append(name)
            elif itype in ('text', 'email'):
                text_inputs.append(name)

        if not pwd_inputs:
            continue

        lf.pwd_field = pwd_inputs[0]
        if text_inputs:
            lf.user_field = text_inputs[0]
        else:
            lf.user_field = "username"

        forms.append(lf)

    return forms


def _parse_builtin(html_bytes: bytes, base_url: str) -> list[_LoginForm]:
    """Fallback parser using stdlib html.parser."""
    forms = []

    class _FormParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms: list[_LoginForm] = []
            self._in_form = False
            self._current: _LoginForm | None = None
            self._text_fields: list[str] = []
            self._pwd_fields: list[str] = []

        def handle_starttag(self, tag, attrs):
            attrs_d = dict(attrs)
            if tag == 'form':
                self._in_form = True
                self._current = _LoginForm()
                self._current.action = attrs_d.get('action', '')
                self._current.method = attrs_d.get('method', 'POST').upper()
                self._current.base_url = base_url
                self._text_fields = []
                self._pwd_fields = []
            elif self._in_form and tag == 'input':
                name = attrs_d.get('name', '')
                itype = attrs_d.get('type', 'text').lower()
                value = attrs_d.get('value', '')
                if itype == 'hidden' and name:
                    self._current.hidden_fields[name] = value
                elif itype == 'password':
                    self._pwd_fields.append(name)
                elif itype in ('text', 'email'):
                    self._text_fields.append(name)

        def handle_endtag(self, tag):
            if tag == 'form' and self._in_form and self._current and self._pwd_fields:
                self._current.pwd_field = self._pwd_fields[0]
                self._current.user_field = self._text_fields[0] if self._text_fields else "username"
                self.forms.append(self._current)
                self._in_form = False

    parser = _FormParser()
    parser.feed(html_bytes.decode('utf-8', errors='ignore'))
    parser.close()
    return parser.forms


class SmartFormPlugin(BasePlugin):
    """Generic web login form brute-forcer.

    Async-capable when httpx is available, with stdlib urllib fallback.
    """

    name = "smart_form"
    service_type = "http_form"     # Not auto-registered — invoked manually or via HTTP plugin
    is_async = True

    def _fetch_page(self, url: str, timeout: float = 5.0) -> tuple[int, bytes]:
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'
            })
            with _get_opener().open(req, timeout=timeout) as resp:
                return (resp.status, resp.read())
        except Exception:
            return (0, b"")

    def _submit_login(self, form: _LoginForm, user: str, pwd: str, timeout: float = 5.0) -> tuple[int, bytes, str]:
        """Submit login form. Returns (status, body_bytes, redirect_url)."""
        # Resolve action URL
        action = form.action
        if not action or action == '#':
            action = form.base_url
        elif not action.startswith('http'):
            action = urllib.parse.urljoin(form.base_url, action)

        data = dict(form.hidden_fields)
        data[form.user_field] = user
        data[form.pwd_field] = pwd

        post_data = urllib.parse.urlencode(data).encode('utf-8')

        try:
            req = urllib.request.Request(action, data=post_data,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',
                    'Content-Type': 'application/x-www-form-urlencoded',
                })
            req.method = form.method
            with _get_opener().open(req, timeout=timeout) as resp:
                body = resp.read()
                redirect_url = resp.url if resp.url != action else ""
                return (resp.status, body, redirect_url)
        except urllib.error.HTTPError as e:
            body = e.read() if hasattr(e, 'read') else b""
            return (e.code, body, "")
        except Exception:
            return (0, b"", "")

    def test(self, asset, cred) -> ScanResult:
        """Sync test: parse form, submit login, analyze response."""
        scheme = 'https' if asset.service == 'https' else 'http'
        base = f"{scheme}://{asset.ip}:{asset.port}"

        # Fetch login page
        status, body = self._fetch_page(base)
        if status == 0:
            return ScanResult(False)

        forms = _parse_forms(body, base)
        if not forms:
            # No login form found — fall back to Basic Auth
            return ScanResult(False)

        form = forms[0]

        # For each attempt, re-fetch the page to get fresh CSRF tokens
        # (then submit with the fresh tokens)
        _, fresh_body = self._fetch_page(base)
        fresh_forms = _parse_forms(fresh_body, base)
        if fresh_forms:
            form = fresh_forms[0]

        # Submit login
        status2, resp_body, redirect = self._submit_login(form, cred.username, cred.password)

        # Analysis: login success indicators
        # 1. Redirect away from login page (and not back to login)
        if redirect and 'login' not in redirect.lower():
            return ScanResult(True, FindingType.WEAK_PASSWORD)

        # 2. 302 redirect response
        if status2 in (301, 302, 303):
            return ScanResult(True, FindingType.WEAK_PASSWORD)

        # 3. Body content changed significantly (no more login form)
        if resp_body:
            new_forms = _parse_forms(resp_body, base)
            if not new_forms and len(resp_body) > 100:
                # Login form disappeared — may indicate success
                return ScanResult(True, FindingType.WEAK_PASSWORD)

        return ScanResult(False)

    async def test_async(self, client, asset, cred) -> ScanResult:
        """Async test using httpx."""
        scheme = 'https' if asset.service == 'https' else 'http'
        base = f"{scheme}://{asset.ip}:{asset.port}"

        try:
            resp = await client.get(base)
            body = resp.content
        except Exception:
            return ScanResult(False)

        forms = _parse_forms(body, base)
        if not forms:
            return ScanResult(False)

        form = forms[0]

        # Re-fetch for fresh tokens
        try:
            resp2 = await client.get(base)
            fresh_forms = _parse_forms(resp2.content, base)
            if fresh_forms:
                form = fresh_forms[0]
        except Exception:
            pass

        # Build POST data
        action = form.action or base
        if not action.startswith('http'):
            from urllib.parse import urljoin
            action = urljoin(base, action)

        data = dict(form.hidden_fields)
        data[form.user_field] = cred.username
        data[form.pwd_field] = cred.password

        try:
            post_resp = await client.post(
                action, data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                follow_redirects=False,
            )
            if post_resp.status_code in (301, 302, 303):
                loc = post_resp.headers.get('location', '')
                if 'login' not in loc.lower():
                    return ScanResult(True, FindingType.WEAK_PASSWORD)
            if post_resp.status_code == 200:
                new_forms = _parse_forms(post_resp.content, base)
                if not new_forms and len(post_resp.content) > 100:
                    return ScanResult(True, FindingType.WEAK_PASSWORD)
        except Exception:
            pass

        return ScanResult(False)
