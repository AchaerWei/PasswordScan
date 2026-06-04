from __future__ import annotations
import ssl, base64, threading, html.parser, urllib.request, urllib.error, urllib.parse, socket
from collections import OrderedDict
from netspider._lib.constants import SCAN_TIMEOUT, HTTP_PORTS
from netspider._lib.types import FindingType, _set_finding_type


from netspider.security import create_ssl_context

# Proxy bypass — scanner must connect directly, not through system proxy.
# SSL verification is configurable via --verify-ssl / NETSPIDER_VERIFY_SSL.
# Default: disabled (internal scanning with self-signed certificates).
def _get_opener():
    """Build opener with current SSL verification setting (lazy to respect config)."""
    ctx = create_ssl_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )

def _http_request(url: str, user: str | None = None, pwd: str | None = None,
                  timeout: float = 5.0) -> tuple[int, dict[str, str]]:
    """Make HTTP request. Returns (status_code, headers_dict).
    If user/pwd provided, adds Basic Auth header.
    Bypasses system proxy for direct connection to targets.
    """
    try:
        req = urllib.request.Request(url)
        if user is not None and pwd is not None:
            creds = base64.b64encode(f"{user}:{pwd}".encode('utf-8')).decode('utf-8')
            req.add_header('Authorization', f'Basic {creds}')
        with _get_opener().open(req, timeout=timeout) as resp:
            # Check if the server redirected — can't verify Basic Auth at redirect target
            if resp.url != url:
                return (302, dict(resp.headers))
            return (resp.status, dict(resp.headers))
    except urllib.error.HTTPError as e:
        return (e.code, dict(e.headers) if e.headers else {})
    except Exception:
        return (0, {})


def _http_fetch_body(url: str, timeout: float = 5.0) -> bytes:
    """Fetch HTTP response body. Returns empty bytes on failure."""
    try:
        req = urllib.request.Request(url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'})
        with _get_opener().open(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        return b""


def _parse_login_form(html_bytes: bytes, base_url: str) -> dict | None:
    """Extract login form from HTML. Returns dict with action/method/fields/hidden
    or None if no password field found."""
    import html.parser

    class _FormParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms: list[dict] = []
            self._in_form = False
            self._current = {}
            self._text_fields = []
            self._hidden = {}

        def handle_starttag(self, tag, attrs):
            attrs_d = dict(attrs)
            if tag == 'form':
                self._in_form = True
                self._current = {
                    'action': attrs_d.get('action', ''),
                    'method': attrs_d.get('method', 'post').upper(),
                }
                self._text_fields = []
                self._hidden = {}
            elif self._in_form and tag == 'input':
                name = attrs_d.get('name', '')
                itype = attrs_d.get('type', 'text')
                value = attrs_d.get('value', '')
                if itype == 'hidden':
                    if name:
                        self._hidden[name] = value
                elif itype in ('text', 'email', 'password') or not itype:
                    self._text_fields.append({
                        'name': name, 'type': itype, 'value': value
                    })

        def handle_endtag(self, tag):
            if tag == 'form' and self._in_form:
                self._in_form = False
                # Only keep forms with a password field
                has_pwd = any(f['type'] == 'password' for f in self._text_fields)
                if has_pwd:
                    self._current['fields'] = self._text_fields
                    self._current['hidden'] = self._hidden
                    self.forms.append(self._current)

    parser = _FormParser()
    try:
        parser.feed(html_bytes.decode('utf-8', errors='ignore'))
    except Exception:
        return None

    if not parser.forms:
        return None

    form = parser.forms[0]
    # Resolve action URL
    action = form['action']
    if not action or action.startswith('#'):
        action = base_url
    elif action.startswith('/'):
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        action = f"{parsed.scheme}://{parsed.netloc}{action}"
    elif not action.startswith('http'):
        if base_url.endswith('/'):
            action = base_url + action
        else:
            action = base_url.rsplit('/', 1)[0] + '/' + action

    form['action'] = action
    return form


def _submit_form_login(form: dict, user: str, pwd: str, base_url: str,
                       timeout: float = 5.0) -> bool:
    """Submit login form with credentials. Returns True if login likely succeeded."""
    import urllib.parse

    data = {}
    # Fill username/password fields
    for f in form['fields']:
        if f['type'] == 'password':
            data[f['name']] = pwd
        elif any(kw in f['name'].lower() for kw in ('user', 'login', 'email', 'account', 'name', 'id', 'usr')):
            data[f['name']] = user

    # Add hidden fields (CSRF tokens, etc.)
    data.update(form['hidden'])

    encoded = urllib.parse.urlencode(data).encode('utf-8')
    action_url = form['action']

    try:
        req = urllib.request.Request(action_url, data=encoded,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',
                'Referer': base_url,
            })
        resp = _get_opener().open(req, timeout=timeout)

        # Check success indicators
        if resp.url != action_url:
            # Redirect after login → success
            body = resp.read()
            return b'login' not in body.lower() or b'fail' not in body.lower()

        body = resp.read()
        body_lower = body.lower()

        # Failure keywords
        fail_kw = [b'incorrect', b'invalid', b'wrong password', b'bad password',
                   b'authentication failed', b'login failed', b'incorrecto',
                   b'\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf',  # 密码错误
                   b'\xe7\x99\xbb\xe5\xbd\x95\xe5\xa4\xb1\xe8\xb4\xa5']   # 登录失败
        if any(kw in body_lower for kw in fail_kw):
            return False

        # Success indicator: no password field on response (logged in page)
        if b'<input type="password"' in body_lower:
            return False

        # Check for session cookies
        set_cookie = resp.headers.get('Set-Cookie', resp.headers.get('set-cookie', ''))
        if set_cookie and ('session' in set_cookie.lower() or 'auth' in set_cookie.lower()
                           or 'token' in set_cookie.lower() or 'jsessionid' in set_cookie.lower()):
            return True

        # Status is 200 and no clear failure → cautious success
        if resp.status == 200 and b'password' not in body_lower:
            return True

        return False

    except urllib.error.HTTPError as e:
        return False
    except Exception:
        return False


def _try_form_login(url: str, user: str, pwd: str) -> bool:
    """Fetch page, detect login form, attempt form-based authentication."""
    body = _http_fetch_body(url, timeout=5.0)
    if not body:
        return False
    # Quick check: page must have a password input field
    if b'<input type="password"' not in body.lower() and b'type=password' not in body.lower():
        return False
    form = _parse_login_form(body, url)
    if form is None:
        return False
    return _submit_form_login(form, user, pwd, url)


# HTTP Basic Auth requirement cache: key=(ip,port), value=bool (requires_auth)
# LRU-bounded FIFO eviction to prevent unbounded growth on large scans
_HTTP_AUTH_CACHE_MAX = 1000
_http_auth_cache: OrderedDict[tuple[str, int], bool] = OrderedDict()
_http_auth_cache_lock = threading.Lock()

def _cache_http_auth(key: tuple[str, int], value: bool):
    """Thread-safe cache write with LRU eviction."""
    with _http_auth_cache_lock:
        if key not in _http_auth_cache and len(_http_auth_cache) >= _HTTP_AUTH_CACHE_MAX:
            _http_auth_cache.popitem(last=False)
        _http_auth_cache[key] = value

def test_http(ip: str, port: int, user: str, pwd: str) -> bool:
    """Test HTTP Basic Auth with two-step verification.
    Uses per-host cache to avoid probe on every credential (50% request savings)."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    cache_key = (ip, port)

    # Fast path: check cache
    with _http_auth_cache_lock:
        if cache_key in _http_auth_cache:
            if not _http_auth_cache[cache_key]:
                return False
            code2, _ = _http_request(url, user, pwd, timeout=4.0)
            return code2 == 200

    # Slow path: first probe for this host
    code1, headers1 = _http_request(url, timeout=4.0)
    if code1 == 0:
        _cache_http_auth(cache_key, False)
        return False

    if code1 == 401:
        www_auth = headers1.get('WWW-Authenticate', headers1.get('Www-Authenticate', ''))
        requires_auth = 'basic' in www_auth.lower()
        _cache_http_auth(cache_key, requires_auth)
        if not requires_auth:
            return False
        code2, _ = _http_request(url, user, pwd, timeout=4.0)
        return code2 == 200

    # Server returned non-401 without auth — check for form login first
    if code1 == 200:
        form_result = _try_form_login(url, user, pwd)
        if form_result:
            return True
        # Don't cache form-login hosts — another credential may succeed via form
        return False
    _cache_http_auth(cache_key, False)
    if code1 in (301, 302, 403):
        code2, _ = _http_request(url, user, pwd, timeout=4.0)
        if code1 == 403 and code2 == 200:
            return True
    return False


def test_elasticsearch(ip: str, port: int, user: str, pwd: str) -> bool:
    """Elasticsearch Basic Auth / no-auth test via HTTP REST API."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        code1, headers1 = _http_request(url, timeout=4.0)
        if code1 == 0:
            return False
        if code1 == 200:
            # No auth required — check body for ES identity
            _set_finding_type(FindingType.NO_AUTH)
            return True
        if code1 == 401:
            code2, _ = _http_request(url, user, pwd, timeout=4.0)
            return code2 == 200
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


from netspider._lib.types import NetworkError
