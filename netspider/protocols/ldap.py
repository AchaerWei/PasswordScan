import socket, struct
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError
from netspider._lib.ber import _ber_len_content, _ber_decode_length, _ber_octet_string


def test_ldap(ip: str, port: int, user: str, pwd: str) -> bool:
    """LDAP Simple Bind via raw socket (BER encoding).

    Multi-DN strategy:
      1. If user contains '=', treat as full DN → single attempt.
      2. Probe RootDSE for defaultNamingContext (anonymous search).
      3. Build DN candidates from naming context + common patterns.
      4. Try each candidate; return True on first success.
    """
    try:
        if '=' in user:
            return _try_ldap_bind(ip, port, user, pwd)

        naming_ctx = _probe_rootdse(ip, port)
        candidates = _build_dn_candidates(user, naming_ctx)
        for dn in candidates:
            if _try_ldap_bind(ip, port, dn, pwd):
                return True
        return False
    except Exception:
        return False


def _try_ldap_bind(ip: str, port: int, dn: str, pwd: str) -> bool:
    """Single LDAP Simple Bind attempt. Returns True on success."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(5.0)
        bind_req = _build_ldap_bind(dn, pwd)
        sock.send(bind_req)
        resp = sock.recv(4096)
        sock.close()
        if len(resp) < 2:
            return False
        return _parse_ldap_bind_response(resp)
    except Exception:
        return False


def _build_ldap_bind(dn: str, pwd: str) -> bytes:
    """Build LDAP Simple Bind Request (BER-encoded)."""
    version = bytes([0x02, 0x01, 0x03])  # INTEGER(3) — LDAPv3
    name = _ber_octet_string(dn.encode('utf-8'))
    auth_simple = bytes([0x80]) + _ber_len_content(len(pwd)) + pwd.encode('utf-8')
    # Auth choice = simple(0) + auth
    auth = bytes([0xA0, len(auth_simple)]) + auth_simple
    # Bind request body
    body = version + name + auth
    # full = SEQUENCE(msg_id=1, BindRequest=APPLICATION(0))
    msg_sq = bytes([0x02, 0x01, 0x01])  # messageID = 1
    bind_op = bytes([0x62]) + _ber_len_content(len(body)) + body
    full = bytes([0x30]) + _ber_len_content(len(msg_sq) + len(bind_op)) + msg_sq + bind_op
    return full


def _parse_ldap_bind_response(data: bytes) -> bool:
    """Parse LDAP Bind Response. errCode=0 = success."""
    try:
        if data[0] != 0x30:  # SEQUENCE
            return False
        # Find BindResponse (APPLICATION 1 = 0x61)
        pos = 2
        while pos < len(data):
            tag = data[pos]
            if tag == 0x61:  # BindResponse
                pos += 1
                # Get length
                if data[pos] & 0x80:
                    ll = data[pos] & 0x7F
                    pos += 1 + ll
                else:
                    pos += 1
                # Read resultCode (INTEGER 0x0A)
                for _ in range(20):
                    if pos >= len(data):
                        return False
                    if data[pos] == 0x0A:  # ENUMERATED
                        pos += 1
                        val_len = data[pos]; pos += 1
                        if val_len == 1:
                            return data[pos] == 0x00  # success
                        if val_len == 0:
                            return False
                        result = 0
                        for i in range(val_len):
                            result = (result << 8) | data[pos + i]
                        return result == 0
                    pos += 1
            else:
                if data[pos] & 0x80:
                    ll = data[pos] & 0x7F
                    pos += 1 + ll
                else:
                    pos += 1
        return False
    except Exception:
        return False


# ---- RootDSE Probe ----

_ROOTDSE_TIMEOUT = 3.0


def _probe_rootdse(ip: str, port: int) -> str:
    """Probe RootDSE via anonymous search, return defaultNamingContext or ''.

    Sends an LDAP SearchRequest (base="" scope=baseObject filter=(objectClass=*))
    requesting the defaultNamingContext attribute. Gracefully returns '' on failure.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=_ROOTDSE_TIMEOUT)
        sock.settimeout(3.0)
        req = _build_rootdse_search()
        sock.send(req)
        resp = _recv_all_ldap(sock, 8192)
        sock.close()
        return _parse_naming_context(resp)
    except Exception:
        return ''


def _recv_all_ldap(sock, max_size: int) -> bytes:
    """Read all available data from LDAP socket (up to max_size)."""
    sock.settimeout(1.0)
    data = b''
    try:
        while len(data) < max_size:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def _build_rootdse_search() -> bytes:
    """Build LDAP SearchRequest for RootDSE attribute defaultNamingContext.

    SEQUENCE(msgID=1, SearchRequest=APPLICATION(3))
    SearchRequest: base="" scope=0 deref=0 sizeLimit=0 timeLimit=0
                   typesOnly=FALSE filter=(objectClass=*) attributes=defaultNamingContext
    """
    msg_id = bytes([0x02, 0x01, 0x01])  # messageID = 1

    base_object = _ber_octet_string(b'')  # "" = RootDSE
    scope = bytes([0x0A, 0x01, 0x00])     # ENUMERATED baseObject
    deref = bytes([0x0A, 0x01, 0x00])     # ENUMERATED neverDerefAliases
    size_limit = bytes([0x02, 0x01, 0x00])  # INTEGER 0 = no limit
    time_limit = bytes([0x02, 0x01, 0x00])  # INTEGER 0 = no limit
    types_only = bytes([0x01, 0x01, 0x00])  # BOOLEAN FALSE

    # Filter: (objectClass=*)  →  present [7] IMPLICIT AttributeDescription
    attr_desc = b'objectClass'
    filter_tag = bytes([0x87, len(attr_desc)]) + attr_desc

    # Attribute selection: SEQUENCE { OCTET STRING "defaultNamingContext" }
    attr_name = b'defaultNamingContext'
    attr_octet = bytes([0x04, len(attr_name)]) + attr_name
    attr_list = bytes([0x30, len(attr_octet)]) + attr_octet

    body = base_object + scope + deref + size_limit + time_limit + types_only + filter_tag + attr_list
    op = bytes([0x63]) + _ber_len_content(len(body)) + body
    full = bytes([0x30]) + _ber_len_content(len(msg_id) + len(op)) + msg_id + op
    return full


def _parse_naming_context(data: bytes) -> str:
    """Extract defaultNamingContext value from SearchResultEntry response."""
    try:
        if len(data) < 4:
            return ''
        needle = b'defaultNamingContext'
        idx = data.find(needle)
        if idx < 0:
            return ''
        pos = idx + len(needle)
        limit = min(pos + 20, len(data))
        while pos < limit:
            if data[pos] == 0x31:  # SET OF values
                pos += 1
                if pos < len(data):
                    if data[pos] & 0x80:
                        ll = data[pos] & 0x7F
                        pos += 1 + ll
                    else:
                        pos += 1
                if pos < len(data) and data[pos] == 0x04:
                    pos += 1
                    if pos < len(data):
                        val_len = data[pos]
                        pos += 1
                        if pos + val_len <= len(data):
                            return data[pos:pos + val_len].decode('utf-8', errors='ignore')
                return ''
            pos += 1
        return ''
    except Exception:
        return ''


# ---- DN Candidate Builder ----

def _dc_to_domain(base_dn: str) -> str:
    """Extract domain.com from dc=domain,dc=com pattern."""
    parts = []
    for part in base_dn.lower().split(','):
        part = part.strip()
        if part.startswith('dc='):
            parts.append(part[3:])
    return '.'.join(parts) if parts else ''


def _build_dn_candidates(user: str, base_dn: str) -> list[str]:
    """Build prioritized DN candidates for the given user.

    Coverage:
      AD UPN user@domain   (can bind directly in AD)
      AD SAM CN=user,CN=Users,<base>
      OpenLDAP cn=user,<base>
      OpenLDAP uid=user,<base>
      FreeIPA  uid=user,cn=users,cn=accounts,<base>
      Bare username (fallback for proxies)
    """
    candidates = []

    if base_dn:
        domain = _dc_to_domain(base_dn)
        if domain:
            candidates.append(f"{user}@{domain}")

    if base_dn:
        candidates.append(f"CN={user},CN=Users,{base_dn}")

    if base_dn:
        candidates.append(f"cn={user},{base_dn}")

    if base_dn:
        candidates.append(f"uid={user},{base_dn}")

    if base_dn:
        candidates.append(f"uid={user},cn=users,cn=accounts,{base_dn}")

    candidates.append(user)

    # Deduplicate preserving priority order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result
