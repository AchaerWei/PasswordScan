import socket, hashlib  # codeql-skip: py/weak-cryptographic-algorithm — MD5 required by RTSP Digest (RFC 2069)
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, FindingType, _set_finding_type
from netspider._lib.socket_utils import _recv_until_delim


def _parse_rtsp_auth_header(response: str) -> dict | None:
    """Parse WWW-Authenticate: Digest header from RTSP response."""
    for line in response.split('\r\n'):
        lower = line.lower()
        if lower.startswith('www-authenticate:'):
            hdr = line.split(':', 1)[1].strip()
            if hdr.lower().startswith('digest '):
                hdr = hdr[7:]
            p = {}
            i = 0
            while i < len(hdr):
                while i < len(hdr) and hdr[i] in ' ,\t':
                    i += 1
                if i >= len(hdr):
                    break
                eq = hdr.find('=', i)
                if eq < 0:
                    break
                key = hdr[i:eq].strip()
                i = eq + 1
                if i >= len(hdr):
                    break
                if hdr[i] == '"':
                    i += 1
                    ve = i
                    while ve < len(hdr):
                        if hdr[ve] == '"' and (ve == 0 or hdr[ve - 1] != '\\'):
                            break
                        ve += 1
                    p[key] = hdr[i:ve]
                    i = ve + 1
                else:
                    ve = i
                    while ve < len(hdr) and hdr[ve] not in ', \t':
                        ve += 1
                    p[key] = hdr[i:ve]
                    i = ve
            return p if 'nonce' in p else None
    return None


def test_rtsp(ip: str, port: int, user: str, pwd: str) -> bool:
    """RTSP Digest authentication test (RFC 2326 + RFC 2617)."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(5.0)
        base_uri = f"rtsp://{ip}:{port}/"

        req1 = (
            f"DESCRIBE {base_uri} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: Scanner/2.0\r\n"
            f"\r\n"
        ).encode()
        sock.send(req1)
        resp1 = _recv_until_delim(sock, b'\r\n\r\n', timeout=5.0)
        if not resp1:
            sock.close()
            return False

        resp1_str = resp1.decode('utf-8', errors='ignore')
        if '200 OK' in resp1_str[:30]:
            sock.close()
            _set_finding_type(FindingType.NO_AUTH)
            return True  # No auth required

        if '401' not in resp1_str[:30]:
            sock.close()
            return False

        auth_hdr = _parse_rtsp_auth_header(resp1_str)
        if not auth_hdr or 'nonce' not in auth_hdr:
            sock.close()
            return False

        realm = auth_hdr.get('realm', 'RTSP Server')
        nonce = auth_hdr.get('nonce', '')
        opaque = auth_hdr.get('opaque', '')

        ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
        ha2 = hashlib.md5(f"DESCRIBE:{base_uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        auth_val = (
            f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{base_uri}", response="{response}"'
        )
        if opaque:
            auth_val += f', opaque="{opaque}"'

        req2 = (
            f"DESCRIBE {base_uri} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"Authorization: {auth_val}\r\n"
            f"User-Agent: Scanner/2.0\r\n"
            f"\r\n"
        ).encode()
        sock.send(req2)
        resp2 = _recv_until_delim(sock, b'\r\n\r\n', timeout=5.0)
        sock.close()

        if not resp2:
            return False
        return '200 OK' in resp2.decode('utf-8', errors='ignore')[:30]
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
