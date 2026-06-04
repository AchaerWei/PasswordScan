import socket, base64, re, time
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError
from netspider._lib.ntlm import _ntlmssp_negotiate, _ntlmssp_parse_challenge, _ntlmssp_authenticate


def test_winrm(ip: str, port: int, user: str, pwd: str) -> bool:
    """WinRM NTLM auth test via WS-Man HTTP endpoint."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(8.0)

        # Step 1: POST /wsman with no auth → expect 401 with WWW-Authenticate: Negotiate/NTLM
        req1 = (
            f"POST /wsman HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: Keep-Alive\r\n"
            f"\r\n"
        ).encode()
        sock.send(req1)
        resp1 = b''
        try:
            while b'\r\n\r\n' not in resp1:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp1 += chunk
                if len(resp1) > 16384:
                    break
        except socket.timeout:
            pass

        resp1_str = resp1.decode('utf-8', errors='ignore')
        if '401' not in resp1_str[:30] and 'WWW-Authenticate' not in resp1_str:
            sock.close()
            return False

        # Step 2: Build NTLMSSP Type 1 (Negotiate)
        nego_token = _ntlmssp_negotiate('', 'SCANNER')
        auth_hdr1 = base64.b64encode(nego_token).decode('ascii')

        req2 = (
            f"POST /wsman HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: Keep-Alive\r\n"
            f"Authorization: Negotiate {auth_hdr1}\r\n"
            f"\r\n"
        ).encode()
        sock.send(req2)
        resp2 = b''
        try:
            while b'\r\n\r\n' not in resp2:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
                if len(resp2) > 16384:
                    break
        except socket.timeout:
            pass

        resp2_str = resp2.decode('utf-8', errors='ignore')
        # HTTP headers are case-insensitive per RFC 7230
        resp2_lower = resp2_str.lower()
        if 'www-authenticate: negotiate' not in resp2_lower and 'www-authenticate: ntlm' not in resp2_lower:
            sock.close()
            return False

        # Extract NTLMSSP Challenge (case-insensitive per RFC 7230)
        import re
        chal_match = re.search(r'(?:Negotiate|NTLM)\s+([A-Za-z0-9+/=]+)', resp2_str, re.IGNORECASE)
        if not chal_match:
            sock.close()
            return False

        challenge_blob = base64.b64decode(chal_match.group(1))
        ch_info = _ntlmssp_parse_challenge(challenge_blob)
        if not ch_info or len(ch_info.get('challenge', b'')) < 8:
            sock.close()
            return False

        # Step 3: NTLMSSP Type 3 (Authenticate)
        auth_token = _ntlmssp_authenticate(user, '', 'SCANNER', ch_info, pwd)
        auth_hdr3 = base64.b64encode(auth_token).decode('ascii')

        req3 = (
            f"POST /wsman HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: Keep-Alive\r\n"
            f"Authorization: Negotiate {auth_hdr3}\r\n"
            f"\r\n"
        ).encode()
        sock.send(req3)
        resp3 = b''
        try:
            while b'\r\n\r\n' not in resp3:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp3 += chunk
                if len(resp3) > 16384:
                    break
        except socket.timeout:
            pass

        sock.close()
        resp3_str = resp3.decode('utf-8', errors='ignore')
        # 200 or non-401 = success; 401 = failed auth
        return '401' not in resp3_str[:30]
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
