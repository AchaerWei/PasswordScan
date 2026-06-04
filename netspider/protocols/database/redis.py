from __future__ import annotations
import socket
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, FindingType, _set_finding_type


def test_redis(ip: str, port: int, user: str, pwd: str) -> bool:
    """Test Redis AUTH. Uses strict Redis protocol check."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(4.0)

        # First, try PING to check if this is Redis and if it needs auth
        sock.send(b"*1\r\n$4\r\nPING\r\n")
        resp = sock.recv(1024)

        # Redis responses always start with +, -, :, $, or *
        if not resp or resp[0:1] not in (b'+', b'-', b':', b'$', b'*'):
            sock.close()
            return False

        # +PONG = no auth needed
        if resp.startswith(b'+PONG'):
            sock.close()
            _set_finding_type(FindingType.NO_AUTH)
            return True

        # -NOAUTH = auth required
        if b'NOAUTH' in resp:
            cmd = f"*2\r\n$4\r\nAUTH\r\n${len(pwd)}\r\n{pwd}\r\n"
            sock.send(cmd.encode())
            resp = sock.recv(1024)
            sock.close()
            return resp.startswith(b'+OK')

        # -ERR or other error = auth failed or unknown command
        if resp.startswith(b'-ERR'):
            # Might be a password-protected Redis that rejects PING
            cmd = f"*2\r\n$4\r\nAUTH\r\n${len(pwd)}\r\n{pwd}\r\n"
            sock.send(cmd.encode())
            resp = sock.recv(1024)
            sock.close()
            return resp.startswith(b'+OK')

        sock.close()
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
