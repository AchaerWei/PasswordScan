import socket, ssl, base64
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError
from netspider._lib.socket_utils import _smtp_recv_line
from netspider.security import create_ssl_context


def test_smtp(ip: str, port: int, user: str, pwd: str) -> bool:
    """SMTP AUTH LOGIN. Works on port 25 (plain), 587 (submission), 465 (TLS)."""
    use_tls = port == 465
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        if use_tls:
            ctx = create_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        banner = _smtp_recv_line(sock, 5.0)
        if not banner.startswith(b"220"):
            sock.close()
            return False

        def _cmd(cmd: bytes) -> bytes:
            sock.send(cmd + b"\r\n")
            return _smtp_recv_line(sock)

        ehlo = _cmd(b"EHLO weakpass.local")
        if b"250" not in ehlo:
            sock.close()
            return False
        # Drain any remaining multi-line EHLO response (250-xxx continuation)
        while True:
            try:
                peek = _smtp_recv_line(sock, timeout=0.3)
                if peek.startswith(b"250") and peek[3:4] in (b"-", b" "):
                    continue
                if not peek:
                    break
                break
            except Exception:
                break

        auth = _cmd(b"AUTH LOGIN")
        if not auth.startswith(b"334"):
            # Try AUTH PLAIN as fallback
            auth = _cmd(b"AUTH PLAIN")
            if not auth.startswith(b"334"):
                sock.close()
                return False
            # AUTH PLAIN: one-shot base64(\0user\0pwd)
            plain = base64.b64encode(f"\x00{user}\x00{pwd}".encode()).decode()
            sock.send(plain.encode() + b"\r\n")
            resp = _smtp_recv_line(sock)
            sock.close()
            return resp.startswith(b"235")

        # AUTH LOGIN: two-step base64
        sock.send(base64.b64encode(user.encode()) + b"\r\n")
        resp_user = _smtp_recv_line(sock)
        if not resp_user.startswith(b"334"):
            sock.close()
            return False

        sock.send(base64.b64encode(pwd.encode()) + b"\r\n")
        resp_pass = _smtp_recv_line(sock)
        sock.close()
        return resp_pass.startswith(b"235")
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def test_imap(ip: str, port: int, user: str, pwd: str) -> bool:
    """IMAP LOGIN. Works on port 143 (plain), 993 (TLS)."""
    use_tls = port == 993
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        if use_tls:
            ctx = create_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        sock.settimeout(SCAN_TIMEOUT)
        banner = sock.recv(4096)
        if not (banner.startswith(b"* OK") or banner.startswith(b"* PREAUTH")):
            sock.close()
            return False

        # Reject credentials with chars that break IMAP LOGIN syntax
        if any(c in user + pwd for c in '\r\n'):
            sock.close()
            return False
        cmd = f"a001 LOGIN {user} {pwd}\r\n".encode()
        sock.send(cmd)
        resp = sock.recv(4096)
        sock.close()
        resp_text = resp.decode("utf-8", errors="ignore").lower()
        return "a001 ok" in resp_text and "login" in resp_text
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def test_pop3(ip: str, port: int, user: str, pwd: str) -> bool:
    """POP3 USER/PASS. Works on port 110 (plain), 995 (TLS)."""
    use_tls = port == 995
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        if use_tls:
            ctx = create_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        sock.settimeout(SCAN_TIMEOUT)
        banner = sock.recv(4096)
        if not banner.startswith(b"+OK"):
            sock.close()
            return False

        # Reject credentials with chars that break POP3 command syntax
        if any(c in user + pwd for c in '\r\n'):
            sock.close()
            return False

        sock.send(f"USER {user}\r\n".encode())
        resp_user = sock.recv(4096)
        if not resp_user.startswith(b"+OK"):
            sock.close()
            return False

        sock.send(f"PASS {pwd}\r\n".encode())
        resp_pass = sock.recv(4096)
        sock.close()
        return resp_pass.startswith(b"+OK")
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
