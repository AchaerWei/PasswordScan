from __future__ import annotations
import socket, time, re, ftplib
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    paramiko = None
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, FindingType, _set_finding_type
from netspider._lib.socket_utils import _recv_until


def test_ftp(ip: str, port: int, user: str, pwd: str) -> bool:
    try:
        f = ftplib.FTP()
        f.connect(ip, port, timeout=SCAN_TIMEOUT)
        f.login(user, pwd)
        # Quit may fail if server already closed connection — login already succeeded
        try:
            f.quit()
        except Exception:
            f.close()
        return True
    except (ftplib.error_perm, ftplib.error_temp):
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def test_telnet(ip: str, port: int, user: str, pwd: str) -> bool:
    """Telnet via raw socket with IAC handling.
    Strict two-step verification: must see login prompt → send user→ see password prompt → send pass
    → check response for clear failure or success indicators. Ambiguous = False."""
    IAC, WONT, DONT = 0xFF, 0xFC, 0xFE
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(4.0)

        # ---- Read initial banner, accumulate and strip IAC ----
        data = b""
        for _ in range(10):
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Process accumulated data for IAC sequences that may span chunks
                clean = bytearray()
                i = 0
                while i < len(data):
                    if data[i] == IAC and i + 2 < len(data):
                        i += 3
                    else:
                        clean.append(data[i])
                        i += 1
                data = bytes(clean)
            except socket.timeout:
                break
            # Stop when we see a login prompt
            txt = data.decode("utf-8", errors="ignore").lower()
            if any(p in txt for p in ('login:', 'username:', 'user:', 'password:', 'passwd:')):
                break
            if len(data) > 8192:
                break

        text = data.decode("utf-8", errors="ignore").lower()

        # Must see a login-type prompt to proceed
        has_login_prompt = any(
            p in text.rstrip().split('\n')[-1] if text else False
            for p in ('login:', 'username:', 'user:')
        )
        has_pwd_prompt = any(
            p in text.rstrip().split('\n')[-1] if text else False
            for p in ('password:', 'passwd:')
        )

        if has_login_prompt:
            # Send username
            sock.send((user + "\r\n").encode())
            resp = _recv_until(sock, [b"password:", b"passwd:", b"login:", b"fail", b"denied"])
            resp_text = resp.decode("utf-8", errors="ignore").lower()

            if "password:" in resp_text or "passwd:" in resp_text:
                sock.send((pwd + "\r\n").encode())
                result = _recv_until(sock,
                    [b"$", b"#", b">", b"login:", b"fail", b"denied",
                     b"last login", b"welcome", b"successful",
                     b"incorrect", b"invalid", b"bad password"]).decode(
                    "utf-8", errors="ignore").lower()
                sock.close()

                # STRICT failure check first
                fail_kw = ["login incorrect", "invalid", "fail",
                          "authentication failed", "access denied", "wrong password",
                          "bad password", "permission denied"]
                # "login:" suggests another login prompt (failure), but
                # "last login:" is a success indicator — don't flag it
                if any(kw in result for kw in fail_kw):
                    return False
                if "login:" in result and "last login:" not in result:
                    return False
                # STRICT success check
                # Must see shell prompt at end of response, not just a stray char
                lines = [l.strip() for l in result.split('\n') if l.strip()]
                last_line = lines[-1] if lines else ""
                has_prompt = bool(re.search(r'[$#>]\s*$', last_line))
                has_welcome = any(kw in result for kw in
                                 ("last login", "welcome", "successful", "login: ok"))
                # Banner that happens to end in # is common on network devices
                # only trust # if followed by space (shell prompt convention)
                if has_welcome:
                    return True
                if has_prompt and len(last_line) < 200:
                    return True
                return False
            else:
                # Didn't get password prompt after username
                sock.close()
                return False

        elif has_pwd_prompt:
            # Some devices skip username, show password prompt directly
            sock.send((pwd + "\r\n").encode())
            result = _recv_until(sock,
                [b"$", b"#", b">", b"login:", b"fail", b"denied",
                 b"last login", b"welcome", b"successful",
                 b"incorrect", b"invalid", b"bad password"]).decode(
                "utf-8", errors="ignore").lower()
            sock.close()

            fail_kw = ["login incorrect", "invalid", "fail",
                      "authentication failed", "access denied", "wrong password"]
            if any(kw in result for kw in fail_kw):
                return False
            if "login:" in result and "last login:" not in result:
                return False
            lines = [l.strip() for l in result.split('\n') if l.strip()]
            last_line = lines[-1] if lines else ""
            has_prompt = bool(re.search(r'[$#>]\s*$', last_line))
            has_welcome = any(kw in result for kw in
                             ("last login", "welcome", "successful"))
            if has_welcome or (has_prompt and len(last_line) < 200):
                return True
            return False

        else:
            # No recognizable login prompt — not a Telnet login service
            sock.close()
            return False

    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def test_ssh(ip: str, port: int, user: str, pwd: str) -> bool:
    if not HAS_PARAMIKO:
        return False
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, port=port, username=user, password=pwd,
                  timeout=SCAN_TIMEOUT, allow_agent=False, look_for_keys=False,
                  banner_timeout=SCAN_TIMEOUT)
        c.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except (socket.timeout, EOFError, OSError):
        return False
    except Exception:
        return False
