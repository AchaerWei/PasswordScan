"""TCP connect + banner-based service detection (extracted from V2 discovery)."""
import socket, struct
from netspider._lib.constants import NAMED_PORTS, HTTP_PORTS
from netspider._lib.socket_utils import _read_initial_banner

BANNER_SIGNATURES = [
    (b"SSH-", "ssh"), (b"RFB ", "vnc"), (b"RTSP/", "rtsp"),
    (b"+OK", "pop3"), (b"* OK", "imap"), (b"ESMTP", "smtp"),
    (b"220 ", "smtp"), (b"NOAUTH", "redis"), (b"HTTP/", "http"),
    (b"<html", "http"), (b"<!DOCTYPE", "http"), (b"<HTML", "http"),
]

def tcp_connect(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        service = NAMED_PORTS.get(port, "unknown")
        banner = _read_initial_banner(s)
        if banner:
            for sig, svc in BANNER_SIGNATURES:
                if sig in banner:
                    if service == "unknown":
                        service = svc
                    break
        if port in (22, 3306, 5432, 6379, 27017) or port in HTTP_PORTS:
            try:
                if port == 22:
                    if not banner:
                        banner = s.recv(256)
                    service = "ssh" if banner.startswith(b"SSH-") else "unknown"
                elif port == 3306:
                    if not banner:
                        banner = s.recv(256)
                    service = "mysql" if len(banner) > 4 else "unknown"
                elif port == 6379:
                    if b"PONG" not in banner and b"NOAUTH" not in banner:
                        s.send(b"PING\r\n")
                        resp = s.recv(256)
                        if b"PONG" in resp or b"NOAUTH" in resp:
                            service = "redis"
                    else:
                        service = "redis"
                elif port in HTTP_PORTS:
                    if b"HTTP/" not in banner[:12]:
                        s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                        resp = s.recv(1024)
                    else:
                        resp = banner
                    if b"HTTP/" in resp[:12]:
                        service = "https" if port in (443, 8443) else "http"
            except Exception:
                pass
        if service == "unknown":
            try:
                if not banner:
                    banner = b""
                if b"HTTP/" not in banner[:12] and b"<html" not in banner.lower()[:200] and b"<!doctype" not in banner.lower()[:200]:
                    s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    resp = _read_initial_banner(s, timeout=1.0)
                    if resp:
                        if b"HTTP/" in resp[:12]:
                            service = "http"
                        elif b"<html" in resp.lower()[:200]:
                            service = "http"
                        elif b"SSH-" in resp:
                            service = "ssh"
                        elif b"* OK" in resp:
                            service = "imap"
                        elif b"+OK" in resp:
                            service = "pop3"
                        elif b"220" in resp[:4]:
                            service = "smtp"
                        elif b"RFB " in resp:
                            service = "vnc"
            except Exception:
                pass
        s.close()
        return service
    except Exception:
        return ""
