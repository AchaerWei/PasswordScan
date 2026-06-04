"""Socket utility helpers shared across protocol testers."""

import socket
import time


def _read_initial_banner(sock: socket.socket, buf_size: int = 1024,
                         timeout: float = 1.0) -> bytes:
    """Read whatever data the server sends immediately on connect."""
    try:
        sock.settimeout(timeout)
        return sock.recv(buf_size)
    except socket.timeout:
        return b""
    except Exception:
        return b""


def _smtp_recv_line(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read one CRLF-terminated line from SMTP-style server."""
    sock.settimeout(timeout)
    data = b""
    while not data.endswith(b"\r\n"):
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
        if len(data) > 8192:
            break
    return data


def _recv_until(sock: socket.socket, markers: list[bytes],
                max_wait: float = 3.0) -> bytes:
    """Receive data until a marker is found or timeout. Returns accumulated bytes."""
    data = b""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(max(0.05, remaining))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            for marker in markers:
                if marker in data.lower():
                    return data
        except (socket.timeout, TimeoutError):
            break
    return data


def _recv_until_delim(sock, delimiter: bytes, timeout: float = 5.0) -> bytes | None:
    """Receive from socket until delimiter or timeout."""
    sock.settimeout(timeout)
    data = b''
    try:
        while delimiter not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        return data
    except socket.timeout:
        return data if data else None
    except Exception:
        return None
