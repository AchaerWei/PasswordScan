"""Python wrapper for Go protocol testers (goproto binary).

Provides a clean subprocess interface to Go-native protocol implementations.
Used as a cross-validation backend for non-DB protocols.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

_GOPROTO_BIN = Path(__file__).parent / "goproto.exe"


def _run_goproto(protocol: str, **kwargs) -> dict:
    """Run a goproto subcommand and return the JSON result as a dict.

    Returns {"success": bool, "protocol": str, "error": str, "detail": str}
    """
    if not _GOPROTO_BIN.exists():
        return {"success": False, "protocol": protocol,
                "error": f"goproto binary not found at {_GOPROTO_BIN}"}

    cmd = [str(_GOPROTO_BIN), protocol]
    for k, v in kwargs.items():
        cmd.append(f"--{k}")
        cmd.append(str(v))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if proc.stdout.strip():
            return json.loads(proc.stdout.strip())
        return {"success": False, "protocol": protocol,
                "error": proc.stderr.strip() or "no output"}
    except subprocess.TimeoutExpired:
        return {"success": False, "protocol": protocol, "error": "timeout"}
    except Exception as e:
        return {"success": False, "protocol": protocol, "error": str(e)}


# ---- Protocol-specific wrappers ----

def goproto_snmp(ip: str, community: str, timeout: int = 3) -> bool:
    """Test SNMP community string via Go implementation."""
    result = _run_goproto("snmp", host=ip, community=community, timeout=timeout)
    return result.get("success", False)


def goproto_ldap(ip: str, user: str, password: str, timeout: int = 5) -> bool:
    """Test LDAP simple bind via Go implementation."""
    result = _run_goproto("ldap", host=ip, user=user, **{"pass": password, "timeout": timeout})
    return result.get("success", False)


def goproto_imap(ip: str, user: str, password: str, timeout: int = 5) -> bool:
    """Test IMAP LOGIN via Go implementation."""
    result = _run_goproto("imap", host=ip, user=user, **{"pass": password, "timeout": timeout})
    return result.get("success", False)


def goproto_pop3(ip: str, user: str, password: str, timeout: int = 5) -> bool:
    """Test POP3 USER/PASS via Go implementation."""
    result = _run_goproto("pop3", host=ip, user=user, **{"pass": password, "timeout": timeout})
    return result.get("success", False)


def goproto_rtsp(ip: str, user: str, password: str, timeout: int = 5) -> bool:
    """Test RTSP Digest auth via Go implementation."""
    result = _run_goproto("rtsp", host=ip, user=user, **{"pass": password, "timeout": timeout})
    return result.get("success", False)


def goproto_vnc(ip: str, password: str, timeout: int = 5) -> bool:
    """Test VNC challenge-response via Go implementation."""
    result = _run_goproto("vnc", host=ip, **{"pass": password, "timeout": timeout})
    return result.get("success", False)
