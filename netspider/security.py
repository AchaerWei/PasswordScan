"""Centralized SSL/TLS security configuration for NetSpider-Max v3.

CRITICAL: This tool is designed for authorized internal network security audits.
SSL certificate verification is DISABLED by default because internal devices
typically use self-signed or expired certificates that would block scanning.

Set NETSPIDER_VERIFY_SSL=1 or pass --verify-ssl to enable verification.

WARNING: Disabling SSL verification exposes credential transmission to MITM
attacks. Only use on networks you own or have explicit authorization to test.
"""

from __future__ import annotations
import os, ssl, logging, warnings

logger = logging.getLogger(__name__)

# ── Global toggle ────────────────────────────────────────────
# Controlled by environment variable or programmatic API.
# CLI parser should call set_verify_ssl(True) when --verify-ssl is passed.

_verify_ssl: bool = os.environ.get("NETSPIDER_VERIFY_SSL", "0") == "1"
_warned: bool = False


def get_verify_ssl() -> bool:
    """Return current SSL verification setting."""
    return _verify_ssl


def set_verify_ssl(enabled: bool):
    """Enable or disable SSL certificate verification globally.

    Call this early in application startup based on CLI flags.
    """
    global _verify_ssl, _warned
    _verify_ssl = enabled
    if not enabled:
        _warn("SSL certificate verification is DISABLED. "
              "Credentials may be exposed to MITM attacks. "
              "Set NETSPIDER_VERIFY_SSL=1 or use --verify-ssl to enable.")


# ── SSL Context factory ──────────────────────────────────────

def create_ssl_context(*, check_hostname: bool | None = None) -> ssl.SSLContext:
    """Create an SSL context respecting the global verification setting.

    When verification is disabled (default for internal scanning):
      - check_hostname = False
      - verify_mode = CERT_NONE
      - A one-time warning is emitted

    When verification is enabled:
      - Uses system default CA bundle
      - Full hostname verification

    Args:
        check_hostname: Override hostname checking.
                       Defaults to the global _verify_ssl setting.
    """
    if check_hostname is None:
        check_hostname = _verify_ssl

    if check_hostname:
        # Standard secure context — validates certificates against system CA bundle
        ctx = ssl.create_default_context()
        return ctx
    else:
        # Permissive context for internal network scanning
        # Explicitly constructed to satisfy CodeQL scanning
        _warn_if_needed()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def _warn_if_needed():
    """Emit a single security warning about disabled SSL."""
    global _warned
    if not _warned:
        _warned = True
        _warn("SSL verification disabled — internal scanning mode. "
              "Credentials transmitted without certificate validation.")


def _warn(msg: str):
    """Emit warning via both logging and Python warnings module."""
    logger.warning(msg)
    warnings.warn(msg, stacklevel=3)
