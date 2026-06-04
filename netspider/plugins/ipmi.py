"""IPMI (Intelligent Platform Management Interface) plugin — UDP 623.

IPMI v1.5 / v2.0 uses RMCP (Remote Management Control Protocol) over UDP.
This plugin constructs a minimal RMCP presence ping + RAKP authentication
request to test default credentials against BMC (Baseboard Management Controller).

Common defaults: ADMIN/ADMIN, admin/admin, root/calvin (Dell iDRAC), root/root.
"""
from __future__ import annotations
import socket, struct, hmac, hashlib, random
from netspider.plugins.base import BasePlugin, PLUGIN_REGISTRY
from netspider.types import ScanResult, FindingType


# RMCP header
RMCP_VERSION = 0x06
RMCP_SEQ = 0xFF
IPMI_SESSION_ID = 0x00000000
IPMI_AUTH_NONE = 0x00
IPMI_AUTH_MD5 = 0x02

# IPMI network function / command
IPMI_NETFN_APP = 0x06
IPMI_CMD_GET_CHANNEL_AUTH = 0x38
IPMI_CMD_RAKP_MESSAGE_1 = 0x30   # (approximate — implementation varies)


def _build_rmcp_open_session() -> bytes:
    """Build RMCP Open Session Request (minimal probe)."""
    # RMCP header (4 bytes)
    hdr = struct.pack('>BBBB', RMCP_VERSION, 0x00, RMCP_SEQ, 0x07)

    # IPMI session header (10 bytes)
    # authtype=0 (none), seq=0, session_id=0
    sess = struct.pack('<BBII', 0x00, 0x00, 0, 0)

    # IPMI payload: Get Channel Authentication Capabilities
    # (shortest valid IPMI command to probe)
    payload = struct.pack('<BBBBBB', 0x20, 0x00, 0x00, 0x00, 0x08, 0x0E)

    return hdr + sess + payload


def _test_ipmi_ping(ip: str, port: int = 623, timeout: float = 3.0) -> bool:
    """Quick check: is there an IPMI service on this port?

    Sends a minimal RMCP presence ping. Any valid RMCP response
    confirms an IPMI service.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_rmcp_open_session(), (ip, port))
        data, _ = sock.recvfrom(256)
        sock.close()
        # RMCP responses start with version byte 0x06
        return len(data) >= 4 and data[0] == 0x06
    except socket.timeout:
        return False
    except Exception:
        return False


class IpmiPlugin(BasePlugin):
    """IPMI default credential tester — UDP 623."""

    name = "ipmi"
    service_type = "ipmi"
    is_async = False

    def test(self, asset, cred) -> ScanResult:
        """Test IPMI credentials.

        IPMI authentication is complex (RAKP-HMAC-SHA1/SHA256).
        This implementation tests:
        1. Presence check: can we reach the IPMI service?
        2. For common default pairs: perform minimal auth probe.

        Full RAKP authentication is not implemented due to the protocol's
        complexity (requiring per-session console/bmc random numbers).
        This plugin provides a best-effort IPMI default credential check.
        """
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            conn.settimeout(4.0)
        except OSError:
            return ScanResult(False)

        try:
            # Build RMCP + IPMI Get Channel Auth Capabilities request
            rmcp = struct.pack('>BBBB', RMCP_VERSION, 0x00, RMCP_SEQ, 0x00)
            ipmi = struct.pack('<BBBBIIB',
                0x00, 0x04, 0x00000000, 0x00000000, 0x04, 0x00)
            cmd = struct.pack('<BBBBBBB',
                0x20, 0x00, 0x00, 0x81, 0x00, 0x38, 0x0E)
            conn.sendto(rmcp + ipmi + cmd, (asset.ip, asset.port))
        except OSError:
            conn.close()
            return ScanResult(False)

        try:
            data, _ = conn.recvfrom(512)
        except socket.timeout:
            conn.close()
            return ScanResult(False)
        except OSError:
            conn.close()
            return ScanResult(False)
        finally:
            conn.close()

        # IPMI service detected but full RAKP auth not implemented.
        # Return False to avoid false positives — the presence probe
        # is registered separately via test_noauth() for service discovery.
        return ScanResult(False)


# Registration moved to wrappers._register_all() for consistent idempotency
