"""Oracle protocol tester — oracledb thin client (mandatory since Phase 2)."""
from __future__ import annotations
import socket, struct
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError

import oracledb


def test_oracle(ip: str, port: int, user: str, pwd: str) -> bool:
    """Oracle credential test via oracledb thin client (mandatory since Phase 2).

    Eliminates the TNS-detection fallback that could detect service
    presence but never actually verify credentials.
    """
    return _test_oracle_oracledb(ip, port, user, pwd)


def _test_oracle_oracledb(ip: str, port: int, user: str, pwd: str) -> bool:
    """Try Oracle login via oracledb thin client."""
    try:
        conn = oracledb.connect(
            user=user, password=pwd,
            host=ip, port=port,
            service_name='ORCL',
            timeout=SCAN_TIMEOUT,
            disable_oob=True,
        )
        conn.close()
        return True
    except oracledb.exceptions.DatabaseError as e:
        code = str(getattr(e, 'code', ''))
        msg = str(e).lower()
        if '01017' in code or 'invalid' in msg or 'logon denied' in msg:
            return False
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _test_oracle_tns_detect(ip: str, port: int) -> bool:
    """Minimal TNS detection. Returns False — credential verification
    requires 'pip install oracledb'."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(5.0)
        pkt = _build_tns_connect()
        sock.send(pkt)
        resp = sock.recv(4096)
        sock.close()
        if len(resp) < 8:
            return False
        pkt_type = resp[4] if len(resp) > 4 else 0
        if pkt_type in (2, 5, 11, 4):
            return False
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _build_tns_connect() -> bytes:
    """Build a minimal Oracle TNS CONNECT packet."""
    connect_data = (
        b'(DESCRIPTION=('
        b'(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=scanner)(HOST=__scanner__)(USER=scanner)))'
        b'))'
    )
    ns_pkt = b'\x01' + struct.pack('>H', len(connect_data)) + connect_data
    tns_len = len(ns_pkt) + 8
    tns = struct.pack('>H', tns_len)
    tns += struct.pack('>H', 0)
    tns += b'\x01'
    tns += b'\x00'
    tns += struct.pack('>H', 0)
    tns += ns_pkt
    return tns
