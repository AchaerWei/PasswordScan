"""MSSQL protocol tester — pymssql driver + raw TDS 7.x fallback."""
from __future__ import annotations
import socket, struct
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError

try:
    import pymssql
    HAS_PYMSSQL = True
except ImportError:
    HAS_PYMSSQL = False
    pymssql = None


def test_mssql(ip: str, port: int, user: str, pwd: str) -> bool:
    """MSSQL TDS login. Uses pymssql if available, else raw TDS 7.x."""
    if HAS_PYMSSQL:
        return _test_mssql_pymssql(ip, port, user, pwd)
    return _test_mssql_raw(ip, port, user, pwd)


def _test_mssql_pymssql(ip: str, port: int, user: str, pwd: str) -> bool:
    try:
        conn = pymssql.connect(server=ip, port=str(port), user=user,
                               password=pwd, login_timeout=SCAN_TIMEOUT,
                               tds_version='7.0')
        conn.close()
        return True
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _test_mssql_raw(ip: str, port: int, user: str, pwd: str) -> bool:
    """Raw TDS 7.x login without TLS. Handles pre-login + login7."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(5.0)

        prelogin = _build_tds_prelogin()
        sock.send(prelogin)
        resp = _recv_tds_packet(sock)
        if not resp or len(resp) < 8 or resp[0] != 0x04:
            sock.close()
            return False

        enc_required = _parse_tds_prelogin_encryption(resp)
        if enc_required:
            sock.close()
            return False

        login7 = _build_tds_login7(user, pwd)
        sock.send(login7)
        resp = _recv_tds_packet(sock)
        sock.close()

        if not resp or len(resp) < 8 or resp[0] != 0x04:
            return False

        data = resp[8:]
        idx = 0
        while idx < len(data):
            token_type = data[idx]
            if token_type == 0xE3:  # LOGINACK
                if idx + 4 <= len(data):
                    ack_result = data[idx + 3]
                    return ack_result == 0
            elif token_type == 0xAA:  # ERROR
                return False
            elif token_type == 0xFD:  # DONE
                idx += 4
                continue
            elif token_type == 0xAB:  # INFO
                idx += 1
                continue
            elif token_type == 0xE5:  # ENVCHANGE
                break
            idx += 1
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _build_tds_prelogin() -> bytes:
    """Build TDS pre-login packet advertising no encryption."""
    import struct as _st
    buf = bytearray()
    buf += bytes([0x01])
    buf += _st.pack('>H', 0)
    buf += _st.pack('>H', 1)
    enc_placeholder_pos = 1
    buf += bytes([0x00])
    buf += _st.pack('>H', 0)
    buf += _st.pack('>H', 6)
    ver_placeholder_pos = 6
    buf += bytes([0xFF])
    enc_offset = len(buf)
    buf += bytes([0x01])
    ver_offset = len(buf)
    buf += _st.pack('>I', 0x74000004) + bytes([0, 0])
    _st.pack_into('>H', buf, enc_placeholder_pos, enc_offset)
    _st.pack_into('>H', buf, ver_placeholder_pos, ver_offset)
    body = bytes(buf)
    header = _st.pack('>B', 0x12) + _st.pack('>B', 0x01) + _st.pack('>H', 8 + len(body)) + _st.pack('>H', 0) + _st.pack('>B', 0) + _st.pack('>B', 0)
    return header + body


def _parse_tds_prelogin_encryption(data: bytes) -> bool:
    """Parse pre-login response and check if ENCRYPTION is required."""
    import struct as _st
    if len(data) < 12:
        return True
    body = data[8:]
    idx = 0
    while idx < len(body) and body[idx] != 0xFF:
        token = body[idx]
        if idx + 5 > len(body):
            break
        offset = _st.unpack('>H', body[idx + 1:idx + 3])[0]
        length = _st.unpack('>H', body[idx + 3:idx + 5])[0]
        if token == 0x01 and length > 0:
            val = body[offset + 5:offset + 5 + length]
            return len(val) > 0 and (val[0] & 0x08) != 0
        idx += 5
    return False


def _build_tds_login7(user: str, pwd: str) -> bytes:
    """Build TDS Login7 packet with obfuscated password."""
    import struct as _st
    pw_ucs2 = pwd.encode('utf-16le')
    pw_obf = bytes(b ^ 0xA5 for b in pw_ucs2)

    var_data = bytearray()
    hostname = b'SCANNER'
    var_data += hostname
    hostname_offset = len(var_data) - len(hostname)
    user_bytes = user.encode('utf-16le')
    var_data += user_bytes
    user_offset = len(var_data) - len(user_bytes)
    var_data += pw_obf
    pw_offset = len(var_data) - len(pw_obf)
    appname = b'WPScanner'
    var_data += appname
    app_offset = len(var_data) - len(appname)
    servername = b''
    var_data += servername
    svr_offset = len(var_data) - len(servername)
    libname = b'ODBC'
    var_data += libname
    lib_offset = len(var_data) - len(libname)
    lang = b''
    var_data += lang
    lang_offset = len(var_data) - len(lang)
    db = b''
    var_data += db
    db_offset = len(var_data) - len(db)
    cid = bytes([1, 2, 3, 4, 5, 6])
    var_data += cid
    cid_offset = len(var_data) - len(cid)
    sspi = b''
    var_data += sspi
    sspi_offset = len(var_data) - len(sspi)
    attach = b''
    var_data += attach
    attach_offset = len(var_data) - len(attach)

    fixed = bytearray()
    fixed += _st.pack('<I', 0x100)
    fixed += _st.pack('<I', 36)
    fixed += _st.pack('<I', len(var_data))
    fixed += _st.pack('<I', 0xE0)
    fixed += _st.pack('<H', hostname_offset)
    fixed += _st.pack('<H', len(hostname))
    fixed += _st.pack('<H', user_offset)
    fixed += _st.pack('<H', len(user_bytes))
    fixed += _st.pack('<H', pw_offset)
    fixed += _st.pack('<H', len(pw_obf))
    fixed += _st.pack('<H', app_offset)
    fixed += _st.pack('<H', len(appname))
    fixed += _st.pack('<H', svr_offset)
    fixed += _st.pack('<H', len(servername))
    fixed += bytes(4)
    fixed += _st.pack('<H', lib_offset)
    fixed += _st.pack('<H', len(libname))
    fixed += _st.pack('<H', lang_offset)
    fixed += _st.pack('<H', len(lang))
    fixed += _st.pack('<H', db_offset)
    fixed += _st.pack('<H', len(db))
    fixed += _st.pack('<H', cid_offset)
    fixed += _st.pack('<H', len(cid))
    fixed += _st.pack('<H', sspi_offset)
    fixed += _st.pack('<H', len(sspi))
    fixed += _st.pack('<H', attach_offset)
    fixed += _st.pack('<H', len(attach))
    fixed += bytes([0]) + _st.pack('<I', 0)

    body = bytes(fixed) + bytes(var_data)
    header = _st.pack('>B', 0x10) + _st.pack('>B', 0x01) + _st.pack('>H', 8 + len(body)) + _st.pack('>H', 0) + _st.pack('>B', 0) + _st.pack('>B', 0)
    return header + body


def _recv_tds_packet(sock: socket.socket) -> bytes:
    """Receive a full TDS packet."""
    try:
        header = sock.recv(8)
        if len(header) < 8:
            return b''
        import struct as _st
        pkt_len = _st.unpack('>H', header[2:4])[0]
        remaining = pkt_len - 8
        data = header
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        return data
    except socket.timeout:
        return b''
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return b''
