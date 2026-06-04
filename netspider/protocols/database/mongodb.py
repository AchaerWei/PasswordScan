"""MongoDB protocol tester — pymongo driver (mandatory since Phase 2)."""
from __future__ import annotations
import socket, struct, hashlib, hmac, os
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, FindingType, _set_finding_type
from netspider._lib.crypto import _hmac_sha1, _hmac_sha256

import pymongo


def test_mongodb(ip: str, port: int, user: str, pwd: str) -> bool:
    """MongoDB auth via pymongo driver (mandatory since Phase 2).

    Eliminates the hand-written SCRAM-SHA-256/SHA-1 fallback that
    had the auth_msg n={user} bug class.
    """
    return _test_mongodb_pymongo(ip, port, user, pwd)


# ---- MongoDB Wire Protocol Helpers ----

def _mongo_build_hello() -> bytes:
    """Build a MongoDB 'hello' command as OP_MSG."""
    doc = _bson_encode_doc([('hello', 1), ('$db', 'admin')])
    section = bytes([0]) + doc
    body = struct.pack('<I', 0) + section
    return struct.pack('<IIII', 16 + len(body), 1, 0, 2013) + body


def _mongo_build_sasl_start(payload_b64: str, mechanism: str = 'SCRAM-SHA-1') -> bytes:
    doc = _bson_encode_doc([
        ('saslStart', 1),
        ('mechanism', mechanism),
        ('payload', payload_b64),
        ('$db', 'admin'),
    ])
    section = bytes([0]) + doc
    body = struct.pack('<I', 0) + section
    return struct.pack('<IIII', 16 + len(body), 2, 0, 2013) + body


def _mongo_build_sasl_continue(conv_id: int, payload_b64: str) -> bytes:
    doc = _bson_encode_doc([
        ('saslContinue', 1),
        ('conversationId', conv_id),
        ('payload', payload_b64),
        ('$db', 'admin'),
    ])
    section = bytes([0]) + doc
    body = struct.pack('<I', 0) + section
    return struct.pack('<IIII', 16 + len(body), 3, 0, 2013) + body


def _mongo_parse_reply(data: bytes) -> tuple[int, bytes]:
    if len(data) < 22:
        return 0, data
    flags = struct.unpack('<I', data[16:20])[0]
    return flags, data[21:]


def _bson_encode_doc(items: list[tuple]) -> bytes:
    """Minimal BSON document encoder."""
    buf = bytearray()
    for key, value in items:
        if type(value) is bool:
            buf += bytes([8]) + key.encode() + bytes([0]) + (bytes([1]) if value else bytes([0]))
        elif isinstance(value, int):
            if -2**31 <= value <= 2**31 - 1:
                buf += bytes([16]) + key.encode() + bytes([0]) + struct.pack('<i', value)
            else:
                buf += bytes([18]) + key.encode() + bytes([0]) + struct.pack('<q', value)
        elif isinstance(value, str):
            val_bytes = value.encode('utf-8')
            buf += bytes([2]) + key.encode() + bytes([0]) + struct.pack('<i', len(val_bytes) + 1) + val_bytes + bytes([0])
        elif isinstance(value, bytes):
            buf += bytes([5]) + key.encode() + bytes([0]) + struct.pack('<i', len(value)) + bytes([0]) + value
        elif value is None:
            buf += bytes([10]) + key.encode() + bytes([0])
    result = bytes(buf) + bytes([0])
    return struct.pack('<i', len(result) + 4) + result


def _bson_find_field(data: bytes, name: str) -> tuple | None:
    if len(data) < 5:
        return None
    pos = 4
    while pos < len(data) - 1:
        t = data[pos]
        if t == 0:
            break
        pos += 1
        end = data.index(b'\x00', pos)
        fname = data[pos:end].decode('utf-8', errors='ignore')
        pos = end + 1
        if t == 1:
            if fname == name:
                return (t, data[pos:pos + 8])
            pos += 8
        elif t == 2:
            slen = struct.unpack('<i', data[pos:pos + 4])[0]
            val = data[pos + 4:pos + 4 + slen - 1]
            if fname == name:
                return (t, val)
            pos += 4 + slen
        elif t == 4:
            dlen = struct.unpack('<i', data[pos:pos + 4])[0]
            if fname == name:
                return (t, data[pos:pos + dlen])
            pos += dlen
        elif t == 3:
            dlen = struct.unpack('<i', data[pos:pos + 4])[0]
            if fname == name:
                return (t, data[pos:pos + dlen])
            pos += dlen
        elif t == 5:
            blen = struct.unpack('<i', data[pos:pos + 4])[0]
            subtype = data[pos + 4]
            val = data[pos + 5:pos + 5 + blen]
            if fname == name:
                return (t, val)
            pos += 5 + blen
        elif t == 8:
            if fname == name:
                return (t, data[pos:pos + 1])
            pos += 1
        elif t == 10:
            if fname == name:
                return (t, b'')
        elif t == 16:
            if fname == name:
                return (t, data[pos:pos + 4])
            pos += 4
        elif t == 18:
            if fname == name:
                return (t, data[pos:pos + 8])
            pos += 8
        else:
            break
    return None


def _bson_get_string(data: bytes, name: str) -> str | None:
    r = _bson_find_field(data, name)
    if r and r[0] in (2, 5):
        val = r[1]
        return val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else str(val)
    return None


def _bson_get_int32(data: bytes, name: str) -> int | None:
    r = _bson_find_field(data, name)
    if r and r[0] == 16 and len(r[1]) >= 4:
        return struct.unpack('<i', r[1][:4])[0]
    return None


def _bson_get_bool(data: bytes, name: str) -> bool:
    r = _bson_find_field(data, name)
    if r and r[0] == 8 and len(r[1]) >= 1:
        return r[1][0] == 1
    return False


def _bson_get_doc(data: bytes, name: str) -> bytes | None:
    r = _bson_find_field(data, name)
    if r and r[0] in (3, 4):
        return r[1]
    return None


# ---- SCRAM-SHA-1 Helpers ----

def _scram_sha1_client_first(user: str) -> tuple[str, str]:
    import base64 as _b64
    client_nonce = _b64.b64encode(os.urandom(18)).decode('ascii')[:24]
    gs2 = "n,,n=" + user + ",r=" + client_nonce
    return gs2, client_nonce


def _scram_sha1_client_final(user: str, client_nonce: str, server_first: str, password: str) -> str:
    import base64 as _b64
    parts = {}
    for p in server_first.split(','):
        if p and '=' in p:
            k, v = p.split('=', 1)
            parts[k] = v
    combined_nonce = parts.get('r', '')
    salt_b64 = parts.get('s', '')
    iterations = int(parts.get('i', '4096'))

    salt = _b64.b64decode(salt_b64)
    salted_pw = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, 20)

    client_key = _hmac_sha1(salted_pw, b"Client Key")
    stored_key = hashlib.sha1(client_key).digest()

    c_final_no_proof = "c=biws,r=" + combined_nonce
    auth_msg = "n=" + user + ",r=" + client_nonce + "," + server_first + "," + c_final_no_proof

    client_sig = _hmac_sha1(stored_key, auth_msg.encode('utf-8'))
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    proof_b64 = _b64.b64encode(proof).decode('ascii')

    return c_final_no_proof + ",p=" + proof_b64


def _scram_verify_server_final(server_final: str, auth_msg: str, salted_pw: bytes) -> bool:
    import base64 as _b64
    parts = {}
    for p in server_final.split(','):
        if p and '=' in p:
            k, v = p.split('=', 1)
            parts[k] = v
    server_sig_b64 = parts.get('v', '')

    server_key = _hmac_sha1(salted_pw, b"Server Key")
    expected_sig = _hmac_sha1(server_key, auth_msg.encode('utf-8'))
    expected_b64 = _b64.b64encode(expected_sig).decode('ascii')
    return server_sig_b64 == expected_b64


# ---- SCRAM-SHA-256 Helpers ----

def _scram_sha256_client_first(user: str) -> tuple[str, str]:
    import base64 as _b64
    client_nonce = _b64.b64encode(os.urandom(24)).decode('ascii')[:32]
    gs2 = "n,,n=" + user + ",r=" + client_nonce
    return gs2, client_nonce


def _scram_sha256_client_final(user: str, client_nonce: str, server_first: str, password: str) -> str:
    import base64 as _b64
    parts = {}
    for p in server_first.split(','):
        if p and '=' in p:
            k, v = p.split('=', 1)
            parts[k] = v
    combined_nonce = parts.get('r', '')
    salt_b64 = parts.get('s', '')
    iterations = int(parts.get('i', '4096'))

    salt = _b64.b64decode(salt_b64)
    salted_pw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)

    client_key = _hmac_sha256(salted_pw, b"Client Key")
    stored_key = hashlib.sha256(client_key).digest()

    c_final_no_proof = "c=biws,r=" + combined_nonce
    auth_msg = "n=" + user + ",r=" + client_nonce + "," + server_first + "," + c_final_no_proof

    client_sig = _hmac_sha256(stored_key, auth_msg.encode('utf-8'))
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    proof_b64 = _b64.b64encode(proof).decode('ascii')

    return c_final_no_proof + ",p=" + proof_b64


def _scram_sha256_verify_server_final(server_final: str, auth_msg: str, salted_pw: bytes) -> bool:
    import base64 as _b64
    parts = {}
    for p in server_final.split(','):
        if p and '=' in p:
            k, v = p.split('=', 1)
            parts[k] = v
    server_sig_b64 = parts.get('v', '')
    server_key = _hmac_sha256(salted_pw, b"Server Key")
    expected_sig = _hmac_sha256(server_key, auth_msg.encode('utf-8'))
    expected_b64 = _b64.b64encode(expected_sig).decode('ascii')
    return server_sig_b64 == expected_b64


def _test_mongodb_scram(ip: str, port: int, user: str, pwd: str,
                         mechanism: str = 'SCRAM-SHA-1') -> bool:
    """Legacy MongoDB SCRAM wrapper — always delegates to pymongo (Phase 2)."""
    return _test_mongodb_pymongo(ip, port, user, pwd)


def _test_mongodb_noauth_check(ip: str, port: int) -> bool:
    """Check if MongoDB has no authentication configured."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(3.0)
        doc = _bson_encode_doc([('hello', 1), ('$db', 'admin')])
        section = bytes([0]) + doc
        body = struct.pack('<I', 0) + section
        pkt = struct.pack('<IIII', 16 + len(body), 1, 0, 2013) + body
        sock.send(pkt)
        resp = sock.recv(4096)
        sock.close()
        if len(resp) >= 20:
            _, doc = _mongo_parse_reply(resp)
            ok = _bson_get_int32(doc, 'ok')
            if ok == 1:
                _set_finding_type(FindingType.NO_AUTH)
                return True
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _test_mongodb_pymongo(ip: str, port: int, user: str, pwd: str) -> bool:
    try:
        if not user and not pwd:
            client = pymongo.MongoClient(
                host=ip, port=port,
                serverSelectionTimeoutMS=SCAN_TIMEOUT * 1000,
                connectTimeoutMS=SCAN_TIMEOUT * 1000,
            )
            client.admin.command('ping')
            client.close()
            _set_finding_type(FindingType.NO_AUTH)
            return True

        client = pymongo.MongoClient(
            host=ip, port=port, username=user, password=pwd,
            authSource='admin', serverSelectionTimeoutMS=SCAN_TIMEOUT * 1000,
            connectTimeoutMS=SCAN_TIMEOUT * 1000,
        )
        client.admin.command('ping')
        client.close()
        return True
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
