"""PostgreSQL protocol tester — psycopg2 driver (mandatory since Phase 2)."""
from __future__ import annotations
import struct, hashlib, hmac, os
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, FindingType, _set_finding_type

import psycopg2


def test_postgresql(ip: str, port: int, user: str, pwd: str) -> bool:
    """PostgreSQL auth via psycopg2 driver.

    Replaces the hand-written MD5/SCRAM-SHA-256 implementation with
    the mature psycopg2 driver, eliminating the SCRAM auth_msg bug
    class permanently.
    """
    return _test_postgresql_psycopg2(ip, port, user, pwd)


def _test_postgresql_psycopg2(ip: str, port: int, user: str, pwd: str) -> bool:
    """PostgreSQL auth via psycopg2 — handles MD5, SCRAM, no-auth, cert."""
    try:
        conn = psycopg2.connect(
            host=ip, port=port, user=user, password=pwd,
            dbname='postgres', connect_timeout=SCAN_TIMEOUT,
        )
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        msg = str(e).lower()
        psql_state = getattr(e, 'pgcode', '') or ''
        if psql_state == '28P01':
            return False
        if 'password' in msg or 'authentication failed' in msg:
            return False
        if 'no password' in msg or 'trust' in msg:
            _set_finding_type(FindingType.NO_AUTH)
            return True
        if 'could not connect' in msg or 'connection refused' in msg:
            raise NetworkError() from None
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _pg_scram_sha256(sock, user, pwd, _pg_recv) -> bool:
    """Legacy PostgreSQL SCRAM-SHA-256 — kept for unit-test access to SCRAM.

    Note: this hand-written implementation is no longer called by
    test_postgresql() which uses psycopg2 instead. It remains available
    for the test suite to verify SCRAM crypto determinism.
    """
    import base64 as _b64

    client_nonce = _b64.b64encode(os.urandom(24)).decode('ascii')[:32]
    client_first = f"n,,n={user},r={client_nonce}"

    mech = b'SCRAM-SHA-256\x00'
    init_data = struct.pack('>I', len(mech) + len(client_first) + 4)
    sasl_init = init_data + mech + client_first.encode()
    pw_msg = struct.pack('>I', len(sasl_init) + 4) + bytes([ord('p')]) + sasl_init
    sock.send(pw_msg)

    resp = _pg_recv()
    if len(resp) < 9 or resp[0] != ord('R'):
        return False
    auth_type = struct.unpack('>I', resp[5:9])[0]
    if auth_type != 11:
        return False

    server_first = resp[9:].decode('utf-8', errors='ignore').rstrip('\x00')
    parts = {}
    for p in server_first.split(','):
        if '=' in p:
            k, v = p.split('=', 1)
            parts[k] = v
    combined_nonce = parts.get('r', '')
    salt_b64 = parts.get('s', '')
    iterations = int(parts.get('i', '4096'))

    if not combined_nonce.startswith(client_nonce):
        return False

    salt = _b64.b64decode(salt_b64)
    salted_pw = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, iterations, 32)

    client_key = hmac.new(salted_pw, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()

    c_final_no_proof = "c=biws,r=" + combined_nonce
    auth_msg = f"n={user},r={client_nonce}," + server_first + "," + c_final_no_proof

    client_sig = hmac.new(stored_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    proof_b64 = _b64.b64encode(proof).decode('ascii')

    client_final = c_final_no_proof + ",p=" + proof_b64

    pw_resp = struct.pack('>I', len(client_final) + 4)
    pw_msg2 = pw_resp + client_final.encode()
    pw_pkt = struct.pack('>I', len(pw_msg2) + 4) + bytes([ord('p')]) + pw_msg2
    sock.send(pw_pkt)

    resp = _pg_recv()
    if len(resp) < 9 or resp[0] != ord('R'):
        return False

    final_auth_type = struct.unpack('>I', resp[5:9])[0]
    if final_auth_type == 0:
        return True
    if final_auth_type == 12:
        server_final = resp[9:].decode('utf-8', errors='ignore').rstrip('\x00')
        sfinal = {}
        for p in server_final.split(','):
            if '=' in p:
                k, v = p.split('=', 1)
                sfinal[k] = v
        server_sig_b64 = sfinal.get('v', '')
        server_key = hmac.new(salted_pw, b'Server Key', hashlib.sha256).digest()
        expected_sig = hmac.new(server_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
        expected_b64 = _b64.b64encode(expected_sig).decode('ascii')
        return server_sig_b64 == expected_b64

    return False
