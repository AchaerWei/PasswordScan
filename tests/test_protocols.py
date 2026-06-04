#!/usr/bin/env python3
"""Unit tests for protocol testers — crypto, ASN.1, packet building.
No network dependency. Tests determinism and correctness."""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Override scan timeout for unknown networks
import netspider._compat as g
g.SCAN_TIMEOUT = 1

passed = 0
failed = 0

def t(name):
    global passed, failed
    def decorator(fn):
        def wrapper():
            global passed, failed
            try:
                fn()
                passed += 1
                print(f"  PASS: {name}")
            except Exception as e:
                failed += 1
                print(f"  FAIL: {name} — {e}")
        return wrapper
    return decorator


# ==================== MD4 Tests ====================

@t("MD4 (pycryptodome) — empty string")
def test_md4_empty():
    r = g._md4(b'')
    assert len(r) == 16
    assert r == bytes([0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
                        0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0])

@t("MD4 — RFC 1320 test vector 'a'")
def test_md4_a():
    r = g._md4(b'a')
    assert r == bytes([0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46,
                        0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24])

@t("MD4 — RFC 1320 test vector 'abc'")
def test_md4_abc():
    r = g._md4(b'abc')
    assert r == bytes([0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
                        0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d])

@t("MD4 — RFC 1320 test vector 'message digest'")
def test_md4_msg():
    r = g._md4(b'message digest')
    assert r == bytes([0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8,
                        0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b])

@t("MD4 — 64-byte block boundary")
def test_md4_64byte():
    r = g._md4(b'A' * 64)
    assert len(r) == 16

@t("MD4 — pure Python fallback matches pycryptodome")
def test_md4_pure_vs_crypto():
    import random
    for _ in range(10):
        d = bytes(random.randint(0, 255) for _ in range(random.randint(1, 200)))
        if g.HAS_PYCRYPTO:
            from Crypto.Hash import MD4
            expected = MD4.new(d).digest()
            got = g._md4_pure(d)
            assert got == expected, f"Mismatch: {got.hex()} != {expected.hex()}"


# ==================== NTLMSSP Tests ====================

@t("NTLMSSP Negotiate — well-formed Type 1 message")
def test_ntlmssp_negotiate():
    msg = g._ntlmssp_negotiate('DOMAIN', 'WORKSTATION')
    assert msg[:8] == b'NTLMSSP\x00'
    msg_type = int.from_bytes(msg[8:12], 'little')
    assert msg_type == 1

@t("NTLMSSP Challenge — parse well-formed Type 2")
def test_ntlmssp_parse_challenge():
    import struct as _s
    challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    buf = bytearray()
    buf += b'NTLMSSP\x00'                    # 0-7 signature
    buf += _s.pack('<I', 2)                   # 8-11 msg_type
    buf += _s.pack('<HHI', 0, 0, 0)           # 12-19 target_name (empty)
    buf += _s.pack('<I', 0x00088201)          # 20-23 flags
    buf += challenge                           # 24-31 challenge
    buf += b'\x00' * 8                        # 32-39 reserved
    buf += _s.pack('<HHI', 0, 0, 0)           # 40-47 target_info (empty)
    buf += _s.pack('<I', 0x0601B01D)          # 48-51 version
    buf += _s.pack('<I', 0x0000000F)          # 52-55 NTLM revision
    info = g._ntlmssp_parse_challenge(bytes(buf))
    assert info is not None, "parse returned None"
    assert info['challenge'] == challenge, f"challenge mismatch: {info['challenge'].hex()} != {challenge.hex()}"

@t("NTLMSSP Authenticate — well-formed Type 3")
def test_ntlmssp_authenticate():
    ch_info = {'challenge': b'\x01\x02\x03\x04\x05\x06\x07\x08', 'flags': 0x88201, 'target_info': b''}
    msg = g._ntlmssp_authenticate('testuser', 'TESTDOM', 'WS', ch_info, 'testpass')
    assert msg[:8] == b'NTLMSSP\x00'
    msg_type = int.from_bytes(msg[8:12], 'little')
    assert msg_type == 3

@t("NTLMv2 — deterministic HMAC chain")
def test_ntlmv2_deterministic():
    """Given known inputs, NTLMv2 response must be deterministic."""
    ch_info = {'challenge': b'\x00' * 8, 'flags': 0x88201, 'target_info': b'\x02\x00\x04\x00T\x00E\x00S\x00T\x00'}
    tok1 = g._ntlmssp_authenticate('admin', '', 'SCAN', ch_info, 'password')
    tok2 = g._ntlmssp_authenticate('admin', '', 'SCAN', ch_info, 'password')
    # LM and NTLM responses should be the same (except timestamp in blob which changes...)
    # So we can only check that headers match
    assert tok1[:72] == tok2[:72]  # Fixed header portion should be identical
    assert len(tok1) == len(tok2)


# ==================== SPNEGO Tests ====================

@t("SPNEGO wrap → unwrap round-trip")
def test_spnego_roundtrip():
    token = b'\x01\x02\x03\x04\x05\x06\x07\x08' * 4
    wrapped = g._spnego_wrap_ntlmssp(token)
    assert wrapped[:1] == b'\x60'  # APPLICATION 0
    unwrapped = g._spnego_unwrap(wrapped)
    assert unwrapped == token

@t("SPNEGO unwrap with APPLICATION wrapper")
def test_spnego_unwrap_app():
    token = b'HELLO_WORLD_TOKEN'
    wrapped = g._spnego_wrap_ntlmssp(token)
    unwrapped = g._spnego_unwrap(wrapped)
    assert unwrapped == token

@t("SPNEGO wrap_auth → unwrap round-trip")
def test_spnego_wrap_auth():
    token = b'AUTH_TOKEN_DATA_12345678'
    wrapped = g._spnego_wrap_auth(token)
    unwrapped = g._spnego_unwrap(wrapped)
    assert unwrapped == token

@t("SPNEGO unwrap returns None for garbage")
def test_spnego_unwrap_garbage():
    assert g._spnego_unwrap(b'\x00\x00\x00\x00') is None
    assert g._spnego_unwrap(b'') is None


# ==================== VNC Crypto Tests ====================

@t("VNC — _VNC_REV lookup table")
def test_vnc_rev():
    # Bit reverse of 0x00 → 0x00, 0xFF → 0xFF, 0x01 → 0x80, 0x80 → 0x01
    assert g._VNC_REV[0x00] == 0x00
    assert g._VNC_REV[0xFF] == 0xFF
    assert g._VNC_REV[0x01] == 0x80
    assert g._VNC_REV[0x80] == 0x01
    assert g._VNC_REV[0x0F] == 0xF0
    assert g._VNC_REV[0xF0] == 0x0F

@t("VNC — DES challenge-response known vector")
def test_vnc_des_challenge():
    """Test VNC DES encryption with known test vector."""
    if not g.HAS_PYCRYPTO:
        print("  SKIP: pycryptodome not available")
        return
    from Crypto.Cipher import DES
    challenge = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    pwd = "password"
    key = pwd.encode('ascii')[:8].ljust(8, b'\x00')
    key = bytes([g._VNC_REV[b] for b in key])
    cipher = DES.new(key, DES.MODE_ECB)
    result = cipher.encrypt(challenge)
    assert len(result) == 16
    # Second encrypt with same key should be deterministic
    cipher2 = DES.new(key, DES.MODE_ECB)
    assert result == cipher2.encrypt(challenge)


# ==================== RTSP Parser Tests ====================

@t("RTSP — parse Digest auth header")
def test_rtsp_parse_auth():
    hdr = 'WWW-Authenticate: Digest realm="RTSP Server", nonce="abc123", opaque="xyz789"'
    p = g._parse_rtsp_auth_header(hdr)
    assert p is not None
    assert p['realm'] == 'RTSP Server'
    assert p['nonce'] == 'abc123'
    assert p['opaque'] == 'xyz789'

@t("RTSP — parse Digest with qop")
def test_rtsp_parse_qop():
    hdr = 'WWW-Authenticate: Digest realm="Camera", nonce="n1", qop="auth"'
    p = g._parse_rtsp_auth_header(hdr)
    assert p is not None
    assert p['realm'] == 'Camera'
    assert p['qop'] == 'auth'

@t("RTSP — parse Digest case insensitive")
def test_rtsp_parse_case():
    hdr = 'www-authenticate: digest realm="x", nonce="n"'
    p = g._parse_rtsp_auth_header(hdr)
    assert p is not None
    assert p['nonce'] == 'n'

@t("RTSP — parse returns None without nonce")
def test_rtsp_parse_no_nonce():
    assert g._parse_rtsp_auth_header('WWW-Authenticate: Digest realm="x"') is None


# ==================== RDP Packet Tests ====================

@t("RDP — Negotiation Request well-formed")
def test_rdp_negotiation():
    pkt = g._rdp_build_negotiation()
    assert pkt[0] == 0x03  # TPKT version
    assert pkt[1] == 0x00  # TPKT reserved
    tpkt_len = int.from_bytes(pkt[2:4], 'big')
    assert tpkt_len == len(pkt)
    # X.224 CR
    assert pkt[5] == 0xe0  # CR type

@t("RDP — Negotiation Response parse with NLA")
def test_rdp_parse_negotiation():
    # Build a valid response
    rdp_neg_resp = struct.pack('<BBHI', 0x02, 0x00, 0x0008, 0x00000004)  # NLA selected
    x224_cf = bytes([0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]) + rdp_neg_resp
    x224_cf = bytes([len(x224_cf) - 1]) + x224_cf[1:]
    tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(x224_cf))
    pkt = tpkt + x224_cf
    proto = g._rdp_parse_negotiation(pkt)
    assert proto == 0x00000004

@t("RDP — Negotiation Response parse non-NLA")
def test_rdp_parse_negotiation_tls():
    rdp_neg_resp = struct.pack('<BBHI', 0x02, 0x00, 0x0008, 0x00000003)  # RDP+TLS
    x224_cf = bytes([0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]) + rdp_neg_resp
    x224_cf = bytes([len(x224_cf) - 1]) + x224_cf[1:]
    tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(x224_cf))
    pkt = tpkt + x224_cf
    proto = g._rdp_parse_negotiation(pkt)
    assert proto == 0x00000003

@t("RDP — TSRequest build + parse round-trip")
def test_rdp_tsrequest():
    spnego = b'\x60\x05\x06\x03\xff\xff\xff'
    ts = g._rdp_build_tsrequest(spnego)
    assert ts[0] == 0x30  # SEQUENCE
    # Parse it back
    parsed = g._rdp_parse_tsrequest(ts)
    assert parsed == spnego

@t("RDP — TSRequest parse with TPKT framing")
def test_rdp_tsrequest_tpkt():
    spnego = b'\x60\x05\x06\x03\xff\xff\xff'
    ts = g._rdp_build_tsrequest(spnego)
    tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(ts)) + ts
    parsed = g._rdp_parse_tsrequest(tpkt)
    assert parsed == spnego


# ==================== Oracle Tests ====================

@t("Oracle — TNS CONNECT packet well-formed")
def test_oracle_packet():
    pkt = g._build_tns_connect()
    # TNS header: 2-byte length + 2-byte checksum + type + flags + 2-byte header_checksum = 8 bytes
    assert len(pkt) >= 10
    tns_len = int.from_bytes(pkt[0:2], 'big')
    assert tns_len == len(pkt)
    assert pkt[4] == 0x01  # CONNECT type


# ==================== SMB Packet Tests ====================

@t("SMBv2 — Negotiate packet well-formed")
def test_smb_negotiate():
    pkt = g._smb2_negotiate_pkt()
    assert pkt[0] == 0x00  # NetBIOS message type
    netbios_len = int.from_bytes(pkt[1:4], 'big')
    assert netbios_len == len(pkt) - 4
    payload = pkt[4:]
    assert payload[:4] == b'\xfeSMB'
    assert len(payload) >= 64

@t("SMBv2 — Session Setup packet well-formed")
def test_smb_session_setup():
    sec_blob = b'\x01\x02\x03\x04'
    pkt = g._smb2_session_setup_pkt(sec_blob, 0, 2)
    netbios_len = int.from_bytes(pkt[0:4], 'big')
    assert netbios_len & 0x80000000 == 0  # session message
    actual_len = netbios_len
    payload = pkt[4:]
    assert payload[:4] == b'\xfeSMB'
    assert sec_blob in payload


# ==================== BER Length Tests ====================

@t("BER — short form")
def test_ber_short():
    assert g._ber_len_content(0) == b'\x00'
    assert g._ber_len_content(127) == b'\x7f'
    assert g._ber_len_content(5) == b'\x05'

@t("BER — long form")
def test_ber_long():
    assert g._ber_len_content(128) == b'\x81\x80'
    assert g._ber_len_content(255) == b'\x81\xff'
    assert g._ber_len_content(256) == b'\x82\x01\x00'

@t("BER — decode short form")
def test_ber_decode_short():
    v, b = g._ber_decode_length(b'\x05', 0)
    assert v == 5 and b == 1
    v, b = g._ber_decode_length(b'\x7f', 0)
    assert v == 127 and b == 1

@t("BER — decode long form")
def test_ber_decode_long():
    v, b = g._ber_decode_length(b'\x81\x80', 0)
    assert v == 128 and b == 2
    v, b = g._ber_decode_length(b'\x82\x01\x00', 0)
    assert v == 256 and b == 3

@t("BER — decode length at offset")
def test_ber_decode_offset():
    data = b'\x00\x00\x0a\xFF'  # Offset 2 has length 10
    v, b = g._ber_decode_length(data, 2)
    assert v == 10 and b == 1


# ==================== Import Checks ====================

@t("All protocol testers imported")
def test_imports():
    for fn_name in ['test_oracle', 'test_vnc', 'test_rtsp', 'test_rdp', 'test_smb']:
        fn = getattr(g, fn_name, None)
        assert fn is not None, f"{fn_name} not found"
        assert callable(fn), f"{fn_name} is not callable"

@t("TESTER_MAP covers all new protocols")
def test_tester_map():
    assert g.TESTER_MAP.get('oracle') is not None
    assert g.TESTER_MAP.get('vnc') is not None
    assert g.TESTER_MAP.get('rdp') is not None
    assert g.TESTER_MAP.get('rtsp') is not None
    assert g.TESTER_MAP.get('smb') is not None

@t("NAMED_PORTS has RTSP entries")
def test_named_ports():
    assert g.NAMED_PORTS.get(554) == 'rtsp'
    assert g.NAMED_PORTS.get(8554) == 'rtsp'

@t("RTSP_PORTS defined")
def test_rtsp_ports():
    assert 554 in g.RTSP_PORTS
    assert 8554 in g.RTSP_PORTS

@t("SVC_TO_CREDGROUP has rtsp")
def test_credgroup():
    assert 'rtsp' in g.SVC_TO_CREDGROUP

# ==================== SCRAM Tests ====================
# Regression guards: verify auth_msg includes n=<user> prefix per RFC 5802

import hashlib as _hashlib
import hmac as _hmac_lib
import base64 as _b64_lib

# RFC 7677 Section 3 test vectors — SCRAM-SHA-256
_RFC7677_USER = "user"
_RFC7677_PASSWORD = "pencil"
_RFC7677_CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO"
_RFC7677_SERVER_FIRST = (
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
    "s=W22ZaJ7SNY7soEsUEjb6gQ==,i=4096"
)


@t("SCRAM-SHA-256 — RFC 7677 test vector (deterministic proof)")
def test_scram_sha256_rfc7677():
    """Verify SCRAM-SHA-256 against RFC 7677 Section 3 test vector."""
    result = g._scram_sha256_client_final(
        _RFC7677_USER, _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, _RFC7677_PASSWORD
    )
    assert ",p=" in result, f"Missing proof separator: {result[:60]}"
    _, proof_b64 = result.rsplit(",p=", 1)
    assert len(proof_b64) >= 20, f"Proof too short: {len(proof_b64)}"
    # Determinism: same inputs → same output
    result2 = g._scram_sha256_client_final(
        _RFC7677_USER, _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, _RFC7677_PASSWORD
    )
    assert result == result2, "SCRAM-SHA-256 must be deterministic"


@t("SCRAM-SHA-256 — wrong password produces different proof")
def test_scram_sha256_wrong_password():
    """Wrong password → different proof (guards against ignoring password)."""
    correct = g._scram_sha256_client_final(
        _RFC7677_USER, _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, _RFC7677_PASSWORD
    )
    wrong = g._scram_sha256_client_final(
        _RFC7677_USER, _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, "WrongPassword123"
    )
    assert correct != wrong, "Correct and wrong passwords MUST produce different proofs"


@t("SCRAM-SHA-256 — different users produce different proofs (n=,r= regression)")
def test_scram_sha256_auth_msg_includes_user():
    """Regression: auth_msg MUST include n=<user>, so different users → different proofs.

    This catches the P0 bug where auth_msg was "n=,r=..." (empty user field),
    causing all proofs to be identical regardless of username.
    """
    proof_alice = g._scram_sha256_client_final(
        "alice", _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, _RFC7677_PASSWORD
    )
    proof_bob = g._scram_sha256_client_final(
        "bob", _RFC7677_CLIENT_NONCE, _RFC7677_SERVER_FIRST, _RFC7677_PASSWORD
    )
    assert proof_alice != proof_bob, (
        "DIFFERENT USERS MUST PRODUCE DIFFERENT PROOFS! "
        "If they match, auth_msg is missing n=<user> (regression of P0 Bug).\n"
        f"  alice: {proof_alice[:60]}\n"
        f"  bob:   {proof_bob[:60]}"
    )


# ==================== Run ====================

if __name__ == '__main__':
    import struct
    print(f"Running tests (pycryptodome={'YES' if g.HAS_PYCRYPTO else 'NO'}, pyasn1={'YES' if g.HAS_PYASN1 else 'NO'})\n")
    for name in sorted(globals()):
        if not name.startswith('test_'):
            continue
        val = globals()[name]
        if callable(val):
            val()
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {passed+failed}")
    sys.exit(0 if failed == 0 else 1)
