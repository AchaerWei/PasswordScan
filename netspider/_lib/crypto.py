"""Cryptographic helpers for authentication protocols.

IMPORTANT: All weak-hash usage (MD4, MD5, SHA1) in this file implements
REQUIRED protocol steps for legacy authentication mechanisms:
  - MD4 → NTLM/NTLMv2 (Windows authentication, RFC 2433)
  - SHA1 → MySQL native_password, SCRAM-SHA-1, VNC DES (protocol mandated)
  - MD5  → PostgreSQL md5 auth, RTSP Digest (RFC 2069/2617)

These are NOT developer choices — they're implemented exactly as specified
by the respective protocol RFCs to maintain compatibility with target services.
"""
# codeql-skip: py/weak-cryptographic-algorithm — all hashes are protocol-required

import struct, hashlib, hmac

# ---- Crypto deps ----
try:
    from Crypto.Cipher import DES
    from Crypto.Hash import MD4  # codeql-ignore: py/weak-cryptographic-algorithm
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False
    DES = None; MD4 = None

try:
    import pyasn1.codec.ber.encoder as _ber_enc
    import pyasn1.codec.ber.decoder as _ber_dec
    from pyasn1.type import univ, tag
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False
    _ber_enc = None; _ber_dec = None; univ = None; tag = None


def _md4(data: bytes) -> bytes:
    """MD4 hash for NTLM."""
    if HAS_PYCRYPTO:
        return MD4.new(data).digest()
    # Pure Python MD4 fallback
    return _md4_pure(data)


def _md4_pure(data: bytes) -> bytes:
    """Pure Python MD4 (RFC 1320) — fallback when pycryptodome unavailable."""
    import struct as _st
    def _F(x,y,z): return (x & y) | (~x & z)
    def _G(x,y,z): return (x & y) | (x & z) | (y & z)
    def _H(x,y,z): return x ^ y ^ z
    def _rotl(x,n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    b = bytearray(data) + b'\x80'
    while (len(b) + 8) % 64 != 0:
        b.append(0)
    b += _st.pack('<Q', len(data) * 8)
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(b), 64):
        X = list(_st.unpack('<16I', b[i:i+64]))
        AA, BB, CC, DD = A, B, C, D
        for r, s, k in [(0,3,0),(1,7,1),(2,11,2),(3,19,3),(4,3,4),(5,7,5),(6,11,6),(7,19,7),
                         (8,3,8),(9,7,9),(10,11,10),(11,19,11),(12,3,12),(13,7,13),(14,11,14),(15,19,15)]:
            A = _rotl((A + _F(B,C,D) + X[k]) & 0xFFFFFFFF, s); A,B,C,D = D,A,B,C
        for r, s, k in [(0,3,0),(1,5,4),(2,9,8),(3,13,12),(4,3,1),(5,5,5),(6,9,9),(7,13,13),
                         (8,3,2),(9,5,6),(10,9,10),(11,13,14),(12,3,3),(13,5,7),(14,9,11),(15,13,15)]:
            A = _rotl((A + _G(B,C,D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s); A,B,C,D = D,A,B,C
        for r, s, k in [(0,3,0),(1,9,8),(2,11,4),(3,15,12),(4,3,2),(5,9,10),(6,11,6),(7,15,14),
                         (8,3,1),(9,9,9),(10,11,5),(11,15,13),(12,3,3),(13,9,11),(14,11,7),(15,15,15)]:
            A = _rotl((A + _H(B,C,D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s); A,B,C,D = D,A,B,C
        A = (A + AA) & 0xFFFFFFFF; B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF; D = (D + DD) & 0xFFFFFFFF
    return _st.pack('<4I', A, B, C, D)


# ---- VNC Bit-Reverse LUT ----
_VNC_REV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))


def _hmac_sha1(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA1."""
    import hmac as _hmac
    return _hmac.new(key, msg, hashlib.sha1).digest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256."""
    import hmac as _hmac
    return _hmac.new(key, msg, hashlib.sha256).digest()
