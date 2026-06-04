"""NTLMSSP authentication protocol helpers.

MD5/MD4 usage here implements NTLMv2 as specified by MS-NLMP —
these are protocol-mandated algorithms, not developer choices.
"""
# codeql-skip: py/weak-cryptographic-algorithm

import os, struct, time, hashlib, hmac
from netspider._lib.crypto import _md4


def _ntlmssp_negotiate(domain: str = "", workstation: str = "") -> bytes:
    """Build NTLMSSP Type 1 (Negotiate) message."""
    sig = b'NTLMSSP\x00'
    msg_type = struct.pack('<I', 1)
    flags = 0x00088207
    dom = domain.encode('utf-16le') if domain else b''
    ws = workstation.encode('utf-16le') if workstation else b''
    dom_off = 32
    ws_off = dom_off + len(dom)
    hdr = (sig + msg_type +
           struct.pack('<HH', len(dom), len(dom)) + struct.pack('<I', dom_off) +
           struct.pack('<HH', len(ws), len(ws)) + struct.pack('<I', ws_off) +
           struct.pack('<I', flags))
    hdr += b'\x00' * (dom_off - len(hdr))
    return hdr + dom + ws


def _ntlmssp_parse_challenge(data: bytes) -> dict | None:
    """Parse NTLMSSP Type 2 (Challenge) message."""
    if len(data) < 32 or data[:8] != b'NTLMSSP\x00':
        return None
    msg_type = struct.unpack('<I', data[8:12])[0]
    if msg_type != 2:
        return None
    challenge = data[24:32]
    if len(challenge) < 8:
        return None
    flags = struct.unpack('<I', data[20:24])[0]
    ti = b''
    if len(data) >= 48:
        ti_len = struct.unpack('<H', data[40:42])[0]
        ti_off = struct.unpack('<I', data[44:48])[0]
        if ti_off > 0 and ti_off + ti_len <= len(data):
            ti = data[ti_off:ti_off + ti_len]
    return {'challenge': challenge, 'flags': flags, 'target_info': ti}


def _ntlmssp_authenticate(user: str, domain: str, ws: str,
                          ch_info: dict, password: str) -> bytes:
    """Build NTLMSSP Type 3 (Authenticate) with NTLMv2 response."""
    from hmac import new as _hmac_new
    server_challenge = ch_info.get('challenge', b'\x00' * 8)
    target_info = ch_info.get('target_info', b'')
    nt_hash = _md4(password.encode('utf-16le'))
    user_up = user.upper().encode('utf-16le')
    dom_up = domain.upper().encode('utf-16le') if domain else b''
    ntlm_v2_hash = _hmac_new(nt_hash, user_up + dom_up, hashlib.md5).digest()
    client_nonce = os.urandom(8)
    epoch_diff = 11644473600
    now_ft = int((time.time() + epoch_diff) * 10000000)
    blob = (struct.pack('<IIQ', 0x01010000, 0, now_ft) + client_nonce +
            struct.pack('<I', 0) + target_info + struct.pack('<I', 0))
    nt_proof = _hmac_new(ntlm_v2_hash, server_challenge + blob, hashlib.md5).digest()
    ntlmv2_resp = nt_proof + blob
    lmv2 = _hmac_new(ntlm_v2_hash, server_challenge + client_nonce, hashlib.md5).digest()
    lm_resp = lmv2 + client_nonce
    user_b = user.encode('utf-16le')
    dom_b = domain.encode('utf-16le') if domain else b''
    ws_b = ws.encode('utf-16le') if ws else b''
    sig = b'NTLMSSP\x00'
    mt = struct.pack('<I', 3)
    body_off = 72
    offsets = {}
    payload = b''
    for name, data in [('lm', lm_resp), ('ntlm', ntlmv2_resp), ('dom', dom_b),
                        ('user', user_b), ('ws', ws_b), ('sk', b'')]:
        offsets[name] = body_off + len(payload)
        payload += data
    flags_v = 0x00088201
    fixed = (sig + mt +
             struct.pack('<HH', len(lm_resp), len(lm_resp)) + struct.pack('<I', offsets['lm']) +
             struct.pack('<HH', len(ntlmv2_resp), len(ntlmv2_resp)) + struct.pack('<I', offsets['ntlm']) +
             struct.pack('<HH', len(dom_b), len(dom_b)) + struct.pack('<I', offsets['dom']) +
             struct.pack('<HH', len(user_b), len(user_b)) + struct.pack('<I', offsets['user']) +
             struct.pack('<HH', len(ws_b), len(ws_b)) + struct.pack('<I', offsets['ws']) +
             struct.pack('<HH', 0, 0) + struct.pack('<I', offsets['sk']) +
             struct.pack('<I', flags_v) +
             b'\x06\x01\xb0\x1d\x00\x00\x00\x0f')  # Windows 7 version blob
    while len(fixed) < body_off:
        fixed += b'\x00'
    return fixed + payload
