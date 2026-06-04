import socket, struct, time
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError
from netspider._lib.ntlm import _ntlmssp_negotiate, _ntlmssp_parse_challenge, _ntlmssp_authenticate


def test_smb(ip: str, port: int, user: str, pwd: str) -> bool:
    """SMB authentication test. Uses impacket if available, else raw SMBv2+NTLMSSP."""
    try:
        import impacket.smbconnection
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(ip, ip, sess_port=port, timeout=SCAN_TIMEOUT)
        conn.login(user, pwd)
        conn.close()
        return True
    except ImportError:
        pass
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        pass
    return _test_smb_v2(ip, port, user, pwd)


def _test_smb_v2(ip: str, port: int, user: str, pwd: str) -> bool:
    """SMBv2 Negotiate + NTLMSSP Session Setup."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(6.0)
        # --- Negotiate ---
        neg_pkt = _smb2_negotiate_pkt()
        sock.send(neg_pkt)
        resp = sock.recv(4096)
        if len(resp) < 68:
            sock.close(); return False
        # Check SMBv2 signature
        if resp[4:8] != b'\xfeSMB':
            sock.close(); return False
        # Status == 0 means negotiate OK
        status = struct.unpack('<I', resp[12:16])[0]
        if status != 0:
            sock.close(); return False
        # Parse security blob from negotiate response
        sec_off = struct.unpack('<H', resp[72:74])[0]
        sec_len = struct.unpack('<H', resp[74:76])[0]
        # --- Session Setup with NTLMSSP Negotiate ---
        nego_token = _ntlmssp_negotiate('', 'SCANNER')
        ss1 = _smb2_session_setup_pkt(nego_token, 0, 2)
        sock.send(ss1)
        resp = sock.recv(4096)
        if len(resp) < 8:
            sock.close(); return False
        # Status should be STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) — more data needed
        status = struct.unpack('<I', resp[12:16])[0]
        if status != 0xC0000016:  # STATUS_MORE_PROCESSING_REQUIRED
            sock.close(); return False
        # Parse NTLMSSP Challenge from response
        sec_off2 = struct.unpack('<H', resp[72:74])[0]
        sec_len2 = struct.unpack('<H', resp[74:76])[0]
        if sec_off2 + sec_len2 > len(resp):
            sock.close(); return False
        challenge_blob = resp[sec_off2:sec_off2 + sec_len2]
        ch_info = _ntlmssp_parse_challenge(challenge_blob)
        if not ch_info or len(ch_info.get('challenge', b'')) < 8:
            sock.close(); return False
        # --- Session Setup with NTLMSSP Authenticate ---
        auth_token = _ntlmssp_authenticate(user, '', 'SCANNER', ch_info, pwd)
        ss2 = _smb2_session_setup_pkt(auth_token, 0, 3)
        sock.send(ss2)
        resp = sock.recv(4096)
        sock.close()
        if len(resp) < 16:
            return False
        status = struct.unpack('<I', resp[12:16])[0]
        return status == 0  # STATUS_SUCCESS
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _smb2_negotiate_pkt() -> bytes:
    """Build SMBv2 Negotiate request with NetBIOS wrapper."""
    # SMBv2 Negotiate body
    dialects = b'\x02\x02\x02\x10\x03\x00\x03\x02\x03\x11'  # SMB 2.0.2, 2.1.0, 3.0, 3.0.2, 3.1.1
    dialect_arr = struct.pack('<H', 5) + struct.pack('<5H', 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    # SMBv2 header (64-byte fixed)
    hdr = b'\xfeSMB'  # ProtocolId
    hdr += struct.pack('<H', 64)  # StructureSize
    hdr += struct.pack('<H', 0)  # CreditCharge
    hdr += struct.pack('<I', 0)  # Status
    hdr += struct.pack('<H', 0)  # Command: NEGOTIATE
    hdr += struct.pack('<H', 0)  # CreditRequest
    hdr += struct.pack('<I', 0x01)  # Flags: SIGNING_REQUIRED off
    hdr += struct.pack('<I', 0)  # NextCommand
    hdr += struct.pack('<Q', 1)  # MessageId
    hdr += struct.pack('<I', 0)  # Reserved
    hdr += struct.pack('<I', 0)  # TreeId
    hdr += struct.pack('<Q', 0)  # SessionId
    hdr += b'\x00' * 16  # Signature
    pkt = hdr + dialect_arr
    # NetBIOS session wrapper (4 bytes: type + 24-bit length)
    return struct.pack('>I', len(pkt)) + pkt


def _smb2_session_setup_pkt(sec_blob: bytes, session_id: int, msg_id: int) -> bytes:
    """Build SMBv2 Session Setup request."""
    flags = 0x00 if session_id == 0 else 0x01  # SMB2_FLAGS_SIGNING for subsequent
    hdr = b'\xfeSMB'
    hdr += struct.pack('<H', 64)
    hdr += struct.pack('<H', 0)
    hdr += struct.pack('<I', 0)
    hdr += struct.pack('<H', 1)  # Command: SESSION_SETUP
    hdr += struct.pack('<H', 0)
    hdr += struct.pack('<I', flags)
    hdr += struct.pack('<I', 0)
    hdr += struct.pack('<Q', msg_id)
    hdr += struct.pack('<I', 0)  # Reserved
    hdr += struct.pack('<I', 0)  # TreeId
    hdr += struct.pack('<Q', session_id)
    hdr += b'\x00' * 16  # Signature
    # Session Setup body: StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) + Channel(4)
    # + SecBufOffset(2) + SecBufLength(2) + PreviousSessionId(8) = 24 bytes
    body = struct.pack('<H', 24)  # StructureSize
    body += b'\x00'  # Flags
    body += b'\x01'  # SecurityMode: SIGNING_ENABLED
    body += struct.pack('<I', 0)  # Capabilities
    body += struct.pack('<I', 0)  # Channel
    sec_off = 64 + 24  # offset after header + body
    body += struct.pack('<H', sec_off)
    body += struct.pack('<H', len(sec_blob))
    body += struct.pack('<Q', 0)  # PreviousSessionId
    pkt = hdr + body + sec_blob
    # Pad to 4-byte alignment if needed
    while len(pkt) % 4 != 0:
        pkt += b'\x00'
    netbios = struct.pack('>I', len(pkt) | 0x00000000)
    return netbios + pkt
