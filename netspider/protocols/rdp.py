import socket, ssl, struct, time
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError
from netspider._lib.ntlm import _ntlmssp_negotiate, _ntlmssp_parse_challenge, _ntlmssp_authenticate
from netspider._lib.spnego import _spnego_wrap_ntlmssp, _spnego_unwrap, _spnego_wrap_auth
from netspider._lib.ber import _ber_len_content, _ber_decode_length
from netspider.security import create_ssl_context


def test_rdp(ip: str, port: int, user: str, pwd: str) -> bool:
    """RDP NLA (CredSSP) authentication test."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(8.0)

        neg_req = _rdp_build_negotiation()
        sock.send(neg_req)
        resp = sock.recv(4096)
        if len(resp) < 8:
            sock.close()
            return False

        selected_proto = _rdp_parse_negotiation(resp)
        if selected_proto is None or not (selected_proto & 0x04):
            sock.close()
            return False

        ctx = create_ssl_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=ip)

        result = _rdp_nla_auth(tls_sock, user, pwd)
        tls_sock.close()
        return result
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _rdp_build_negotiation() -> bytes:
    """Build TPKT + X.224 CR + RDP Negotiation Request (select NLA)."""
    rdp_neg_req = struct.pack('<BBHI', 0x01, 0x00, 0x0008, 0x00000004)
    cookie = b'Cookie: mstshash=scanner\r\n'
    x224_body = cookie + rdp_neg_req
    x224_cr = bytes([len(x224_body) + 1, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00]) + x224_body
    tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(x224_cr))
    return tpkt + x224_cr


def _rdp_parse_negotiation(data: bytes) -> int | None:
    """Parse RDP Negotiation Response, return selected protocol bitmask."""
    try:
        if len(data) < 4:
            return None
        tpkt_len = struct.unpack('>H', data[2:4])[0]
        x224 = data[4:tpkt_len] if tpkt_len <= len(data) else data[4:]
        if x224[1] != 0xd0:
            return None
        pos = 2
        while pos + 8 <= len(x224):
            rdp_type = x224[pos]
            if rdp_type == 0x02:
                rdp_len = struct.unpack('<H', x224[pos + 2:pos + 4])[0]
                if pos + rdp_len <= len(x224):
                    return struct.unpack('<I', x224[pos + 4:pos + 8])[0]
            pos += 1
        return None
    except Exception:
        return None


def _rdp_nla_auth(tls_sock, user: str, pwd: str) -> bool:
    """Perform CredSSP/NLA NTLMSSP authentication over TLS."""
    nego_token = _ntlmssp_negotiate('', 'SCANNER')
    spnego_init = _spnego_wrap_ntlmssp(nego_token)
    tsreq1 = _rdp_build_tsrequest(spnego_init)
    tls_sock.send(tsreq1)

    resp = tls_sock.recv(4096)
    if not resp:
        return False

    spnego_resp = _rdp_parse_tsrequest(resp)
    if not spnego_resp:
        return False

    ntlm_challenge = _spnego_unwrap(spnego_resp)
    if not ntlm_challenge:
        return False

    ch_info = _ntlmssp_parse_challenge(ntlm_challenge)
    if not ch_info:
        return False

    auth_token = _ntlmssp_authenticate(user, '', 'SCANNER', ch_info, pwd)
    spnego_auth = _spnego_wrap_auth(auth_token)
    tsreq2 = _rdp_build_tsrequest(spnego_auth)
    tls_sock.send(tsreq2)

    try:
        resp2 = tls_sock.recv(4096)
        if not resp2 or len(resp2) <= 4:
            return False
        spnego_final = _rdp_parse_tsrequest(resp2)
        if not spnego_final:
            return False
        inner = _spnego_unwrap(spnego_final)
        if not inner or len(inner) < 8:
            return False
        ftype = struct.unpack('<I', inner[8:12])[0]
        if ftype == 2:
            return False  # Challenge → auth failed
        return True  # Non-challenge response → likely success
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _rdp_build_tsrequest(nego_tokens: bytes) -> bytes:
    """Build CredSSP TSRequest SEQUENCE { version[0]=2, negoTokens[1] }."""
    ver = b'\xa0\x03\x02\x01\x02'
    nego = b'\xa1' + _ber_len_content(len(nego_tokens)) + nego_tokens
    seq_body = ver + nego
    return b'\x30' + _ber_len_content(len(seq_body)) + seq_body


def _rdp_parse_tsrequest(data: bytes) -> bytes | None:
    """Parse TSRequest, extract negoTokens value, stripping TPKT framing."""
    try:
        buf = data
        if len(buf) >= 4 and buf[0] == 0x03:
            tpkt_len = struct.unpack('>H', buf[2:4])[0]
            if tpkt_len <= len(buf):
                buf = buf[4:tpkt_len]
            else:
                buf = buf[4:]
        if len(buf) < 2 or buf[0] != 0x30:
            return None
        idx = 1
        seq_len, seq_lenb = _ber_decode_length(buf, idx)
        idx += seq_lenb
        seq_end = idx + seq_len
        while idx < seq_end:
            tag = buf[idx]
            idx += 1
            tag_len, tag_lenb = _ber_decode_length(buf, idx)
            idx += tag_lenb
            if tag == 0xa1:
                return buf[idx:idx + tag_len]
            idx += tag_len
        return None
    except Exception:
        return None
