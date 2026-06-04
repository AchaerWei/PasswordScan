import socket, struct, time
from netspider._lib.types import NetworkError
from netspider._lib.ber import _ber_len_content, _ber_decode_length


def _parse_snmp_response_error(data: bytes) -> bool:
    """Parse SNMP GetResponse and return True if error-status == 0 (success).
    Walks BER structure: SEQUENCE → version → community → GetResponse-PDU(0xA2)
    → request-id → error-status → error-index → varbind-list.
    Returns False on parse failure or non-zero error-status."""
    try:
        pos = 0
        if pos >= len(data) or data[pos] != 0x30:
            return False
        pos += 1
        if pos >= len(data):
            return False
        if data[pos] & 0x80:
            ll = data[pos] & 0x7F
            pos += 1 + ll
        else:
            pos += 1
        # Skip version (INTEGER 0x02)
        if pos >= len(data) or data[pos] != 0x02:
            return False
        pos += 1
        if pos >= len(data):
            return False
        if data[pos] & 0x80:
            ll = data[pos] & 0x7F
            pos += 1 + ll
        else:
            ver_len = data[pos]
            pos += 1 + ver_len
        # Skip community (OCTET STRING 0x04)
        if pos >= len(data) or data[pos] != 0x04:
            return False
        pos += 1
        if pos >= len(data):
            return False
        if data[pos] & 0x80:
            ll = data[pos] & 0x7F
            pos += 1 + ll
        else:
            comm_len = data[pos]
            pos += 1 + comm_len
        # Expect GetResponse-PDU (0xA2)
        if pos >= len(data) or data[pos] != 0xA2:
            return False
        pos += 1
        if pos >= len(data):
            return False
        if data[pos] & 0x80:
            ll = data[pos] & 0x7F
            pos += 1 + ll
        else:
            pdu_len = data[pos]
            pos += 1
        # Skip request-id (INTEGER 0x02)
        if pos >= len(data) or data[pos] != 0x02:
            return False
        pos += 1
        if pos >= len(data):
            return False
        if data[pos] & 0x80:
            ll = data[pos] & 0x7F
            pos += 1 + ll
        else:
            reqid_len = data[pos]
            pos += 1 + reqid_len
        # Read error-status (INTEGER 0x02)
        if pos >= len(data) or data[pos] != 0x02:
            return False
        pos += 1
        if pos >= len(data):
            return False
        err_len = data[pos]
        pos += 1
        if pos + err_len > len(data):
            return False
        error_status = 0
        for i in range(err_len):
            error_status = (error_status << 8) | data[pos + i]
        return error_status == 0
    except Exception:
        return False


def test_snmp(ip: str, port: int, community: str, retries: int = 3) -> bool:
    """Test SNMPv1/v2c community string with retry logic for UDP."""
    pkt = _build_snmp_get(community)

    last_err = None
    for attempt in range(retries):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0 + attempt * 1.5)
            s.sendto(pkt, (ip, port))
            resp = s.recv(4096)
            s.close()
            if len(resp) > 0 and resp[0] == 0x30:
                return _parse_snmp_response_error(resp)
            # Non-SEQUENCE response is noise, not a valid SNMP response
        except socket.timeout:
            last_err = 'timeout'
            s.close()
            time.sleep(0.3)
        except Exception as e:
            last_err = str(e)
            try:
                s.close()
            except Exception:
                pass
            time.sleep(0.3)

    return False


def _build_snmp_get(community: str) -> bytes:
    """Build a minimal SNMPv2c GET request for sysDescr (1.3.6.1.2.1.1.1.0)."""
    oid = b'\x2b\x06\x01\x02\x01\x01\x01\x00'  # .1.3.6.1.2.1.1.1.0
    # NULL value
    null_val = b'\x30\x00'
    # varbind
    varbind = (b'\x30' + _ber_len_content(2 + len(oid) + len(null_val))
               + b'\x06' + _ber_len_content(len(oid)) + oid + null_val)
    # varbind list
    varlist = b'\x30' + _ber_len_content(len(varbind)) + varbind
    # request-id, error, error-index
    req = b'\x02\x01\x00\x02\x01\x00\x02\x01\x00'
    # PDU (get-request = 0xA0)
    pdu = b'\xa0' + _ber_len_content(len(req) + len(varlist)) + req + varlist
    # community
    comm = b'\x04' + _ber_len_content(len(community)) + community.encode()
    # version (v2c = 1)
    ver = b'\x02\x01\x01'
    # full message
    msg = (b'\x30' + _ber_len_content(len(ver) + len(comm) + len(pdu))
           + ver + comm + pdu)
    return msg
