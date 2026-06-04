"""SPNEGO helpers for RDP CredSSP and other NTLM-wrapping protocols."""

from netspider._lib.ber import _ber_len_content, _ber_decode_length


def _spnego_wrap_ntlmssp(token: bytes) -> bytes:
    """Wrap NTLMSSP token in SPNEGO NegTokenInit for CredSSP."""
    # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    ntlm_oid = b'\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
    # mechTypes: SEQUENCE OF OID
    mech_type_seq = b'\x30' + _ber_len_content(len(ntlm_oid)) + ntlm_oid
    # mechTypes [0] IMPLICIT SEQUENCE OF
    mech_types_ctx = b'\xa0' + _ber_len_content(len(mech_type_seq)) + mech_type_seq
    # mechToken [2] IMPLICIT OCTET STRING
    mech_token_ctx = b'\xa2' + _ber_len_content(len(token)) + token
    # NegTokenInit SEQUENCE { mechTypes [0], mechToken [2] }
    neg_body = mech_types_ctx + mech_token_ctx
    neg_token = b'\x30' + _ber_len_content(len(neg_body)) + neg_body
    # SPNEGO OID: 1.3.6.1.5.5.2
    spnego_oid = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
    # InitialContextToken [APPLICATION 0] IMPLICIT SEQUENCE { thisMech, negToken }
    init_body = spnego_oid + neg_token
    return b'\x60' + _ber_len_content(len(init_body)) + init_body


def _spnego_unwrap(data: bytes) -> bytes | None:
    """Extract NTLMSSP token from SPNEGO NegTokenResp/NegTokenInit."""
    try:
        idx = 0
        if idx < len(data) and data[idx] == 0x60:
            idx += 1
            ll, llb = _ber_decode_length(data, idx)
            idx += llb
        if idx + 1 < len(data) and data[idx] == 0x06:
            oid_len = data[idx + 1]
            idx += 2 + oid_len
        if idx >= len(data) or data[idx] != 0x30:
            return None
        idx += 1
        seq_len, seq_lenb = _ber_decode_length(data, idx)
        idx += seq_lenb
        seq_end = idx + seq_len
        while idx < seq_end:
            tag_byte = data[idx]
            idx += 1
            tag_len, tag_lenb = _ber_decode_length(data, idx)
            idx += tag_lenb
            if tag_byte == 0xa2:
                return data[idx:idx + tag_len]
            idx += tag_len
        return None
    except Exception:
        return None


def _spnego_wrap_auth(token: bytes) -> bytes:
    """Wrap NTLMSSP Authenticate token in SPNEGO NegTokenResp."""
    resp_token = b'\xa2' + _ber_len_content(len(token)) + token
    neg_token = b'\x30' + _ber_len_content(len(resp_token)) + resp_token
    spnego_oid = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
    init_body = spnego_oid + neg_token
    return b'\x60' + _ber_len_content(len(init_body)) + init_body
