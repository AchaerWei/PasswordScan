"""ASN.1 BER encoding/decoding helpers."""


def _ber_decode_length(data: bytes, idx: int):
    """Decode BER length. Returns (length, bytes_consumed)."""
    if idx >= len(data):
        return 0, 0
    if data[idx] < 0x80:
        return data[idx], 1
    num_bytes = data[idx] & 0x7F
    length = 0
    for i in range(num_bytes):
        if idx + 1 + i >= len(data):
            return 0, 0
        length = (length << 8) | data[idx + 1 + i]
    return length, 1 + num_bytes


def _ber_len_content(length: int) -> bytes:
    """BER length encoding."""
    if length < 128:
        return bytes([length])
    buf = bytearray()
    while length > 0:
        buf.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(buf)]) + bytes(buf)


def _ber_octet_string(data: bytes) -> bytes:
    """BER OCTET STRING tag (0x04) + length + data."""
    return bytes([0x04]) + _ber_len_content(len(data)) + data
