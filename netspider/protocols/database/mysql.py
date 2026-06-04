"""MySQL protocol tester — native_password + caching_sha2_password."""
from __future__ import annotations
import socket, struct, hashlib
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError, _set_finding_type


def _parse_mysql_handshake(data: bytes) -> dict | None:
    """Parse MySQL server handshake packet. Returns dict with auth fields or None."""
    try:
        if len(data) < 4:
            return None
        pkt_len = data[0] | (data[1] << 8) | (data[2] << 16)
        pkt = bytes(data[4:4 + pkt_len])
        info = {}
        pos = 1  # protocol version
        end = pkt.index(b'\x00', pos)
        info['server_version'] = pkt[pos:end].decode('utf-8', errors='ignore')
        pos = end + 1
        info['conn_id'] = struct.unpack('<I', pkt[pos:pos + 4])[0]; pos += 4
        info['auth_plugin_data_1'] = pkt[pos:pos + 8]; pos += 8
        pos += 1  # filler (0x00)
        info['caps_lower'] = struct.unpack('<H', pkt[pos:pos + 2])[0]; pos += 2
        info['charset'] = pkt[pos]; pos += 1
        info['status'] = struct.unpack('<H', pkt[pos:pos + 2])[0]; pos += 2
        info['caps_upper'] = struct.unpack('<H', pkt[pos:pos + 2])[0]; pos += 2
        auth_plugin_data_len = pkt[pos] if pkt[pos] > 0 else 20; pos += 1
        pos += 10  # reserved
        part2_len = max(12, auth_plugin_data_len - 8)
        info['auth_plugin_data_2'] = pkt[pos:pos + part2_len]
        info['auth_data'] = (info['auth_plugin_data_1'] + info['auth_plugin_data_2'])[:auth_plugin_data_len]
        rest = pkt[pos + part2_len:]
        term = rest.find(b'\x00')
        info['auth_plugin_name'] = rest[:term].decode('utf-8', errors='ignore') if term >= 0 else ''
        return info
    except Exception:
        return None


def test_mysql(ip: str, port: int, user: str, pwd: str) -> bool:
    """MySQL auth: supports native_password and caching_sha2_password fast auth."""
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(6.0)
        data = sock.recv(4096)
        info = _parse_mysql_handshake(data)
        if not info:
            sock.close()
            return False

        auth_plugin = info['auth_plugin_name']
        auth_data = info['auth_data']
        caps = info['caps_lower'] | (info['caps_upper'] << 16)

        if auth_plugin == 'caching_sha2_password' or 'caching_sha2_password' in auth_plugin:
            ok = _mysql_caching_sha2_auth(sock, user, pwd, auth_data, caps)
        else:
            ok = _mysql_native_auth(sock, user, pwd, auth_data, caps)

        sock.close()
        return ok
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _mysql_native_auth(sock: socket.socket, user: str, pwd: str,
                       auth_data: bytes, caps: int) -> bool:
    """mysql_native_password auth.
    Correct algorithm: response = XOR(SHA1(password), SHA1(scramble + SHA1(SHA1(password))))
    """
    stage1 = hashlib.sha1(pwd.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    auth_data_20 = auth_data[:20] if len(auth_data) >= 20 else auth_data + b'\x00' * (20 - len(auth_data))
    stage3 = hashlib.sha1(auth_data_20 + stage2).digest()
    response = bytes(s1 ^ s3 for s1, s3 in zip(stage1, stage3))

    client_caps = 0x0002 | 0x0200 | 0x8000 | 0x0008 | 0x0020 | 0x80000
    payload = bytearray()
    payload += struct.pack('<I', client_caps)
    payload += struct.pack('<I', 16777215)
    payload += bytes([33])
    payload += b'\x00' * 23
    payload += user.encode() + b'\x00'
    payload += bytes([20]) + bytes(response[:20])
    payload += b'mysql_native_password\x00'

    header = struct.pack('<I', len(payload))[:3] + bytes([1])
    sock.send(header + payload)
    result = _recv_mysql_packet(sock)
    return len(result) >= 4 and result[4] == 0x00


def _mysql_caching_sha2_auth(sock: socket.socket, user: str, pwd: str,
                              auth_data: bytes, caps: int) -> bool:
    """caching_sha2_password XOR fast auth + full auth fallback."""
    # Step 1: XOR fast auth
    p1 = hashlib.sha256(pwd.encode()).digest()
    p2 = hashlib.sha256(p1).digest()
    p3_input = p2 + auth_data
    p3 = hashlib.sha256(p3_input).digest()
    response = bytearray(len(p1))
    for i in range(len(p1)):
        response[i] = p1[i] ^ p3[i]

    client_caps = 0x0002 | 0x0200 | 0x8000 | 0x0008 | 0x0020 | 0x80000 | 0x00040000
    payload = bytearray()
    payload += struct.pack('<I', client_caps)
    payload += struct.pack('<I', 16777215)
    payload += bytes([33])
    payload += b'\x00' * 23
    payload += user.encode() + b'\x00'
    payload += bytes([len(response)]) + bytes(response)
    payload += b'caching_sha2_password\x00'

    header = struct.pack('<I', len(payload))[:3] + bytes([1])
    sock.send(header + payload)
    result = _recv_mysql_packet(sock)

    if len(result) < 4:
        return False

    if result[4] == 0x00:  # OK packet — fast auth succeeded
        return True
    if result[4] == 0xFF:  # ERR packet
        return False

    # AuthMoreData (0x01): server wants full auth
    if result[4] == 0x01:
        # Data follows: byte 5 = auth method (3=full, 4=fast_auth_complete)
        if len(result) > 5 and result[5] == 4:
            # Fast auth complete: send plaintext password
            pw_bytes = pwd.encode() + b'\x00'
            sock.send(pw_bytes)
            result = _recv_mysql_packet(sock)
            return len(result) >= 4 and result[4] == 0x00
        elif len(result) > 5 and result[5] == 3:
            # Full auth: request public key
            sock.send(bytes([2]))  # request public key
            result = _recv_mysql_packet(sock)
            if len(result) < 5 or result[4] == 0xFF:
                return False
            try:
                pubkey_pem = bytes(result[6:]).rstrip(b'\x00').decode('ascii', errors='ignore')
            except Exception:
                return False
            return _mysql_rsa_encrypt_and_send(sock, pwd, pubkey_pem)
        return False

    return False


def _x509_extract_rsa_key(pubkey_pem: str):
    """Extract (modulus, exponent) from X.509 SubjectPublicKeyInfo PEM."""
    import base64
    b64 = pubkey_pem.replace('-----BEGIN PUBLIC KEY-----', '')\
                     .replace('-----END PUBLIC KEY-----', '')\
                     .replace('\n', '').replace('\r', '')
    der = base64.b64decode(b64)

    def _parse_tlv(data, offset):
        tag = data[offset]
        offset += 1
        length = data[offset]
        offset += 1
        if length & 0x80:
            num_len = length & 0x7f
            length = int.from_bytes(data[offset:offset + num_len], 'big')
            offset += num_len
        return tag, length, offset, offset + length

    _, _, val_start, val_end = _parse_tlv(der, 0)
    _, _, alg_id_start, alg_id_end = _parse_tlv(der, val_start)
    _, _, bs_start, bs_end = _parse_tlv(der, alg_id_end)
    pkcs1_offset = bs_start + 1

    _, _, seq_start, seq_end = _parse_tlv(der, pkcs1_offset)
    _, _, mod_s, mod_e = _parse_tlv(der, seq_start)
    modulus = int.from_bytes(der[mod_s:mod_e], 'big')
    _, _, exp_s, exp_e = _parse_tlv(der, mod_e)
    exponent = int.from_bytes(der[exp_s:exp_e], 'big')
    return modulus, exponent


def _mysql_rsa_encrypt_and_send(sock: socket.socket, pwd: str, pubkey_pem: str) -> bool:
    """Encrypt password with RSA public key and send to MySQL."""
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
        pw_bytes = pwd.encode() + b'\x00'
        for use_xor in (True, False):
            if use_xor:
                xored = bytearray(len(pw_bytes))
                for i in range(len(pw_bytes)):
                    xored[i] = pw_bytes[i] ^ (i + 1)
                plaintext = bytes(xored)
            else:
                plaintext = pw_bytes
            try:
                encrypted = pubkey.encrypt(
                    plaintext,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                 algorithm=hashes.SHA1(), label=None)
                )
                sock.send(encrypted)
                result = _recv_mysql_packet(sock)
                if len(result) >= 4 and result[4] == 0x00:
                    return True
            except Exception:
                continue
        return False
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False


def _recv_mysql_packet(sock: socket.socket) -> bytes:
    """Receive a single MySQL packet."""
    try:
        header = sock.recv(4)
        if len(header) < 4:
            return b''
        pkt_len = header[0] | (header[1] << 8) | (header[2] << 16)
        data = header + sock.recv(pkt_len)
        return data
    except socket.timeout:
        return b''
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return b''
