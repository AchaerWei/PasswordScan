import socket, struct, time
from netspider._lib.constants import SCAN_TIMEOUT
from netspider._lib.types import NetworkError

_VNC_REV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))

try:
    from Crypto.Cipher import DES
    HAS_PYCRYPTO = True
except ImportError:
    HAS_PYCRYPTO = False
    DES = None


def test_vnc(ip: str, port: int, user: str, pwd: str) -> bool:
    """VNC RFB 3.3-3.8 authentication (DES-ECB challenge-response)."""
    if not HAS_PYCRYPTO:
        return False
    try:
        sock = socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
        sock.settimeout(5.0)

        pv = sock.recv(12)
        if not pv or not pv.startswith(b'RFB '):
            sock.close()
            return False

        sock.send(pv)

        sec_data = sock.recv(256)
        if len(sec_data) < 1:
            sock.close()
            return False

        num_types = sec_data[0]
        if num_types == 0:
            sock.close()
            return False

        if 2 not in list(sec_data[1:1 + num_types]):
            sock.close()
            return False

        sock.send(b'\x02')

        challenge = b''
        while len(challenge) < 16:
            chunk = sock.recv(16 - len(challenge))
            if not chunk:
                sock.close()
                return False
            challenge += chunk

        key = pwd.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        key = bytes([_VNC_REV[b] for b in key])
        cipher = DES.new(key, DES.MODE_ECB)
        response = cipher.encrypt(challenge)
        sock.send(response)

        result = b''
        while len(result) < 4:
            chunk = sock.recv(4 - len(result))
            if not chunk:
                sock.close()
                return False
            result += chunk

        sock.close()
        return struct.unpack('>I', result)[0] == 0
    except ConnectionRefusedError:
        raise NetworkError() from None
    except Exception:
        return False
