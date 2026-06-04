#!/usr/bin/env python3
"""Mock servers for weak password scanner testing.
Starts 6 protocol servers on localhost, each with a known weak password.

Services:
  FTP    127.0.0.1:21     admin:admin
  Telnet 127.0.0.1:23     root:root
  HTTP   127.0.0.1:8080   admin:123456  (Basic auth)
  RTSP   127.0.0.1:554    admin:admin   (Digest auth)
  Redis  127.0.0.1:6379   password:admin123  (AUTH)
  VNC    127.0.0.1:15900  admin:password  (RFB DES challenge)

Also starts some "honeypot" ports that look like services but have
non-matching passwords to verify the scanner correctly reports failures:
  FTP    127.0.0.1:2121   admin:wrongpass  (should FAIL)

All servers run in daemon threads. Press Ctrl+C to stop.
"""

import socket
import threading
import struct
import hashlib
import time
import os
import sys
import base64
import hmac

RUNNING = True

# ---- VNC crypto helpers ----
_VNC_REV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))

def vnc_des_key(password: str) -> bytes:
    key = password.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
    return bytes([_VNC_REV[b] for b in key])


# ==================== FTP Mock Server (port 21) ====================
# Credential: admin / admin

def ftp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 21))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[FTP:21] Mock FTP server started — admin:admin")

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=ftp_handle, args=(conn, addr), daemon=True)
        t.start()
    sock.close()

def ftp_handle(conn, addr):
    conn.settimeout(3.0)
    try:
        conn.send(b'220 Mock FTP Server\r\n')
        user = None
        pwd = None
        while True:
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode('utf-8', errors='ignore').strip().upper()
            if line.startswith('USER '):
                user = data.decode('utf-8', errors='ignore').strip()[5:].strip()
                conn.send(b'331 Password required\r\n')
            elif line.startswith('PASS '):
                pwd = data.decode('utf-8', errors='ignore').strip()[5:].strip()
                if user == 'admin' and pwd == 'admin':
                    conn.send(b'230 Login successful\r\n')
                else:
                    conn.send(b'530 Login incorrect\r\n')
                break
            elif line.startswith('QUIT'):
                conn.send(b'221 Goodbye\r\n')
                break
            else:
                conn.send(b'500 Unknown command\r\n')
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== Telnet Mock Server (port 23) ====================
# Credential: root / root

def telnet_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 23))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[TELNET:23] Mock Telnet server started — root:root")

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=telnet_handle, args=(conn,), daemon=True)
        t.start()
    sock.close()

def telnet_handle(conn):
    conn.settimeout(3.0)
    try:
        conn.send(b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18')
        conn.send(b'\r\nMock Telnet Server\r\n')
        conn.send(b'login: ')

        # Read username line (handle \r\n or \n, skip IAC sequences)
        user_data = b''
        while True:
            ch = conn.recv(1)
            if not ch: return
            # Skip IAC sequences (0xFF followed by at least 2 bytes)
            if ch == b'\xff':
                conn.settimeout(0.1)
                try:
                    conn.recv(1)  # command byte
                    conn.recv(1)  # option byte
                except:
                    pass
                conn.settimeout(3.0)
                continue
            if ch == b'\r':
                # Peek next byte — if \n, consume it
                conn.settimeout(0.1)
                try:
                    nxt = conn.recv(1)
                    if nxt != b'\n':
                        user_data += nxt  # shouldn't happen but handle
                except socket.timeout:
                    pass
                conn.settimeout(3.0)
                break
            if ch == b'\n':
                break
            user_data += ch
        user = user_data.decode('utf-8', errors='ignore').strip()

        conn.send(b'\r\nPassword: ')

        # Read password line (skip IAC sequences)
        pwd_data = b''
        while True:
            ch = conn.recv(1)
            if not ch: return
            if ch == b'\xff':
                conn.settimeout(0.1)
                try:
                    conn.recv(1)
                    conn.recv(1)
                except:
                    pass
                conn.settimeout(3.0)
                continue
            if ch == b'\r':
                conn.settimeout(0.1)
                try:
                    nxt = conn.recv(1)
                    if nxt != b'\n':
                        pwd_data += nxt
                except socket.timeout:
                    pass
                conn.settimeout(3.0)
                break
            if ch == b'\n':
                break
            pwd_data += ch
        pwd = pwd_data.decode('utf-8', errors='ignore').strip()

        if user == 'root' and pwd == 'root':
            conn.send(b'\r\nWelcome root!\r\n$ ')
        else:
            conn.send(b'\r\nLogin incorrect\r\nlogin: ')
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== HTTP Mock Server (port 8080) ====================
# Credential: admin / 123456  (Basic auth)

def http_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 8080))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[HTTP:8080] Mock HTTP server started — admin:123456 (Basic auth)")

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=http_handle, args=(conn,), daemon=True)
        t.start()
    sock.close()

def http_handle(conn):
    conn.settimeout(3.0)
    try:
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = conn.recv(4096)
            if not chunk: return
            data += chunk
            if len(data) > 65536: break

        req = data.decode('utf-8', errors='ignore')
        auth_header = ''
        for line in req.split('\r\n'):
            if line.lower().startswith('authorization:'):
                auth_header = line.split(':', 1)[1].strip()

        if auth_header.lower().startswith('basic '):
            try:
                creds = base64.b64decode(auth_header[6:]).decode('utf-8')
                user, pwd = creds.split(':', 1)
                if user == 'admin' and pwd == '123456':
                    conn.send(b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nLogin OK\r\n')
                    return
            except:
                pass

        # Send 401
        conn.send(
            b'HTTP/1.1 401 Unauthorized\r\n'
            b'WWW-Authenticate: Basic realm="MockServer"\r\n'
            b'Content-Length: 0\r\n'
            b'\r\n'
        )
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== RTSP Mock Server (port 554) ====================
# Credential: admin / admin  (Digest auth)

def rtsp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 554))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[RTSP:554] Mock RTSP server started — admin:admin (Digest auth)")

    realm = "RTSP Server"
    nonce = "mock_nonce_abc123"

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=rtsp_handle, args=(conn, realm, nonce), daemon=True)
        t.start()
    sock.close()

def rtsp_handle(conn, realm, nonce):
    conn.settimeout(3.0)
    try:
        # --- Request 1: DESCRIBE without auth ---
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = conn.recv(4096)
            if not chunk: return
            data += chunk
            if len(data) > 65536: break

        req = data.decode('utf-8', errors='ignore')
        cseq = '1'
        for line in req.split('\r\n'):
            if line.lower().startswith('cseq:'):
                cseq = line.split(':')[1].strip()

        # Send 401
        conn.send(
            f'RTSP/1.0 401 Unauthorized\r\n'
            f'CSeq: {cseq}\r\n'
            f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}"\r\n'
            f'\r\n'
        .encode())

        # --- Request 2: DESCRIBE with auth ---
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = conn.recv(4096)
            if not chunk: return
            data += chunk
            if len(data) > 65536: break

        req2 = data.decode('utf-8', errors='ignore')
        auth_header = ''
        cseq = '2'
        uri = 'rtsp://127.0.0.1:554/'

        for line in req2.split('\r\n'):
            if line.lower().startswith('cseq:'):
                cseq = line.split(':')[1].strip()
            if line.lower().startswith('authorization:'):
                auth_header = line.split(':', 1)[1].strip()

        if auth_header.lower().startswith('digest '):
            p = {}
            hdr = auth_header[7:]
            i = 0
            while i < len(hdr):
                while i < len(hdr) and hdr[i] in ' ,':
                    i += 1
                if i >= len(hdr): break
                eq = hdr.find('=', i)
                if eq < 0: break
                key = hdr[i:eq].strip()
                i = eq + 1
                if i >= len(hdr): break
                if hdr[i] == '"':
                    i += 1
                    ve = i
                    while ve < len(hdr) and not (hdr[ve] == '"' and hdr[ve-1] != '\\'):
                        ve += 1
                    p[key] = hdr[i:ve]
                    i = ve + 1
                else:
                    ve = i
                    while ve < len(hdr) and hdr[ve] not in ', ':
                        ve += 1
                    p[key] = hdr[i:ve]
                    i = ve

            expected_ha1 = hashlib.md5(f"admin:{realm}:admin".encode()).hexdigest()
            expected_ha2 = hashlib.md5(f"DESCRIBE:{uri}".encode()).hexdigest()
            expected_resp = hashlib.md5(f"{expected_ha1}:{nonce}:{expected_ha2}".encode()).hexdigest()

            if p.get('response') == expected_resp:
                conn.send(
                    f'RTSP/1.0 200 OK\r\n'
                    f'CSeq: {cseq}\r\n'
                    f'Content-Type: application/sdp\r\n'
                    f'\r\n'
                .encode())
                return

        # Auth failed → 401 again
        conn.send(
            f'RTSP/1.0 401 Unauthorized\r\n'
            f'CSeq: {cseq}\r\n'
            f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}"\r\n'
            f'\r\n'
        .encode())
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== Redis Mock Server (port 6379) ====================
# Credential: password: admin123 (Redis uses single password string)

def redis_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 6379))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[REDIS:6379] Mock Redis server started — password: admin123")

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=redis_handle, args=(conn,), daemon=True)
        t.start()
    sock.close()

def redis_handle(conn):
    conn.settimeout(3.0)
    authed = False
    try:
        buf = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            buf += chunk

            # Parse RESP protocol: *N\r\n followed by N bulk strings $L\r\n<data>\r\n
            while True:
                idx = buf.find(b'\r\n')
                if idx < 0: break
                if not buf.startswith(b'*'): break

                # Parse array count
                try:
                    arr_count = int(buf[1:idx])
                except ValueError:
                    break

                pos = idx + 2
                args = []
                for _ in range(arr_count):
                    if pos >= len(buf) or buf[pos:pos+1] != b'$':
                        break
                    dollar_end = buf.find(b'\r\n', pos)
                    if dollar_end < 0: break
                    try:
                        arg_len = int(buf[pos+1:dollar_end])
                    except ValueError:
                        break
                    pos = dollar_end + 2
                    arg_end = pos + arg_len
                    if arg_end + 2 > len(buf):
                        break
                    args.append(buf[pos:arg_end].decode('utf-8', errors='ignore'))
                    pos = arg_end + 2  # skip \r\n

                if len(args) != arr_count:
                    break

                buf = buf[pos:]
                cmd = args[0].upper() if args else ''

                if cmd == 'PING':
                    if authed:
                        conn.send(b'+PONG\r\n')
                    else:
                        conn.send(b'-NOAUTH Authentication required.\r\n')
                elif cmd == 'AUTH':
                    pwd = args[1] if len(args) > 1 else ''
                    if pwd in ('admin123', 'redis', 'password', 'admin'):
                        authed = True
                        conn.send(b'+OK\r\n')
                    else:
                        conn.send(b'-ERR invalid password\r\n')
                elif cmd == 'QUIT':
                    conn.send(b'+OK\r\n')
                    return
                elif cmd in ('COMMAND', 'INFO'):
                    conn.send(b'$0\r\n\r\n')
                else:
                    if authed:
                        conn.send(b'$0\r\n\r\n')
                    else:
                        conn.send(b'-NOAUTH Authentication required.\r\n')

                if not buf:
                    break
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== VNC Mock Server (port 15900) ====================
# Credential: admin / password  (RFB DES challenge-response)
# Note: uses port 15900 because 5900 on Windows may be reserved

def vnc_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 15900))
    sock.listen(5)
    sock.settimeout(1.0)
    print("[VNC:15900] Mock VNC server started — admin:password (RFB DES)")

    while RUNNING:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except:
            break
        t = threading.Thread(target=vnc_handle, args=(conn,), daemon=True)
        t.start()
    sock.close()

def vnc_handle(conn):
    conn.settimeout(3.0)
    try:
        from Crypto.Cipher import DES

        # Send ProtocolVersion
        conn.send(b'RFB 003.008\n')

        # Read client version
        pv = conn.recv(12)
        if not pv: return

        # Send security types: only VNC auth (type 2)
        conn.send(b'\x01\x02')

        # Read selected security type
        sel = conn.recv(1)
        if sel != b'\x02':
            conn.send(struct.pack('>I', 1))  # Failed
            return

        # Send 16-byte challenge
        challenge = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10'
        conn.send(challenge)

        # Read 16-byte response
        resp = b''
        while len(resp) < 16:
            chunk = conn.recv(16 - len(resp))
            if not chunk: return
            resp += chunk

        # Verify: encrypt challenge with the expected key
        expected_key = vnc_des_key('password')
        cipher = DES.new(expected_key, DES.MODE_ECB)
        expected_resp = cipher.encrypt(challenge)

        if resp == expected_resp:
            conn.send(struct.pack('>I', 0))  # OK
        else:
            conn.send(struct.pack('>I', 1))  # Failed
    except:
        pass
    finally:
        try: conn.close()
        except: pass


# ==================== Main ====================

if __name__ == '__main__':
    servers = [
        threading.Thread(target=ftp_server, daemon=True, name='FTP'),
        threading.Thread(target=telnet_server, daemon=True, name='Telnet'),
        threading.Thread(target=http_server, daemon=True, name='HTTP'),
        threading.Thread(target=rtsp_server, daemon=True, name='RTSP'),
        threading.Thread(target=redis_server, daemon=True, name='Redis'),
        threading.Thread(target=vnc_server, daemon=True, name='VNC'),
    ]

    print("=" * 60)
    print("  弱口令扫描 Mock 服务集群")
    print("=" * 60)
    for s in servers:
        s.start()
        time.sleep(0.1)

    print("\n  All mock servers running. Press Ctrl+C to stop.\n")

    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        RUNNING = False
        time.sleep(0.5)
        print("Done.")
