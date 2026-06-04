#!/usr/bin/env python3
"""
全协议模拟服务集群 — 弱口令检测工具综合验证
Comprehensive Protocol Simulator Cluster for Scanner Verification

对每个协议构建模拟服务，验证三类场景:
  A) 正确凭据 → 必须返回 True（否则=漏报）
  B) 错误凭据 → 必须返回 False（否则=误报）
  C) 非匹配服务 → 必须返回 False（否则=跨协议误报）
"""

import sys, os, time, socket, threading, hashlib, hmac, struct, base64, random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netspider._compat import *
# Underscore-prefixed names (imported explicitly since __all__ filters them):
from netspider._lib.ber import _ber_len_content, _ber_decode_length
from netspider._lib.crypto import _VNC_REV, _md4, _hmac_sha1, _hmac_sha256
from netspider._lib.ntlm import _ntlmssp_parse_challenge
from netspider._lib.spnego import _spnego_unwrap, _spnego_wrap_auth
from netspider.protocols.database import _bson_encode_doc, _bson_get_string, _bson_get_int32
from netspider.protocols.rdp import _rdp_parse_tsrequest, _rdp_build_tsrequest

# ================================================================
# Test Framework
# ================================================================

PASS = FAIL = SKIP = 0
LOG = []

def check(name, expected, actual, detail=""):
    global PASS, FAIL
    ok = (expected == actual)
    if ok: PASS += 1
    else: FAIL += 1
    tag = "PASS" if ok else "FAIL"
    msg = f"  [{tag}] {name} (exp={expected}, got={actual}) {detail}"
    LOG.append(msg)
    print(msg)

def skip(name, reason=""):
    global SKIP
    SKIP += 1
    print(f"  [SKIP] {name} — {reason}")


# ================================================================
# Simulator Base
# ================================================================

class SimServer:
    """Base TCP simulator."""
    def __init__(self, name, proto='tcp'):
        self.name = name
        self.proto = proto
        self.port = 0
        self._running = False
        self._thread = None
        self._sock = None
        self._owns_socket = True

    def bind(self):
        if self.proto == 'udp':
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(('127.0.0.1', 0))
            self.port = self._sock.getsockname()[1]
        else:
            self._sock = socket.socket()
            self._sock.bind(('127.0.0.1', 0))
            self._sock.listen(1)
            self.port = self._sock.getsockname()[1]

    def start(self):
        self.bind()
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        time.sleep(0.15)
        return self.port

    def _serve(self):
        raise NotImplementedError

    def stop(self):
        self._running = False
        try:
            if self._owns_socket and self._sock:
                # shutdown before close to interrupt blocking accept()
                try: self._sock.shutdown(socket.SHUT_RDWR)
                except: pass
        except: pass
        try:
            if self._owns_socket and self._sock:
                self._sock.close()
        except: pass

    @property
    def addr(self):
        return ('127.0.0.1', self.port)


class HTTPSimServer(SimServer):
    """Base for HTTP-based sims that use http.server. Does NOT pre-bind."""
    def bind(self):
        tmp = socket.socket()
        tmp.bind(('127.0.0.1', 0))
        self.port = tmp.getsockname()[1]
        tmp.close()
        self._sock = None
        self._owns_socket = False


# ================================================================
# 1. HTTP Basic Auth
# ================================================================

class HTTPBasicSim(HTTPSimServer):
    def __init__(self, user="admin", pwd="admin123"):
        super().__init__(f"HTTP-Basic({user}:{pwd})")
        self.user = user
        self.pwd = pwd

    def _serve(self):
        import http.server
        u, p = self.user, self.pwd

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get('Authorization', '')
                if not auth:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="test"')
                    self.end_headers()
                    return
                try:
                    creds = base64.b64decode(auth.split()[1]).decode()
                    cu, cp = creds.split(':', 1)
                    if cu == u and cp == p:
                        self.send_response(200); self.end_headers()
                    else:
                        self.send_response(401)
                        self.send_header('WWW-Authenticate', 'Basic realm="test"')
                        self.end_headers()
                except:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="test"')
                    self.end_headers()
            def log_message(self, *a): pass

        self._httpd = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), H)
        self._httpd.serve_forever()

    def stop(self):
        try: self._httpd.shutdown()
        except: pass


class HTTPFormSim(HTTPSimServer):
    """Simulates a web login form with CSRF token."""
    def __init__(self, user="admin", pwd="admin123"):
        super().__init__(f"HTTP-Form({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        import http.server
        u, p = self.user, self.pwd

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"""<html><body>
<form method="POST" action="/login">
<input type="hidden" name="csrf_token" value="abc123"/>
<label>Username:</label><input type="text" name="username"/>
<label>Password:</label><input type="password" name="password"/>
<input type="submit" value="Login"/>
</form></body></html>""")

            def do_POST(self):
                import urllib.parse
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                params = urllib.parse.parse_qs(body.decode())
                username = params.get('username', [''])[0]
                password = params.get('password', [''])[0]
                csrf = params.get('csrf_token', [''])[0]

                if csrf != 'abc123':
                    self.send_response(403); self.end_headers()
                    return

                if username == u and password == p:
                    self.send_response(302)
                    self.send_header('Location', '/dashboard')
                    self.send_header('Set-Cookie', 'session=loggedin; Path=/')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<html><body>Login failed: incorrect credentials</body></html>')

            def log_message(self, *a): pass

        self._httpd = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), H)
        self._httpd.serve_forever()

    def stop(self):
        try: self._httpd.shutdown()
        except: pass


# ================================================================
# 2. Telnet
# ================================================================

class TelnetSim(SimServer):
    def __init__(self, user="admin", pwd="cisco123", iac=True):
        super().__init__(f"Telnet({user}:{pwd})")
        self.user = user; self.pwd = pwd
        self.iac = iac

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                # Send IAC negotiation (real telnet servers always do this)
                if self.iac:
                    c.send(b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18')
                c.send(b'\r\nRouter login: ')
                # Read username — skip IAC response bytes from client
                raw = b''
                while True:
                    ch = c.recv(1)
                    if not ch: break
                    if ch == b'\xff':
                        try:
                            c.settimeout(0.1)
                            c.recv(1); c.recv(1)
                            c.settimeout(5.0)
                        except: pass
                        continue
                    if ch == b'\r':
                        # Consume \n if present
                        try:
                            c.settimeout(0.1)
                            nxt = c.recv(1)
                            c.settimeout(5.0)
                        except:
                            pass
                        break
                    if ch == b'\n':
                        break
                    raw += ch
                u = raw.decode('utf-8', errors='ignore').strip()
                if u == self.user:
                    c.send(b'Password: ')
                    raw = b''
                    while True:
                        ch = c.recv(1)
                        if not ch: break
                        if ch == b'\xff':
                            try:
                                c.settimeout(0.1)
                                c.recv(1); c.recv(1)
                                c.settimeout(5.0)
                            except: pass
                            continue
                        if ch == b'\r':
                            try:
                                c.settimeout(0.1)
                                c.recv(1)
                                c.settimeout(5.0)
                            except:
                                pass
                            break
                        if ch == b'\n':
                            break
                        raw += ch
                    pw = raw.decode('utf-8', errors='ignore').strip()
                    if pw == self.pwd:
                        c.send(b'\r\nLast login: Tue May 26 10:00:00 2026\r\nRouter>')
                    else:
                        c.send(b'\r\nLogin incorrect\r\nRouter login: ')
                else:
                    c.send(b'\r\nLogin incorrect\r\nRouter login: ')
                time.sleep(0.2); c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 3. FTP
# ================================================================

class FTPSim(SimServer):
    def __init__(self, user="ftpuser", pwd="ftppass"):
        super().__init__(f"FTP({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(3.0)
                c.send(b'220 FTP ready\r\n')
                u_cmd = c.recv(1024).decode('utf-8', errors='ignore').strip()
                c.send(b'331 Password required\r\n')
                p_cmd = c.recv(1024).decode('utf-8', errors='ignore').strip()
                su = u_cmd.split()[-1] if u_cmd else ''
                sp = p_cmd.split()[-1] if p_cmd else ''
                if su == self.user and sp == self.pwd:
                    c.send(b'230 User logged in\r\n')
                else:
                    c.send(b'530 Login incorrect.\r\n')
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 4. Redis
# ================================================================

class RedisSim(SimServer):
    def __init__(self, password=None):
        label = f"Redis(pwd={password})" if password else "Redis(no-auth)"
        super().__init__(label)
        self.password = password

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(3.0)
                data = c.recv(1024)
                if b'PING' in data:
                    if self.password:
                        c.send(b'-NOAUTH Authentication required.\r\n')
                        auth = c.recv(1024).decode('utf-8', errors='ignore')
                        # extract password from AUTH command
                        lines = auth.strip().split('\r\n')
                        sent = ''
                        for ln in lines:
                            if ln and not ln.startswith('*') and not ln.startswith('$') and ln.upper() != 'AUTH':
                                sent = ln
                        if sent == self.password:
                            c.send(b'+OK\r\n')
                        else:
                            c.send(b'-ERR invalid password\r\n')
                    else:
                        c.send(b'+PONG\r\n')
                else:
                    c.send(b'-ERR unknown command\r\n')
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 5. MySQL (native_password)
# ================================================================

class MySQLSim(SimServer):
    def __init__(self, user="root", pwd="mysql123"):
        super().__init__(f"MySQL({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _compute_response(self, password, scramble_20):
        s1 = hashlib.sha1(password.encode()).digest()
        s2 = hashlib.sha1(s1).digest()
        return bytes(a ^ b for a, b in zip(s1, hashlib.sha1(scramble_20 + s2).digest()))

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                scramble = os.urandom(20)
                # Build handshake
                proto = 10
                sv = b'5.7.38-test\x00'
                body = (bytes([proto]) + sv + struct.pack('<I', 1) +
                        scramble[:8] + b'\x00' +
                        struct.pack('<H', 0xFFF7) + bytes([8]) +
                        struct.pack('<H', 0x0002) + struct.pack('<H', 0xFFFF) +
                        bytes([21]) + b'\x00' * 10 + scramble[8:20] + b'\x00' +
                        b'mysql_native_password\x00')
                hdr = struct.pack('<I', len(body))[:3] + bytes([0])
                c.send(hdr + body)

                # Read response
                resp = b''
                try:
                    h = c.recv(4)
                    if len(h) >= 4:
                        plen = h[0] | (h[1] << 8) | (h[2] << 16)
                        resp = h + c.recv(plen)
                except: pass

                if len(resp) >= 5:
                    payload = resp[4:]
                    pos = 4+4+1+23
                    while pos < len(payload) and payload[pos] != 0: pos += 1
                    pos += 1
                    if pos < len(payload):
                        alen = payload[pos]; pos += 1
                        client_resp = payload[pos:pos+alen]
                        expected = self._compute_response(self.pwd, scramble[:20])
                        ok_pkt = struct.pack('<I', 7)[:3] + bytes([2]) + b'\x00\x00\x00\x02\x00\x00\x00'
                        err_pkt = struct.pack('<I', 7)[:3] + bytes([2]) + b'\xff\x15\x04\x23\x32\x38\x30\x30\x30Access denied\x00'
                        c.send(ok_pkt if client_resp == expected else err_pkt)
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 6. PostgreSQL (MD5)
# ================================================================

class PGSim(SimServer):
    """PostgreSQL MD5 auth simulator."""
    def __init__(self, user="postgres", pwd="pgpass"):
        super().__init__(f"PG-MD5({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                startup = c.recv(4096)
                salt = os.urandom(4)
                # MD5 auth request
                msg = bytes([ord('R')]) + struct.pack('>I', 12) + struct.pack('>I', 5) + salt
                c.send(msg)
                resp = c.recv(4096)
                if len(resp) >= 9:
                    # Parse 'p' message with md5 token
                    inner = hashlib.md5((self.pwd + self.user).encode()).hexdigest()
                    expected = ('md5' + hashlib.md5(inner.encode() + salt).hexdigest()).encode()
                    pos = 5
                    token = resp[pos:pos+len(expected)]
                    if token == expected:
                        c.send(bytes([ord('R')]) + struct.pack('>I', 8) + struct.pack('>I', 0))
                    else:
                        c.send(bytes([ord('E')]) + struct.pack('>I', 64) + b'S' * 56)
                c.close()
            except socket.timeout: continue
            except: break


class PGSCRAMSim(SimServer):
    """PostgreSQL SCRAM-SHA-256 auth simulator."""
    def __init__(self, user="postgres", pwd="scrampass"):
        super().__init__(f"PG-SCRAM({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                startup = c.recv(4096)
                msg = bytes([ord('R')]) + struct.pack('>I', 8) + struct.pack('>I', 10)
                c.send(msg)
                resp = c.recv(4096)
                if len(resp) < 9: c.close(); continue
                client_first = resp[13:].decode('utf-8', errors='ignore')
                parts = {}
                for p in client_first.split(','):
                    if '=' in p: k, v = p.split('=', 1); parts[k] = v
                client_nonce = parts.get('r', '')
                import base64 as _b64
                server_nonce = _b64.b64encode(os.urandom(18)).decode('ascii')
                salt = os.urandom(16)
                salt_b64 = _b64.b64encode(salt).decode('ascii')
                iterations = 4096
                server_first = f"r={client_nonce}{server_nonce},s={salt_b64},i={iterations}"
                sf_bytes = server_first.encode('utf-8')
                sasl_cont = bytes([ord('R')]) + struct.pack('>I', 8 + len(sf_bytes)) + struct.pack('>I', 11) + sf_bytes
                c.send(sasl_cont)
                resp2 = c.recv(4096)
                if len(resp2) < 9: c.close(); continue
                client_final = resp2[9:].decode('utf-8', errors='ignore')
                cf_parts = {}
                for p in client_final.split(','):
                    if '=' in p: k, v = p.split('=', 1); cf_parts[k] = v
                proof_b64 = cf_parts.get('p', '')
                combined_nonce = cf_parts.get('r', '')
                salted_pw = hashlib.pbkdf2_hmac('sha256', self.pwd.encode('utf-8'), salt, iterations, 32)
                client_key = hmac.new(salted_pw, b'Client Key', hashlib.sha256).digest()
                stored_key = hashlib.sha256(client_key).digest()
                c_final_no_proof = f"c=biws,r={combined_nonce}"
                # RFC 5802: client-first-bare MUST include n=<username>
                auth_msg = f"n={self.user},r={client_nonce},{server_first},{c_final_no_proof}"
                client_sig = hmac.new(stored_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
                expected_proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
                expected_proof_b64 = _b64.b64encode(expected_proof).decode('ascii')
                if proof_b64 == expected_proof_b64:
                    server_key = hmac.new(salted_pw, b'Server Key', hashlib.sha256).digest()
                    server_sig = hmac.new(server_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
                    final = "v=" + _b64.b64encode(server_sig).decode('ascii')
                    final_bytes = final.encode('utf-8')
                    sasl_final = bytes([ord('R')]) + struct.pack('>I', 8 + len(final_bytes)) + struct.pack('>I', 12) + final_bytes
                    c.send(sasl_final)
                else:
                    c.send(bytes([ord('E')]) + struct.pack('>I', 64) + b'S' * 56)
                time.sleep(1.0)
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 7. MSSQL (TDS)
# ================================================================

class MSSQLSim(SimServer):
    def __init__(self, user="sa", pwd="P@ssw0rd"):
        super().__init__(f"MSSQL({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                c.recv(4096)  # pre-login
                # Pre-login response: ENCRYPT_NOT_REQ (0x02)
                pre = bytes([0x04,0x01,0x00,0x1A,0x00,0x00,0x01,0x00,
                             0x01,0x00,0x0E,0x00,0x01,
                             0x00,0x00,0x0F,0x00,0x06,0xFF,
                             0x02,  # ENCRYPT_NOT_REQ
                             0x00,0x00,0x00,0x00,0x00,0x00])
                c.send(pre)
                login = c.recv(4096)
                if len(login) < 20:
                    c.close(); continue
                # Check username (UTF-16LE, not obfuscated) and password (XOR 0xA5 obfuscated)
                u_raw = self.user.encode('utf-16le')
                u_ok = u_raw in login
                deobf = bytes(b ^ 0xA5 for b in login)
                p_raw = self.pwd.encode('utf-16le')
                p_ok = p_raw in deobf
                if u_ok and p_ok:
                    c.send(bytes([0x04,0x01,0x00,0x12,0x00,0x00,0x01,0x00,
                                  0xE3,0x03,0x00,0x00,
                                  0xFD,0x00,0x00,0x00,0x00,0x00]))
                else:
                    c.send(bytes([0x04,0x01,0x00,0x12,0x00,0x00,0x01,0x00,
                                  0xAA,0x05,0x00,0x00,0x00,0x00,
                                  0xFD,0x00,0x00,0x00,0x00,0x00]))
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 8. SNMP (UDP)
# ================================================================

class SNMPSim(SimServer):
    def __init__(self, community="public"):
        super().__init__(f"SNMP({community})", proto='udp')
        self.community = community

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                data, addr = self._sock.recvfrom(4096)
                if len(data) < 5 or data[0] != 0x30: continue
                # Extract community
                pos = 2
                if data[pos] == 0x02:
                    pos += 1
                    if data[pos] & 0x80: pos += 1 + (data[pos] & 0x7F)
                    else: pos += 1 + data[pos]
                if pos < len(data) and data[pos] == 0x04:
                    pos += 1
                    clen = data[pos]; pos += 1
                    comm = data[pos:pos+clen].decode('utf-8', errors='ignore')
                    err = 0 if comm == self.community else 2
                    # Build GetResponse
                    vb = bytes([0x30, 0x00])
                    vl = bytes([0x30, len(vb)]) + vb
                    rq = (bytes([0x02,0x01,0x00]) + bytes([0x02,0x01,err]) +
                          bytes([0x02,0x01,0x00]) + vl)
                    pdu = bytes([0xA2, len(rq)]) + rq
                    cm = bytes([0x04, 0x06, 0x70,0x75,0x62,0x6C,0x69,0x63])
                    vr = bytes([0x02, 0x01, 0x01])
                    self._sock.sendto(bytes([0x30, len(vr)+len(cm)+len(pdu)]) + vr + cm + pdu, addr)
            except socket.timeout: continue
            except: break


# ================================================================
# 9. Elasticsearch
# ================================================================

class ESSim(HTTPSimServer):
    def __init__(self, user="elastic", pwd="changeme"):
        super().__init__(f"ES({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        import http.server
        u, p = self.user, self.pwd
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get('Authorization', '')
                if not auth:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="security"')
                    self.end_headers()
                    return
                try:
                    creds = base64.b64decode(auth.split()[1]).decode()
                    cu, cp = creds.split(':', 1)
                    if cu == u and cp == p:
                        self.send_response(200); self.end_headers()
                        self.wfile.write(b'{"name":"test-node","cluster_name":"test"}')
                    else:
                        self.send_response(401)
                        self.send_header('WWW-Authenticate', 'Basic realm="security"')
                        self.end_headers()
                except:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="security"')
                    self.end_headers()
            def log_message(self, *a): pass
        self._httpd = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), H)
        self._httpd.serve_forever()

    def stop(self):
        try: self._httpd.shutdown()
        except: pass


# ================================================================
# 10. RTSP
# ================================================================

class RTSPSim(SimServer):
    def __init__(self, user="admin", pwd="camera123"):
        super().__init__(f"RTSP({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(3.0)
                data = b''
                try:
                    while b'\r\n\r\n' not in data:
                        chunk = c.recv(4096)
                        if not chunk: break
                        data += chunk
                        if len(data) > 8192: break
                except: pass
                resp1 = data.decode('utf-8', errors='ignore')
                if 'DESCRIBE' in resp1:
                    nonce = base64.b64encode(os.urandom(16)).decode()[:24]
                    c.send(('RTSP/1.0 401 Unauthorized\r\n'
                           f'WWW-Authenticate: Digest realm="camera", nonce="{nonce}"\r\n'
                           'CSeq: 1\r\n\r\n').encode())
                    data2 = b''
                    try:
                        while b'\r\n\r\n' not in data2:
                            chunk = c.recv(4096)
                            if not chunk: break
                            data2 += chunk
                            if len(data2) > 8192: break
                    except: pass
                    resp2 = data2.decode('utf-8', errors='ignore')
                    # Actually verify Digest response hash
                    import re as _re
                    m = _re.search(r'Authorization:\s*Digest\s+(.*)', resp2, _re.IGNORECASE)
                    params = {}
                    if m:
                        for part in m.group(1).split(','):
                            kv = part.strip().split('=', 1)
                            if len(kv) == 2:
                                params[kv[0].strip()] = kv[1].strip().strip('"')
                    rx_user = params.get('username', '')
                    rx_realm = params.get('realm', '')
                    rx_nonce = params.get('nonce', '')
                    rx_uri = params.get('uri', '')
                    rx_response = params.get('response', '')
                    base_uri = rx_uri if rx_uri else f"rtsp://{c.getpeername()[0]}:{self.port}/"
                    ha1 = hashlib.md5(f"{rx_user}:{rx_realm}:{self.pwd}".encode()).hexdigest()
                    ha2 = hashlib.md5(f"DESCRIBE:{base_uri}".encode()).hexdigest()
                    expected_resp = hashlib.md5(f"{ha1}:{rx_nonce}:{ha2}".encode()).hexdigest()
                    if rx_response == expected_resp:
                        c.send(b'RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n')
                    else:
                        c.send(b'RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n')
                c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 11. LDAP
# ================================================================

class LDAPSim(SimServer):
    def __init__(self, user="cn=admin,dc=example,dc=com", pwd="ldappass"):
        super().__init__(f"LDAP({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(0.5)
                data = b''
                while True:
                    try:
                        chunk = c.recv(4096)
                        if not chunk: break
                        data += chunk
                    except socket.timeout:
                        break  # no more data coming, proceed
                    if len(data) > 65536: break
                pw_ok = self.pwd.encode('utf-8') in data
                err = b'\x0a\x01\x00' if pw_ok else b'\x0a\x01\x31'
                content = (bytes([0x02,0x01,0x01]) +
                          bytes([0x04,0x00]) +
                          err)
                bind_resp = (bytes([0x61]) + _ber_len_content(len(content)) + content)
                seq = bytes([0x30]) + _ber_len_content(len(bind_resp)) + bind_resp
                c.send(seq)
                time.sleep(0.05)
                c.close()
            except socket.timeout: continue
            except Exception as e:
                break


# ================================================================
# 12. VNC
# ================================================================

class VNCSim(SimServer):
    def __init__(self, pwd="password"):
        super().__init__(f"VNC(pwd={pwd})")
        self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(2.0)
                pv = b'RFB 003.008\n'
                c.send(pv)
                cpv = b''
                while len(cpv) < 12:
                    try:
                        chunk = c.recv(12 - len(cpv))
                        if not chunk: break
                        cpv += chunk
                    except socket.timeout: break
                if len(cpv) < 12:
                    c.close(); continue
                c.send(b'\x01\x02')
                ch = b''
                while len(ch) < 1:
                    try:
                        chunk = c.recv(1 - len(ch))
                        if not chunk: break
                        ch += chunk
                    except socket.timeout: break
                if len(ch) < 1:
                    c.close(); continue
                challenge = os.urandom(16)
                c.send(challenge)
                resp = b''
                while len(resp) < 16:
                    try:
                        chunk = c.recv(16 - len(resp))
                        if not chunk: break
                        resp += chunk
                    except socket.timeout: break
                key = self.pwd.encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
                key = bytes([_VNC_REV[b] for b in key])
                cipher = DES.new(key, DES.MODE_ECB)
                expected = cipher.encrypt(challenge)
                if resp == expected:
                    c.send(struct.pack('>I', 0))
                else:
                    c.send(struct.pack('>I', 1))
                c.close()
            except socket.timeout: continue
            except Exception as e:
                break


# ================================================================
# 13. WinRM (HTTP + NTLM)
# ================================================================

class WinRMSim(SimServer):
    """Minimal WinRM simulation — NTLM handshake with NTLMv2 verification."""
    def __init__(self, user="admin", pwd="winrmpass"):
        super().__init__(f"WinRM({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _recv_http(self, sock, timeout=8.0):
        """Read HTTP request until \r\n\r\n seen."""
        sock.settimeout(timeout)
        data = b''
        try:
            while b'\r\n\r\n' not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
        except socket.timeout:
            pass
        return data

    def _verify_ntlmv2(self, auth_msg, server_challenge):
        """Parse NTLMSSP Type 3 and verify NTLMv2 response against self.pwd.
        Returns (is_valid, username_str)."""
        if len(auth_msg) < 72 or auth_msg[:8] != b'NTLMSSP\x00':
            return False, ''
        msg_type = struct.unpack_from('<I', auth_msg, 8)[0]
        if msg_type != 3:
            return False, ''

        nt_len = struct.unpack_from('<H', auth_msg, 20)[0]
        nt_off = struct.unpack_from('<I', auth_msg, 24)[0]
        user_len = struct.unpack_from('<H', auth_msg, 36)[0]
        user_off = struct.unpack_from('<I', auth_msg, 40)[0]
        dom_len = struct.unpack_from('<H', auth_msg, 28)[0]
        dom_off = struct.unpack_from('<I', auth_msg, 32)[0]

        if nt_len < 16 or nt_off + nt_len > len(auth_msg):
            return False, ''
        nt_response = auth_msg[nt_off:nt_off + nt_len]
        nt_proof = nt_response[:16]
        blob = nt_response[16:]

        user_bytes = auth_msg[user_off:user_off + user_len] if user_len > 0 else b''
        dom_bytes = auth_msg[dom_off:dom_off + dom_len] if dom_len > 0 else b''
        try:
            username = user_bytes.decode('utf-16le', errors='ignore')
        except:
            username = ''

        # Compute expected NTLMv2 response
        nt_hash = _md4(self.pwd.encode('utf-16le'))
        user_up = self.user.upper().encode('utf-16le')
        dom_up = dom_bytes.decode('utf-16le', errors='ignore').upper().encode('utf-16le') if dom_bytes else b''
        ntlm_v2_hash = hmac.new(nt_hash, user_up + dom_up, hashlib.md5).digest()
        expected_proof = hmac.new(ntlm_v2_hash, server_challenge + blob, hashlib.md5).digest()

        return (nt_proof == expected_proof), username

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()

                # Step 1: Return 401 + WWW-Authenticate: Negotiate
                req1 = self._recv_http(c)
                if not req1:
                    c.close(); continue
                c.send(b'HTTP/1.1 401 Unauthorized\r\n'
                       b'WWW-Authenticate: Negotiate\r\n'
                       b'Connection: Keep-Alive\r\n\r\n')

                # Step 2: Receive NTLMSSP Negotiate, respond with Challenge
                req2 = self._recv_http(c)
                if not req2:
                    c.close(); continue
                import re as _re2
                m = _re2.search(rb'Authorization:\s*Negotiate\s+([A-Za-z0-9+/=]+)', req2)
                if not m:
                    c.send(b'HTTP/1.1 401 Unauthorized\r\n\r\n')
                    c.close(); continue

                challenge = os.urandom(8)
                ti = struct.pack('<HH', 2, 4) + b'TEMP'
                ch_pkt = (b'NTLMSSP\x00' + struct.pack('<I', 2) +
                         struct.pack('<HHI', 0, 0, 0) +
                         struct.pack('<I', 0x00088201) +
                         challenge + b'\x00' * 8 +
                         struct.pack('<HHI', len(ti), len(ti), 48) +
                         struct.pack('<I', 0x0601B01D) +
                         struct.pack('<I', 0x0000000F) +
                         b'\x00' * 8 + ti)
                chal_b64 = base64.b64encode(ch_pkt).decode()
                c.send(f'HTTP/1.1 401 Unauthorized\r\n'
                       f'WWW-Authenticate: Negotiate {chal_b64}\r\n'
                       f'Connection: Keep-Alive\r\n\r\n'.encode())

                # Step 3: Receive NTLMSSP Authenticate, verify NTLMv2
                req3 = self._recv_http(c)
                if not req3:
                    c.close(); continue
                m2 = _re2.search(rb'Authorization:\s*Negotiate\s+([A-Za-z0-9+/=]+)', req3)
                if m2:
                    auth_token = base64.b64decode(m2.group(1))
                    valid, _ = self._verify_ntlmv2(auth_token, challenge)
                    if valid:
                        c.send(b'HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n\r\nok')
                    else:
                        c.send(b'HTTP/1.1 401 Unauthorized\r\n\r\n')
                else:
                    c.send(b'HTTP/1.1 401 Unauthorized\r\n\r\n')
                c.close()
            except socket.timeout: continue
            except: break




# 19. SMTP

class SMTPSim(SimServer):
    def __init__(self, user="mailuser", pwd="mailpass"):
        super().__init__(f"SMTP({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                c.send(b"220 smtp.local ESMTP\r\n")
                # Wait for EHLO
                c.recv(4096)
                c.send(b"250-smtp.local\r\n250 AUTH LOGIN PLAIN\r\n")
                # Wait for AUTH command
                c.recv(4096)
                c.send(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                # Read base64 username
                u_raw = c.recv(4096).strip()
                u_dec = base64.b64decode(u_raw).decode()
                if u_dec == self.user:
                    c.send(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                    p_raw = c.recv(4096).strip()
                    p_dec = base64.b64decode(p_raw).decode()
                    if p_dec == self.pwd:
                        c.send(b"235 Authentication successful\r\n")
                    else:
                        c.send(b"535 Authentication failed\r\n")
                else:
                    c.send(b"535 Authentication failed\r\n")
                time.sleep(0.1); c.close()
            except socket.timeout: continue
            except: break

# 20. IMAP

class IMAPSim(SimServer):
    def __init__(self, user="mailuser", pwd="mailpass"):
        super().__init__(f"IMAP({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                c.send(b"* OK IMAP4rev1 ready\r\n")
                cmd = c.recv(4096).decode("utf-8", errors="ignore")
                if f"LOGIN {self.user} {self.pwd}" in cmd:
                    c.send(b"a001 OK LOGIN completed\r\n")
                else:
                    c.send(b"a001 NO LOGIN failed\r\n")
                time.sleep(0.1); c.close()
            except socket.timeout: continue
            except: break

# 21. POP3

class POP3Sim(SimServer):
    def __init__(self, user="mailuser", pwd="mailpass"):
        super().__init__(f"POP3({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)
                c.send(b"+OK POP3 ready\r\n")
                # Read USER
                c.recv(4096)
                c.send(b"+OK\r\n")
                # Read PASS
                pw_cmd = c.recv(4096).decode("utf-8", errors="ignore")
                if f"PASS {self.pwd}" in pw_cmd:
                    c.send(b"+OK mailbox locked\r\n")
                else:
                    c.send(b"-ERR authentication failed\r\n")
                time.sleep(0.1); c.close()
            except socket.timeout: continue
            except: break


# ================================================================
# 22. SSH (paramiko-based mock server)
# ================================================================

class SSHSim(SimServer):
    """Minimal SSH server using paramiko ServerInterface."""
    def __init__(self, user="sshuser", pwd="sshpass"):
        super().__init__(f"SSH({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _serve(self):
        import paramiko
        host_key = paramiko.RSAKey.generate(1024)

        class Server(paramiko.ServerInterface):
            def __init__(self, username, password):
                self._u = username; self._p = password
            def check_auth_password(self, username, password):
                if username == self._u and password == self._p:
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED
            def get_allowed_auths(self, username):
                return "password"

        while self._running:
            try:
                self._sock.settimeout(1.0)
                client, _ = self._sock.accept()
                t = paramiko.Transport(client)
                t.add_server_key(host_key)
                try:
                    t.start_server(server=Server(self.user, self.pwd))
                except paramiko.SSHException:
                    t.close()
                    continue
                # Wait for auth completion (accept blocks until auth done)
                try:
                    t.accept(10)
                except Exception:
                    pass
                t.close()
            except socket.timeout:
                continue
            except Exception:
                pass


# ================================================================
# 23. RDP NLA (CredSSP + TLS + NTLMSSP)
# ================================================================

class RDPSim(SimServer):
    """RDP NLA/CredSSP simulator with TLS and NTLMv2 auth verification."""
    def __init__(self, user="admin", pwd="rdppass"):
        super().__init__(f"RDP-NLA({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _verify_ntlmv2(self, auth_msg, server_challenge):
        if len(auth_msg) < 72 or auth_msg[:8] != b'NTLMSSP\x00':
            return False
        msg_type = struct.unpack_from('<I', auth_msg, 8)[0]
        if msg_type != 3:
            return False

        nt_len = struct.unpack_from('<H', auth_msg, 20)[0]
        nt_off = struct.unpack_from('<I', auth_msg, 24)[0]
        user_len = struct.unpack_from('<H', auth_msg, 36)[0]
        user_off = struct.unpack_from('<I', auth_msg, 40)[0]

        if nt_len < 16 or nt_off + nt_len > len(auth_msg):
            return False
        nt_response = auth_msg[nt_off:nt_off + nt_len]
        nt_proof = nt_response[:16]
        blob = nt_response[16:]

        u_end = user_off + user_len if user_len > 0 else user_off
        if u_end > len(auth_msg):
            return False

        nt_hash = _md4(self.pwd.encode('utf-16le'))
        user_up = self.user.upper().encode('utf-16le')
        ntlm_v2_hash = hmac.new(nt_hash, user_up, hashlib.md5).digest()
        expected_proof = hmac.new(ntlm_v2_hash, server_challenge + blob, hashlib.md5).digest()
        return nt_proof == expected_proof

    def _build_rdp_nego_resp(self):
        """TPKT + X.224 CC + RDP Negotiation Response (NLA=0x04)."""
        rdp_neg_resp = struct.pack('<BBHI', 0x02, 0x00, 0x0008, 0x00000004)
        x224_body = rdp_neg_resp
        x224_cc = bytes([len(x224_body) + 1, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00]) + x224_body
        tpkt = bytes([0x03, 0x00]) + struct.pack('>H', 4 + len(x224_cc))
        return tpkt + x224_cc

    def _build_tsrequest(self, nego_tokens):
        """TSRequest SEQUENCE { version[0]=2, negoTokens[1] }."""
        ver = b'\xa0\x03\x02\x01\x02'
        nego = b'\xa1' + _ber_len_content(len(nego_tokens)) + nego_tokens
        seq_body = ver + nego
        return b'\x30' + _ber_len_content(len(seq_body)) + seq_body

    def _parse_tsrequest(self, data):
        """Parse TSRequest, extract negoTokens from TPKT framing."""
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
                if tag == 0xa1:  # negoTokens
                    return buf[idx:idx + tag_len]
                idx += tag_len
            return None
        except Exception:
            return None

    def _spnego_wrap_token(self, token):
        """Wrap any NTLMSSP token in SPNEGO NegTokenResp wrapper."""
        resp = b'\xa2' + _ber_len_content(len(token)) + token
        neg = b'\x30' + _ber_len_content(len(resp)) + resp
        oid = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
        body = oid + neg
        return b'\x60' + _ber_len_content(len(body)) + body

    def _serve(self):
        import ssl as _ssl
        import tempfile, datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import rsa

        while self._running:
            try:
                self._sock.settimeout(1.0)
                client, _ = self._sock.accept()
                client.settimeout(8.0)

                # Step 1: Receive RDP Negotiation Request
                nego_req = client.recv(4096)
                if len(nego_req) < 8:
                    client.close(); continue

                # Step 2: Send RDP Negotiation Response (NLA selected)
                client.send(self._build_rdp_nego_resp())

                # Step 3: TLS handshake
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-rdp")])
                cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
                    .public_key(key.public_key()).serial_number(1)\
                    .not_valid_before(datetime.datetime.now(datetime.UTC))\
                    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))\
                    .sign(key, hashes.SHA256())
                cert_pem = cert.public_bytes(_ser.Encoding.PEM)
                key_pem = key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                            _ser.NoEncryption())
                cf = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
                kf = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
                cf.write(cert_pem); cf.close()
                kf.write(key_pem); kf.close()
                try:
                    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cf.name, kf.name)
                    tls_sock = ctx.wrap_socket(client, server_side=True)
                except Exception:
                    client.close()
                    os.unlink(cf.name); os.unlink(kf.name)
                    continue

                # Step 4: Receive NTLMSSP Negotiate (Type 1) in SPNEGO+TSRequest
                req1 = tls_sock.recv(4096)
                if not req1:
                    tls_sock.close(); os.unlink(cf.name); os.unlink(kf.name)
                    continue

                # Step 5: Send NTLMSSP Challenge (Type 2)
                server_challenge = os.urandom(8)
                ti = struct.pack('<HH', 2, 4) + b'TEMP'
                ch_pkt = (b'NTLMSSP\x00' + struct.pack('<I', 2) +
                         struct.pack('<HHI', 0, 0, 0) +
                         struct.pack('<I', 0x00088201) +
                         server_challenge + b'\x00' * 8 +
                         struct.pack('<HHI', len(ti), len(ti), 48) +
                         struct.pack('<I', 0x0601B01D) +
                         struct.pack('<I', 0x0000000F) +
                         b'\x00' * 8 + ti)
                tsreq_ch = _rdp_build_tsrequest(self._spnego_wrap_token(ch_pkt))
                tls_sock.send(tsreq_ch)

                # Step 6: Receive NTLMSSP Authenticate (Type 3) — use real parse/unwrap
                req2 = tls_sock.recv(4096)
                if not req2:
                    tls_sock.close(); os.unlink(cf.name); os.unlink(kf.name)
                    continue

                spnego_blob = _rdp_parse_tsrequest(req2)
                if not spnego_blob:
                    tls_sock.close(); os.unlink(cf.name); os.unlink(kf.name)
                    continue

                inner = _spnego_unwrap(spnego_blob)
                valid = False
                if inner and len(inner) >= 72:
                    valid = self._verify_ntlmv2(inner, server_challenge)

                if valid:
                    dummy = b'NTLMSSP\x00' + struct.pack('<I', 0)
                    tls_sock.send(_rdp_build_tsrequest(self._spnego_wrap_token(dummy)))
                else:
                    tls_sock.send(tsreq_ch)  # re-send challenge → client ftype==2 → False

                tls_sock.close()
                os.unlink(cf.name); os.unlink(kf.name)
            except socket.timeout:
                continue
            except Exception:
                pass


# ================================================================
# 24. SMBv2 (NetBIOS + NTLMSSP Session Setup)
# ================================================================

class SMBv2Sim(SimServer):
    """SMBv2 mock with NTLMv2 Session Setup authentication."""
    def __init__(self, user="admin", pwd="smbpass"):
        super().__init__(f"SMBv2({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _verify_ntlmv2(self, auth_msg, server_challenge):
        if len(auth_msg) < 72 or auth_msg[:8] != b'NTLMSSP\x00':
            return False
        msg_type = struct.unpack_from('<I', auth_msg, 8)[0]
        if msg_type != 3:
            return False
        nt_len = struct.unpack_from('<H', auth_msg, 20)[0]
        nt_off = struct.unpack_from('<I', auth_msg, 24)[0]
        if nt_len < 16 or nt_off + nt_len > len(auth_msg):
            return False
        nt_response = auth_msg[nt_off:nt_off + nt_len]
        nt_proof = nt_response[:16]
        blob = nt_response[16:]
        nt_hash = _md4(self.pwd.encode('utf-16le'))
        user_up = self.user.upper().encode('utf-16le')
        ntlm_v2_hash = hmac.new(nt_hash, user_up, hashlib.md5).digest()
        expected_proof = hmac.new(ntlm_v2_hash, server_challenge + blob, hashlib.md5).digest()
        return nt_proof == expected_proof

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)

                # --- SMBv2 Negotiate ---
                nb_hdr = c.recv(4)
                if len(nb_hdr) < 4:
                    c.close(); continue
                nb_len = struct.unpack('>I', nb_hdr)[0]
                body = c.recv(nb_len)
                if len(body) < 64 or body[0:4] != b'\xfeSMB':
                    c.close(); continue

                # Build negotiate response
                neg_hdr = b'\xfeSMB'
                neg_hdr += struct.pack('<H', 64)  # StructureSize
                neg_hdr += struct.pack('<H', 0)  # CreditCharge
                neg_hdr += struct.pack('<I', 0)  # Status: SUCCESS
                neg_hdr += struct.pack('<H', 0)  # Command: NEGOTIATE
                neg_hdr += struct.pack('<H', 2)  # CreditResponse
                neg_hdr += struct.pack('<I', 0)  # Flags
                neg_hdr += struct.pack('<I', 0)  # NextCommand
                neg_hdr += struct.pack('<Q', 1)  # MessageId
                neg_hdr += struct.pack('<I', 0)  # Reserved
                neg_hdr += struct.pack('<I', 0)  # TreeId
                neg_hdr += struct.pack('<Q', 0)  # SessionId
                neg_hdr += b'\x00' * 16  # Signature

                # Negotiate response body
                neg_body = struct.pack('<H', 65)  # StructureSize
                neg_body += struct.pack('<H', 1)  # SecurityMode: SIGNING_ENABLED
                neg_body += struct.pack('<H', 0x0311)  # Dialect: SMB 3.1.1
                neg_body += b'\x00'  # NegotiateContextCount
                neg_body += struct.pack('<H', 0x50)  # ServerGuid offset
                neg_body += struct.pack('<H', 0x10)  # ServerGuid len
                neg_body += struct.pack('<I', 0x01)  # Capabilities
                neg_body += struct.pack('<I', 65535)  # MaxTransactSize
                neg_body += struct.pack('<I', 65535)  # MaxReadSize
                neg_body += struct.pack('<I', 65535)  # MaxWriteSize
                neg_body += struct.pack('<Q', 0)  # SystemTime
                neg_body += struct.pack('<Q', 0)  # BootTime
                neg_body += struct.pack('<H', 0)  # SecBufOffset
                neg_body += struct.pack('<H', 0)  # SecBufLength
                neg_body += b'\x00' * 4  # padding
                neg_body += os.urandom(16)  # ServerGuid
                neg_pkt = neg_hdr + neg_body
                c.send(struct.pack('>I', len(neg_pkt)) + neg_pkt)

                # --- Session Setup 1: NTLMSSP Negotiate ---
                nb1 = c.recv(4)
                if len(nb1) < 4: c.close(); continue
                nlen1 = struct.unpack('>I', nb1)[0]
                ss1 = c.recv(nlen1)
                if len(ss1) < 80:
                    c.close(); continue
                # Client request: body has StructureSize(2)+Flags(1)+SecMode(1)+Capabilities(4)+Channel(4)=12 bytes
                # SecurityBufferOffset is at body offset 12 = packet offset 64+12 = 76
                sec_off1 = struct.unpack('<H', ss1[76:78])[0]
                sec_len1 = struct.unpack('<H', ss1[78:80])[0]
                if sec_off1 + sec_len1 > len(ss1):
                    c.close(); continue

                # Build Session Setup response with NTLMSSP Challenge
                server_challenge = os.urandom(8)
                ti = struct.pack('<HH', 2, 4) + b'TEMP'
                ch_pkt = (b'NTLMSSP\x00' + struct.pack('<I', 2) +
                         struct.pack('<HHI', 0, 0, 0) +
                         struct.pack('<I', 0x00088201) +
                         server_challenge + b'\x00' * 8 +
                         struct.pack('<HHI', len(ti), len(ti), 48) +
                         struct.pack('<I', 0x0601B01D) +
                         struct.pack('<I', 0x0000000F) +
                         b'\x00' * 8 + ti)

                ss_hdr = b'\xfeSMB'
                ss_hdr += struct.pack('<H', 64)
                ss_hdr += struct.pack('<H', 0)
                ss_hdr += struct.pack('<I', 0xC0000016)  # STATUS_MORE_PROCESSING_REQUIRED
                ss_hdr += struct.pack('<H', 1)  # Command: SESSION_SETUP
                ss_hdr += struct.pack('<H', 2)
                ss_hdr += struct.pack('<I', 0)
                ss_hdr += struct.pack('<I', 0)
                ss_hdr += struct.pack('<Q', 2)
                ss_hdr += struct.pack('<I', 0)
                ss_hdr += struct.pack('<I', 0)
                ss_hdr += struct.pack('<Q', 1)  # SessionId=1
                ss_hdr += b'\x00' * 16

                # Response body: StructureSize(2)+SessionFlags(2)=4
                # SecurityBufferOffset at body offset 4 = packet offset 68
                # Client reads at resp[72:74] which is body[4:6] (resp = NetBIOS(4) + header(64) + body)
                ss_body = struct.pack('<H', 9)              # StructureSize
                ss_body += struct.pack('<H', 0)             # SessionFlags (2 bytes)
                sec_off = 4 + 64 + 8                        # NetBIOS + header + body = 76
                ss_body += struct.pack('<H', sec_off)       # SecurityBufferOffset (at body offset 4)
                ss_body += struct.pack('<H', len(ch_pkt))   # SecurityBufferLength
                ss_resp1 = ss_hdr + ss_body + ch_pkt
                c.send(struct.pack('>I', len(ss_resp1)) + ss_resp1)

                # --- Session Setup 2: NTLMSSP Authenticate ---
                nb2 = c.recv(4)
                if len(nb2) < 4:
                    c.close(); continue
                nlen2 = struct.unpack('>I', nb2)[0]
                ss2 = c.recv(nlen2)
                if len(ss2) < 88:
                    c.close(); continue

                # Client request has same structure: sec_off at body offset 12 = packet offset 76
                sec_off2 = struct.unpack('<H', ss2[76:78])[0]
                sec_len2 = struct.unpack('<H', ss2[78:80])[0]
                if sec_off2 + sec_len2 > len(ss2):
                    c.close(); continue
                auth_blob = ss2[sec_off2:sec_off2 + sec_len2]

                valid = self._verify_ntlmv2(auth_blob, server_challenge)

                ss_hdr2 = b'\xfeSMB'
                ss_hdr2 += struct.pack('<H', 64)
                ss_hdr2 += struct.pack('<H', 0)
                ss_hdr2 += struct.pack('<I', 0 if valid else 0xC000006D)  # SUCCESS or LOGON_FAILURE
                ss_hdr2 += struct.pack('<H', 1)
                ss_hdr2 += struct.pack('<H', 2)
                ss_hdr2 += struct.pack('<I', 0)
                ss_hdr2 += struct.pack('<I', 0)
                ss_hdr2 += struct.pack('<Q', 3)
                ss_hdr2 += struct.pack('<I', 0)
                ss_hdr2 += struct.pack('<I', 0)
                ss_hdr2 += struct.pack('<Q', 1)
                ss_hdr2 += b'\x00' * 16

                ss_body2 = struct.pack('<H', 9) + struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<H', 0)
                ss_resp2 = ss_hdr2 + ss_body2
                c.send(struct.pack('>I', len(ss_resp2)) + ss_resp2)

                c.close()
            except socket.timeout:
                continue
            except Exception:
                pass


# ================================================================
# 25. MySQL caching_sha2_password
# ================================================================

class MySQLCacheSha2Sim(SimServer):
    """MySQL handshake advertising caching_sha2_password — XOR fast auth verification."""
    def __init__(self, user="root", pwd="mysqlsha2"):
        super().__init__(f"MySQL-cache-sha2({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _compute_xor_response(self, password, auth_data):
        p1 = hashlib.sha256(password.encode()).digest()
        p2 = hashlib.sha256(p1).digest()
        p3 = hashlib.sha256(p2 + auth_data).digest()
        return bytes(a ^ b for a, b in zip(p1, p3))

    def _serve(self):
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)

                auth_data = os.urandom(20)
                proto = 10
                sv = b'8.0.35-test\x00'
                caps_lower = 0xFFF7
                body = (bytes([proto]) + sv + struct.pack('<I', 1) +
                        auth_data[:8] + b'\x00' +
                        struct.pack('<H', caps_lower) + bytes([8]) +
                        struct.pack('<H', 0x0002) + struct.pack('<H', 0xFFFF) +
                        bytes([20]) + b'\x00' * 10 + auth_data[8:20] + b'caching_sha2_password\x00')
                hdr = struct.pack('<I', len(body))[:3] + bytes([0])
                c.send(hdr + body)

                # Receive client response
                resp = b''
                try:
                    h = c.recv(4)
                    if len(h) >= 4:
                        plen = h[0] | (h[1] << 8) | (h[2] << 16)
                        resp = h + c.recv(plen)
                except Exception:
                    pass

                if len(resp) < 5:
                    c.close(); continue

                payload = resp[4:]
                # Skip caps(4) + max_pkt(4) + charset(1) + reserved(23)
                pos = 4 + 4 + 1 + 23
                while pos < len(payload) and payload[pos] != 0:
                    pos += 1
                pos += 1  # skip null terminator of username
                if pos < len(payload):
                    alen = payload[pos]; pos += 1
                    client_resp = payload[pos:pos + alen]
                    expected = self._compute_xor_response(self.pwd, auth_data)
                    if client_resp == expected:
                        ok_pkt = struct.pack('<I', 7)[:3] + bytes([2]) + b'\x00\x00\x00\x02\x00\x00\x00'
                        c.send(ok_pkt)
                    else:
                        err_pkt = (struct.pack('<I', 7)[:3] + bytes([2]) +
                                  b'\xff\x15\x04\x23\x32\x38\x30\x30\x30Access denied\x00')
                        c.send(err_pkt)
                c.close()
            except socket.timeout:
                continue
            except Exception:
                pass


# ================================================================
# 26. MongoDB SCRAM-SHA-256 + SCRAM-SHA-1
# ================================================================

class MongoSCRAMSim(SimServer):
    """MongoDB wire protocol with full SCRAM-SHA-256/SHA-1 SASL exchange."""
    def __init__(self, user="admin", pwd="mongopass"):
        super().__init__(f"Mongo-SCRAM({user}:{pwd})")
        self.user = user; self.pwd = pwd

    def _build_opmsg(self, msg_id, doc_bytes):
        section = bytes([0]) + doc_bytes
        body = struct.pack('<I', 0) + section
        return struct.pack('<IIII', 16 + len(body), msg_id, 0, 2013) + body

    def _parse_opmsg(self, data):
        if len(data) < 22:
            return 0, b''
        flags = struct.unpack('<I', data[16:20])[0]
        return flags, data[21:]  # skip section kind byte

    def _serve(self):
        import base64 as _b64
        while self._running:
            try:
                self._sock.settimeout(1.0)
                c, _ = self._sock.accept()
                c.settimeout(5.0)

                msg_id = 1

                # Step 1: Receive hello
                hello_data = c.recv(4096)
                if len(hello_data) < 20:
                    c.close(); continue

                # Send hello response
                hello_doc = _bson_encode_doc([
                    ('ok', 1), ('maxWireVersion', 13),
                    ('minWireVersion', 0), ('isWritablePrimary', True),
                ])
                c.send(self._build_opmsg(msg_id, hello_doc))
                msg_id += 1

                # Step 2: Receive saslStart
                sasl_data = c.recv(4096)
                if len(sasl_data) < 20:
                    c.close(); continue
                _, sasl_doc = self._parse_opmsg(sasl_data)
                mechanism = _bson_get_string(sasl_doc, 'mechanism') or 'SCRAM-SHA-1'
                payload_b64 = _bson_get_string(sasl_doc, 'payload') or ''
                client_first = _b64.b64decode(payload_b64).decode('utf-8', errors='ignore')

                # Parse client nonce from client_first
                parts = {}
                for p in client_first.split(','):
                    if '=' in p: k, v = p.split('=', 1); parts[k] = v
                client_nonce = parts.get('r', '')
                username = parts.get('n', '')

                # Generate server-first
                if mechanism == 'SCRAM-SHA-256':
                    hash_name = 'sha256'
                    dklen = 32
                else:
                    hash_name = 'sha1'
                    dklen = 20

                server_nonce = _b64.b64encode(os.urandom(18)).decode('ascii')
                salt = os.urandom(16)
                salt_b64 = _b64.b64encode(salt).decode('ascii')
                iterations = 4096
                server_first = f"r={client_nonce}{server_nonce},s={salt_b64},i={iterations}"
                server_first_b64 = _b64.b64encode(server_first.encode('utf-8')).decode('ascii')

                conv_id = random.randint(1, 999999)

                sasl_start_doc = _bson_encode_doc([
                    ('ok', 1), ('conversationId', conv_id),
                    ('payload', server_first_b64), ('done', False),
                ])
                c.send(self._build_opmsg(msg_id, sasl_start_doc))
                msg_id += 1

                # Step 3: Receive saslContinue
                continue_data = c.recv(4096)
                if len(continue_data) < 20:
                    c.close(); continue
                _, continue_doc = self._parse_opmsg(continue_data)
                cv_id = _bson_get_int32(continue_doc, 'conversationId')
                cf_payload = _bson_get_string(continue_doc, 'payload') or ''
                client_final = _b64.b64decode(cf_payload).decode('utf-8', errors='ignore')

                # Parse client-final (c=...,r=...,p=...)
                cf_parts = {}
                for p in client_final.split(','):
                    if '=' in p: k, v = p.split('=', 1); cf_parts[k] = v
                proof_b64 = cf_parts.get('p', '')
                combined_nonce = cf_parts.get('r', '')

                # Verify proof
                salted_pw = hashlib.pbkdf2_hmac(hash_name, self.pwd.encode('utf-8'), salt, iterations, dklen)

                if dklen == 32:
                    hmac_fn = _hmac_sha256
                else:
                    hmac_fn = _hmac_sha1
                client_key = hmac_fn(salted_pw, b"Client Key")
                stored_key = hashlib.new(hash_name, client_key).digest()

                c_final_no_proof = f"c=biws,r={combined_nonce}"
                # RFC 5802: client-first-bare MUST include n=<username>
                auth_msg = f"n={self.user},r={client_nonce},{server_first},{c_final_no_proof}"

                client_sig = hmac_fn(stored_key, auth_msg.encode('utf-8'))
                expected_proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
                expected_proof_b64 = _b64.b64encode(expected_proof).decode('ascii')

                if proof_b64 == expected_proof_b64:
                    server_key = hmac_fn(salted_pw, b"Server Key")
                    server_sig = hmac_fn(server_key, auth_msg.encode('utf-8'))
                    server_sig_b64 = _b64.b64encode(server_sig).decode('ascii')
                    final_payload = f"v={server_sig_b64}"
                    sasl_final_doc = _bson_encode_doc([
                        ('ok', 1), ('conversationId', cv_id),
                        ('payload', _b64.b64encode(final_payload.encode('utf-8')).decode('ascii')),
                        ('done', True),
                    ])
                else:
                    sasl_final_doc = _bson_encode_doc([
                        ('ok', 0), ('errmsg', 'Authentication failed'),
                        ('code', 18),
                    ])

                c.send(self._build_opmsg(msg_id, sasl_final_doc))
                c.close()
            except socket.timeout:
                continue
            except Exception:
                pass


# ================================================================
# Main Test Runner
# ================================================================

def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def test_trio(name, tester_fn, sim, good_user, good_pwd, bad_user, bad_pwd,
              cross_sim=None, cross_user="x", cross_pwd="x"):
    """Standard three-way test: correct creds, wrong creds, cross-protocol."""
    if sim:
        # A) Correct credentials
        r = tester_fn(*sim.addr, good_user, good_pwd)
        check(f"{name}: correct creds", True, r)

        # B) Wrong credentials
        r = tester_fn(*sim.addr, bad_user, bad_pwd)
        check(f"{name}: wrong creds", False, r)

    # C) Non-matching service (cross-protocol check)
    if cross_sim:
        r = tester_fn(*cross_sim.addr, cross_user, cross_pwd)
        check(f"{name}: vs non-matching service", False, r)


def main():
    global PASS, FAIL, SKIP

    print("=" * 60)
    print("  弱口令扫描器 — 全协议综合验证集群")
    print(f"  环境: Python {sys.version.split()[0]}, "
          f"paramiko={'YES' if HAS_PARAMIKO else 'NO'}, "
          f"crypto={'YES' if HAS_PYCRYPTO else 'NO'}")
    print("=" * 60)

    sims = []

    # ── 1. HTTP ──
    banner("1. HTTP Basic Auth")
    s1 = HTTPBasicSim("admin", "admin123")
    s1.start(); sims.append(s1)
    test_trio("HTTP", test_http, s1, "admin", "admin123", "admin", "wrongpass")
    # Cross-protocol: test HTTP tester against FTP sim
    s_nonauth = HTTPBasicSim("x", "x")  # unused
    s_nonauth.start(); sims.append(s_nonauth)

    # ── 1b. HTTP Form Login ──
    banner("1b. HTTP Form Login")
    s_form = HTTPFormSim("admin", "admin123")
    s_form.start(); sims.append(s_form)
    r = test_http(*s_form.addr, "admin", "admin123")
    check("HTTP Form: correct creds", True, r)
    r = test_http(*s_form.addr, "admin", "wrongpass")
    check("HTTP Form: wrong creds", False, r)

    # ── 2. Telnet ──
    banner("2. Telnet")
    s2 = TelnetSim("admin", "cisco123")
    s2.start(); sims.append(s2)
    r = test_telnet(*s2.addr, "admin", "cisco123")
    check("Telnet: correct creds", True, r)
    r = test_telnet(*s2.addr, "admin", "wrongpass")
    check("Telnet: wrong creds", False, r)
    r = test_telnet(*s1.addr, "admin", "cisco123")  # vs HTTP server
    check("Telnet: vs HTTP server", False, r)

    # ── 3. FTP ──
    banner("3. FTP")
    s3 = FTPSim("ftpuser", "ftppass")
    s3.start(); sims.append(s3)
    r = test_ftp(*s3.addr, "ftpuser", "ftppass")
    check("FTP: correct creds", True, r)
    r = test_ftp(*s3.addr, "ftpuser", "wrongpass")
    check("FTP: wrong creds", False, r)
    r = test_ftp(*s1.addr, "ftpuser", "ftppass")  # vs HTTP
    check("FTP: vs HTTP server", False, r)

    # ── 4. Redis ──
    banner("4. Redis")
    s4a = RedisSim(None)  # no auth
    s4a.start(); sims.append(s4a)
    r = test_redis(*s4a.addr, "", "")
    check("Redis: no-auth (no creds)", True, r)

    s4b = RedisSim("redispass")
    s4b.start(); sims.append(s4b)
    r = test_redis(*s4b.addr, "", "redispass")
    check("Redis: correct password", True, r)
    r = test_redis(*s4b.addr, "", "wrongpass")
    check("Redis: wrong password", False, r)
    r = test_redis(*s1.addr, "", "redispass")  # vs HTTP
    check("Redis: vs HTTP server", False, r)

    # ── 5. MySQL ──
    banner("5. MySQL (native_password)")
    s5 = MySQLSim("root", "mysql123")
    s5.start(); sims.append(s5)
    r = test_mysql(*s5.addr, "root", "mysql123")
    check("MySQL: correct creds", True, r)
    r = test_mysql(*s5.addr, "root", "wrongpass")
    check("MySQL: wrong creds", False, r)
    r = test_mysql(*s1.addr, "root", "mysql123")  # vs HTTP
    check("MySQL: vs HTTP server", False, r)

    # ── 6. PostgreSQL ──
    banner("6. PostgreSQL (MD5)")
    s6 = PGSim("postgres", "pgpass")
    s6.start(); sims.append(s6)
    r = test_postgresql(*s6.addr, "postgres", "pgpass")
    check("PostgreSQL: correct creds", True, r)
    r = test_postgresql(*s6.addr, "postgres", "wrongpass")
    check("PostgreSQL: wrong creds", False, r)
    r = test_postgresql(*s1.addr, "postgres", "pgpass")
    check("PostgreSQL: vs HTTP server", False, r)

    # ── 6b. PostgreSQL SCRAM-SHA-256 ──
    banner("6b. PostgreSQL (SCRAM-SHA-256)")
    s6b = SimServer("PG-SCRAM")
    scram_pwd = "scrampass"
    def _pgscram_serve():
        import base64 as _b64
        while s6b._running:
            try:
                s6b._sock.settimeout(1.0)
                c, _ = s6b._sock.accept()
                c.settimeout(5.0)
                startup = c.recv(4096)
                msg = bytes([ord('R')]) + struct.pack('>I', 8) + struct.pack('>I', 10)
                c.send(msg)
                resp = c.recv(4096)
                if len(resp) < 9: c.close(); continue
                client_first = resp[13:].decode('utf-8', errors='ignore')
                parts = {}
                for p in client_first.split(','):
                    if '=' in p: k, v = p.split('=', 1); parts[k] = v
                client_nonce = parts.get('r', '')
                username = parts.get("n", "postgres")  # RFC 5802: parse n=<user> from client-first
                server_nonce = _b64.b64encode(os.urandom(18)).decode('ascii')
                salt = os.urandom(16)
                salt_b64 = _b64.b64encode(salt).decode('ascii')
                iterations = 4096
                server_first = f"r={client_nonce}{server_nonce},s={salt_b64},i={iterations}"
                sf_bytes = server_first.encode('utf-8')
                sasl_cont = bytes([ord('R')]) + struct.pack('>I', 8 + len(sf_bytes)) + struct.pack('>I', 11) + sf_bytes
                c.send(sasl_cont)
                resp2 = c.recv(4096)
                if len(resp2) < 9: c.close(); continue
                client_final = resp2[9:].decode('utf-8', errors='ignore')
                cf_parts = {}
                for p in client_final.split(','):
                    if '=' in p: k, v = p.split('=', 1); cf_parts[k] = v
                proof_b64 = cf_parts.get('p', '')
                combined_nonce = cf_parts.get('r', '')
                salted_pw = hashlib.pbkdf2_hmac('sha256', scram_pwd.encode('utf-8'), salt, iterations, 32)
                client_key = hmac.new(salted_pw, b'Client Key', hashlib.sha256).digest()
                stored_key = hashlib.sha256(client_key).digest()
                c_final_no_proof = f"c=biws,r={combined_nonce}"
                # RFC 5802: client-first-bare MUST include n=<username>
                auth_msg = f"n={username},r={client_nonce},{server_first},{c_final_no_proof}"
                client_sig = hmac.new(stored_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
                expected_proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
                expected_proof_b64 = _b64.b64encode(expected_proof).decode('ascii')
                if proof_b64 == expected_proof_b64:
                    server_key = hmac.new(salted_pw, b'Server Key', hashlib.sha256).digest()
                    server_sig = hmac.new(server_key, auth_msg.encode('utf-8'), hashlib.sha256).digest()
                    final = "v=" + _b64.b64encode(server_sig).decode('ascii')
                    final_bytes = final.encode('utf-8')
                    sasl_final = bytes([ord('R')]) + struct.pack('>I', 8 + len(final_bytes)) + struct.pack('>I', 12) + final_bytes
                    c.send(sasl_final)
                else:
                    c.send(bytes([ord('E')]) + struct.pack('>I', 64) + b'S' * 56)
                time.sleep(0.5)
                c.close()
            except socket.timeout: continue
            except: break
    s6b._serve = _pgscram_serve
    s6b.start(); sims.append(s6b)
    r = test_postgresql(*s6b.addr, "postgres", scram_pwd)
    check("PostgreSQL SCRAM: correct creds", True, r)
    r = test_postgresql(*s6b.addr, "postgres", "wrongpass")
    check("PostgreSQL SCRAM: wrong creds", False, r)

    # ── 7. MSSQL ──
    banner("7. MSSQL (TDS)")
    s7 = MSSQLSim("sa", "P@ssw0rd")
    s7.start(); sims.append(s7)
    r = test_mssql(*s7.addr, "sa", "P@ssw0rd")
    check("MSSQL: correct creds", True, r)
    r = test_mssql(*s7.addr, "sa", "wrongpass")
    check("MSSQL: wrong creds", False, r)
    r = test_mssql(*s1.addr, "sa", "P@ssw0rd")  # vs HTTP
    check("MSSQL: vs HTTP server", False, r)

    # ── 8. SNMP ──
    banner("8. SNMP (UDP)")
    s8 = SNMPSim("public")
    s8.start(); sims.append(s8)
    r = test_snmp(*s8.addr, "public")
    check("SNMP: correct community", True, r)
    r = test_snmp(*s8.addr, "private")
    check("SNMP: wrong community", False, r)

    # ── 9. Elasticsearch ──
    banner("9. Elasticsearch (NEW)")
    s9 = ESSim("elastic", "changeme")
    s9.start(); sims.append(s9)
    r = test_elasticsearch(*s9.addr, "elastic", "changeme")
    check("Elasticsearch: correct creds", True, r)
    r = test_elasticsearch(*s9.addr, "elastic", "wrongpass")
    check("Elasticsearch: wrong creds", False, r)
    r = test_elasticsearch(*s1.addr, "elastic", "changeme")  # vs HTTP
    check("Elasticsearch: vs HTTP server", False, r)

    # ── 10. RTSP ──
    banner("10. RTSP")
    s10 = RTSPSim("admin", "camera123")
    s10.start(); sims.append(s10)
    r = test_rtsp(*s10.addr, "admin", "camera123")
    check("RTSP: correct creds", True, r)
    r = test_rtsp(*s10.addr, "admin", "wrongpass")
    check("RTSP: wrong creds", False, r)
    r = test_rtsp(*s1.addr, "admin", "camera123")  # vs HTTP
    check("RTSP: vs HTTP server", False, r)

    # ── 11. LDAP ──
    banner("11. LDAP")
    s11 = LDAPSim("cn=admin,dc=example,dc=com", "ldappass")
    s11.start(); sims.append(s11)
    r = test_ldap(*s11.addr, "cn=admin,dc=example,dc=com", "ldappass")
    check("LDAP: correct creds", True, r)
    r = test_ldap(*s11.addr, "cn=admin,dc=example,dc=com", "wrongpass")
    check("LDAP: wrong creds", False, r)
    r = test_ldap(*s1.addr, "cn=admin,dc=example,dc=com", "ldappass")  # vs HTTP
    check("LDAP: vs HTTP server", False, r)

    # ── 12. VNC ──
    if HAS_PYCRYPTO:
        banner("12. VNC")
        s12 = VNCSim("vncpass1")
        s12.start(); sims.append(s12)
        r = test_vnc(*s12.addr, "", "vncpass1")
        check("VNC: correct password", True, r)
        r = test_vnc(*s12.addr, "", "wrongpass")
        check("VNC: wrong password", False, r)
    else:
        banner("12. VNC — SKIPPED (no pycryptodome)")
        skip("VNC: requires pycryptodome")

    # ── 13. WinRM ──
    banner("13. WinRM (NEW)")
    s13 = WinRMSim("admin", "winrmpass")
    s13.start(); sims.append(s13)
    r = test_winrm(*s13.addr, "admin", "winrmpass")
    check("WinRM: correct creds", True, r)
    r = test_winrm(*s13.addr, "admin", "wrongpass")
    check("WinRM: wrong creds", False, r)
    r = test_winrm(*s1.addr, "admin", "winrmpass")  # vs HTTP
    check("WinRM: vs HTTP server", False, r)
    r = test_winrm(*s2.addr, "admin", "winrmpass")  # vs Telnet
    check("WinRM: vs Telnet server", False, r)

    # ── 14. Oracle (TNS detect mode) ──
    banner("14. Oracle (TNS detect, no oracledb)")
    s14 = SimServer("Oracle-TNS")
    def _ora_serve():
        while s14._running:
            try:
                s14._sock.settimeout(1.0)
                c, _ = s14._sock.accept()
                c.settimeout(3.0)
                c.recv(4096)
                resp = struct.pack('>H', 8) + struct.pack('>H', 0) + b'\x02\x00' + struct.pack('>H', 0)
                c.send(resp); c.close()
            except socket.timeout: continue
            except: break
    s14._serve = _ora_serve
    s14.start(); sims.append(s14)
    # Without oracledb, Oracle tester returns False (TNS detected, creds not verified)
    r = test_oracle(*s14.addr, "system", "manager")
    print(f"  Oracle without oracledb → {r} (expected False — creds cannot be verified)")
    check("Oracle: returns False when oracledb unavailable", False, r)

    # ── 15. SSH (requires paramiko server — test basic) ──
    banner("15. SSH — connection test")
    # SSH can't be fully simulated without a real SSH server.
    # But we can verify it handles connection failure gracefully.
    try: r = test_ssh('127.0.0.1', 19999, 'root', 'password')
    except NetworkError: r = False
    check("SSH: no service (closed port)", False, r)
    if HAS_PARAMIKO:
        print("  paramiko available — SSH tester is functional")
    else:
        skip("SSH: paramiko not available")

    # ── 16. RDP — basic connectivity ──
    banner("16. RDP — connection test")
    try: r = test_rdp('127.0.0.1', 19998, 'admin', 'password')
    except NetworkError: r = False
    check("RDP: no service (closed port)", False, r)

    # ── 17. SMB — basic connectivity ──
    banner("17. SMB — connection test")
    try: r = test_smb('127.0.0.1', 19997, 'admin', 'password')
    except NetworkError: r = False
    check("SMB: no service (closed port)", False, r)

    # ── 18. MongoDB — no auth server ──
    banner("18. MongoDB — no auth detection")
    class MongoNoAuth(SimServer):
        def _serve(self):
            while self._running:
                try:
                    self._sock.settimeout(1.0)
                    c, _ = self._sock.accept()
                    c.settimeout(3.0)
                    c.recv(4096)
                    # Return {ok: 1} for hello (now int32, parsed correctly)
                    doc = _bson_encode_doc([('ok', 1), ('maxWireVersion', 13), ('minWireVersion', 0)])
                    section = bytes([0]) + doc
                    body = struct.pack('<I', 0) + section
                    c.send(struct.pack('<IIII', 16+len(body), 1, 0, 2013) + body)
                    c.recv(4096)  # saslStart — close without responding, simulating auth failure
                    c.close()
                except socket.timeout: continue
                except: break
    s18 = MongoNoAuth("Mongo-auth-required")
    s18.start(); sims.append(s18)
    r = test_mongodb(*s18.addr, 'admin', 'password')
    check("MongoDB: auth failed (wrong creds)", False, r)

    # ── 19. SMTP ──
    banner("19. SMTP")
    s19 = SMTPSim("mailuser", "mailpass")
    s19.start(); sims.append(s19)
    r = test_smtp(*s19.addr, "mailuser", "mailpass")
    check("SMTP: correct creds", True, r)
    r = test_smtp(*s19.addr, "mailuser", "wrongpass")
    check("SMTP: wrong creds", False, r)
    r = test_smtp(*s1.addr, "mailuser", "mailpass")  # vs HTTP
    check("SMTP: vs HTTP server", False, r)

    # ── 20. IMAP ──
    banner("20. IMAP")
    s20 = IMAPSim("mailuser", "mailpass")
    s20.start(); sims.append(s20)
    r = test_imap(*s20.addr, "mailuser", "mailpass")
    check("IMAP: correct creds", True, r)
    r = test_imap(*s20.addr, "mailuser", "wrongpass")
    check("IMAP: wrong creds", False, r)
    r = test_imap(*s1.addr, "mailuser", "mailpass")  # vs HTTP
    check("IMAP: vs HTTP server", False, r)

    # ── 21. POP3 ──
    banner("21. POP3")
    s21 = POP3Sim("mailuser", "mailpass")
    s21.start(); sims.append(s21)
    r = test_pop3(*s21.addr, "mailuser", "mailpass")
    check("POP3: correct creds", True, r)
    r = test_pop3(*s21.addr, "mailuser", "wrongpass")
    check("POP3: wrong creds", False, r)
    r = test_pop3(*s1.addr, "mailuser", "mailpass")  # vs HTTP
    check("POP3: vs HTTP server", False, r)

    # ── 22. SSH ──
    if HAS_PARAMIKO:
        banner("22. SSH (NEW)")
        s22 = SSHSim("sshuser", "sshpass")
        s22.start(); sims.append(s22)
        r = test_ssh(*s22.addr, "sshuser", "sshpass")
        check("SSH: correct creds", True, r)
        r = test_ssh(*s22.addr, "sshuser", "wrongpass")
        check("SSH: wrong creds", False, r)
        r = test_ssh(*s1.addr, "sshuser", "sshpass")  # vs HTTP
        check("SSH: vs HTTP server", False, r)
    else:
        banner("22. SSH — SKIPPED (no paramiko)")
        skip("SSH: paramiko not available")

    # ── 23. RDP NLA ──
    banner("23. RDP NLA (NEW)")
    s23 = RDPSim("admin", "rdppass")
    s23.start(); sims.append(s23)
    r = test_rdp(*s23.addr, "admin", "rdppass")
    check("RDP NLA: correct creds", True, r)
    r = test_rdp(*s23.addr, "admin", "wrongpass")
    check("RDP NLA: wrong creds", False, r)
    r = test_rdp(*s1.addr, "admin", "rdppass")  # vs HTTP
    check("RDP NLA: vs HTTP server", False, r)

    # ── 24. SMBv2 ──
    banner("24. SMBv2 (NEW)")
    s24 = SMBv2Sim("admin", "smbpass")
    s24.start(); sims.append(s24)
    r = test_smb(*s24.addr, "admin", "smbpass")
    check("SMBv2: correct creds", True, r)
    r = test_smb(*s24.addr, "admin", "wrongpass")
    check("SMBv2: wrong creds", False, r)
    r = test_smb(*s1.addr, "admin", "smbpass")  # vs HTTP
    check("SMBv2: vs HTTP server", False, r)

    # ── 25. MySQL caching_sha2_password ──
    banner("25. MySQL caching_sha2_password (NEW)")
    s25 = MySQLCacheSha2Sim("root", "mysqlsha2")
    s25.start(); sims.append(s25)
    r = test_mysql(*s25.addr, "root", "mysqlsha2")
    check("MySQL cache-sha2: correct creds", True, r)
    r = test_mysql(*s25.addr, "root", "wrongpass")
    check("MySQL cache-sha2: wrong creds", False, r)
    r = test_mysql(*s1.addr, "root", "mysqlsha2")  # vs HTTP
    check("MySQL cache-sha2: vs HTTP server", False, r)

    # ── 26. MongoDB SCRAM ──
    banner("26. MongoDB SCRAM-SHA-256 (NEW)")
    s26 = MongoSCRAMSim("admin", "mongopass")
    s26.start(); sims.append(s26)
    r = test_mongodb(*s26.addr, "admin", "mongopass")
    check("MongoDB SCRAM: correct creds", True, r)
    r = test_mongodb(*s26.addr, "admin", "wrongpass")
    check("MongoDB SCRAM: wrong creds", False, r)
    r = test_mongodb(*s1.addr, "admin", "mongopass")  # vs HTTP
    check("MongoDB SCRAM: vs HTTP server", False, r)

    # ── Cleanup ──
    banner("Cleanup")
    for s in sims:
        try: s.stop()
        except: pass
    print(f"  Stopped {len(sims)} simulators")

    # ── Summary ──
    print(f"\n{'='*60}")
    total = PASS + FAIL + SKIP
    print(f"  结果: {PASS} PASS | {FAIL} FAIL | {SKIP} SKIP | {total} total")
    print(f"{'='*60}")

    if FAIL > 0:
        print(f"\n  *** {FAIL} 项测试失败! ***")
        for entry in LOG:
            if '[FAIL]' in entry:
                print(entry)
        return False
    else:
        print(f"\n  全部 {PASS} 项通过! 无误判。")
        return True


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
