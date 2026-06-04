"""Compatibility module — re-exports all symbols that tests expect from the old V2 GUI.

This replaces `from PasswordScanV2.weak_pass_scanner_gui import *`
which was the monolithic re-export file in V2.
"""
# Types
from netspider._lib.types import (
    FindingType, NetworkError, ScanResult,
    _finding_ctx, _set_finding_type, _get_finding_type,
)

# Constants
from netspider._lib.constants import (
    NAMED_PORTS, HTTP_PORTS, RTSP_PORTS, DB_PORTS,
    NETWORK_PORTS, WINDOWS_PORTS, SVC_TO_CREDGROUP, SCAN_TIMEOUT,
)

# Crypto
from netspider._lib.crypto import (
    _md4, _md4_pure, _VNC_REV, _hmac_sha1, _hmac_sha256,
    HAS_PYCRYPTO, HAS_PYASN1, DES, MD4,
)

# BER
from netspider._lib.ber import (
    _ber_len_content, _ber_decode_length, _ber_octet_string,
)

# NTLM
from netspider._lib.ntlm import (
    _ntlmssp_negotiate, _ntlmssp_parse_challenge, _ntlmssp_authenticate,
)

# SPNEGO
from netspider._lib.spnego import (
    _spnego_wrap_ntlmssp, _spnego_unwrap, _spnego_wrap_auth,
)

# Socket utils
from netspider._lib.socket_utils import (
    _recv_until, _recv_until_delim, _read_initial_banner, _smtp_recv_line,
)

# TCP connect
from netspider._lib.tcp_connect import tcp_connect, BANNER_SIGNATURES

# Protocol testers
from netspider.protocols import TESTER_MAP
from netspider.protocols.http import (
    test_http, test_elasticsearch,
    _http_request, _http_fetch_body, _parse_login_form,
    _submit_form_login, _try_form_login,
    _http_auth_cache, _http_auth_cache_lock, _cache_http_auth,
)
from netspider.protocols.network import (
    test_ssh, test_telnet, test_ftp, HAS_PARAMIKO,
)
from netspider.protocols.mail import test_smtp, test_imap, test_pop3
from netspider.protocols.database import (
    test_redis, test_mysql, test_postgresql, test_mssql, test_oracle, test_mongodb,
    HAS_PYMSSQL,
    _parse_mysql_handshake, _mysql_native_auth, _mysql_caching_sha2_auth,
    _x509_extract_rsa_key, _mysql_rsa_encrypt_and_send, _recv_mysql_packet,
    _pg_scram_sha256,
    _test_mssql_pymssql, _test_mssql_raw,
    _build_tds_prelogin, _parse_tds_prelogin_encryption, _build_tds_login7, _recv_tds_packet,
    _build_tns_connect, _test_oracle_oracledb, _test_oracle_tns_detect,
    _bson_encode_doc, _bson_find_field, _bson_get_string,
    _bson_get_int32, _bson_get_bool, _bson_get_doc,
    _mongo_build_hello, _mongo_build_sasl_start, _mongo_build_sasl_continue, _mongo_parse_reply,
    _scram_sha1_client_first, _scram_sha1_client_final, _scram_verify_server_final,
    _scram_sha256_client_first, _scram_sha256_client_final, _scram_sha256_verify_server_final,
    _test_mongodb_scram, _test_mongodb_noauth_check, _test_mongodb_pymongo,
)
from netspider.protocols.snmp import (
    test_snmp, _parse_snmp_response_error, _build_snmp_get,
)
from netspider.protocols.smb import (
    test_smb, _test_smb_v2, _smb2_negotiate_pkt, _smb2_session_setup_pkt,
)
from netspider.protocols.ldap import (
    test_ldap, _build_ldap_bind, _parse_ldap_bind_response,
)
from netspider.protocols.rdp import (
    test_rdp, _rdp_build_negotiation, _rdp_parse_negotiation,
    _rdp_nla_auth, _rdp_build_tsrequest, _rdp_parse_tsrequest,
)
from netspider.protocols.rtsp import (
    test_rtsp, _parse_rtsp_auth_header,
)
from netspider.protocols.vnc import test_vnc, HAS_PYCRYPTO as VNC_HAS_PYCRYPTO
from netspider.protocols.winrm import test_winrm

__all__ = [n for n in dir() if not n.startswith('_')]
