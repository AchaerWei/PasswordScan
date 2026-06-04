"""Database protocol testers — split by protocol for maintainability.

Each protocol lives in its own module. This __init__.py re-exports the
public API to preserve backward compatibility with all existing callers.

Phase 2 (Sprint 2): Each sub-module uses a mature driver library instead
of hand-written protocol implementations, eliminating the SCRAM auth_msg
bug class permanently.
"""
from netspider.protocols.database.redis import test_redis
from netspider.protocols.database.mysql import (
    test_mysql, _parse_mysql_handshake, _mysql_native_auth,
    _mysql_caching_sha2_auth, _x509_extract_rsa_key,
    _mysql_rsa_encrypt_and_send, _recv_mysql_packet,
)
from netspider.protocols.database.postgresql import test_postgresql, _pg_scram_sha256
from netspider.protocols.database.mssql import (
    test_mssql, HAS_PYMSSQL,
    _test_mssql_pymssql, _test_mssql_raw,
    _build_tds_prelogin, _parse_tds_prelogin_encryption,
    _build_tds_login7, _recv_tds_packet,
)
from netspider.protocols.database.oracle import (
    test_oracle, _test_oracle_oracledb, _test_oracle_tns_detect,
    _build_tns_connect,
)
from netspider.protocols.database.mongodb import (
    test_mongodb,
    _test_mongodb_scram, _test_mongodb_noauth_check, _test_mongodb_pymongo,
    _mongo_build_hello, _mongo_build_sasl_start, _mongo_build_sasl_continue,
    _mongo_parse_reply,
    _bson_encode_doc, _bson_find_field, _bson_get_string,
    _bson_get_int32, _bson_get_bool, _bson_get_doc,
    _scram_sha1_client_first, _scram_sha1_client_final, _scram_verify_server_final,
    _scram_sha256_client_first, _scram_sha256_client_final, _scram_sha256_verify_server_final,
)

__all__ = [
    "test_redis", "test_mysql", "test_postgresql", "test_mssql",
    "test_oracle", "test_mongodb", "HAS_PYMSSQL",
]
