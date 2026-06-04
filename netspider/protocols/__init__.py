"""Protocol testers — public API."""
from netspider.protocols.http import test_http, test_elasticsearch
from netspider.protocols.network import test_ssh, test_telnet, test_ftp, HAS_PARAMIKO
from netspider.protocols.mail import test_smtp, test_imap, test_pop3
from netspider.protocols.database import (
    test_redis, test_mysql, test_postgresql, test_mssql, test_oracle, test_mongodb,
    HAS_PYMSSQL,
)
from netspider.protocols.snmp import test_snmp
from netspider.protocols.smb import test_smb
from netspider.protocols.ldap import test_ldap
from netspider.protocols.rdp import test_rdp
from netspider.protocols.winrm import test_winrm
from netspider.protocols.rtsp import test_rtsp
from netspider.protocols.vnc import test_vnc, HAS_PYCRYPTO

TESTER_MAP = {
    "ssh": test_ssh, "telnet": test_telnet, "ftp": test_ftp,
    "http": test_http, "https": test_http,
    "redis": test_redis, "mysql": test_mysql, "postgresql": test_postgresql,
    "mssql": test_mssql, "oracle": test_oracle, "mongodb": test_mongodb,
    "elasticsearch": test_elasticsearch,
    "smb": test_smb, "ldap": test_ldap, "snmp": None,
    "rdp": test_rdp, "vnc": test_vnc, "winrm": test_winrm, "rtsp": test_rtsp,
    "smtp": test_smtp, "imap": test_imap, "pop3": test_pop3,
}
