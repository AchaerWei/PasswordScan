# Shared constants used across core modules

NAMED_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 554: "rtsp", 636: "ldap",
    1080: "http", 1433: "mssql", 1521: "oracle",
    3000: "http", 3306: "mysql", 3389: "rdp",
    4848: "http", 5000: "http", 5001: "https",
    5432: "postgresql", 5601: "http", 5900: "vnc",
    5985: "winrm", 5986: "winrm",
    6379: "redis", 7001: "http", 7002: "https",
    8000: "http", 8008: "http", 8080: "http", 8081: "http",
    8086: "http", 8111: "http", 8123: "http", 8161: "http",
    8443: "https", 8554: "rtsp", 8888: "http", 9000: "http",
    9043: "https", 9060: "http", 9090: "http", 9200: "elasticsearch",
    9990: "http", 11211: "memcached", 15672: "http", 18083: "http",
    27017: "mongodb",
    25: "smtp", 110: "pop3", 143: "imap",
    465: "smtp", 587: "smtp",
    993: "imap", 995: "pop3",
}

HTTP_PORTS = {80, 443, 1080, 8000, 8008, 8080, 8443, 8888, 9090}
RTSP_PORTS = {554, 8554}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
NETWORK_PORTS = {21, 22, 23, 161, 554, 3389, 445, 389, 636, 5900, 8554}
WINDOWS_PORTS = {445, 3389, 5985, 5986}

# Which credential groups to try for which service types
SVC_TO_CREDGROUP = {
    "ssh":          ["remote", "network", "database", "security", "ics", "general"],
    "telnet":       ["remote", "network", "security", "ics", "general"],
    "ftp":          ["remote", "network", "printer", "general"],
    "http":         ["web", "middleware", "network", "security", "camera", "printer", "ics", "general"],
    "https":        ["web", "middleware", "network", "security", "camera", "printer", "ics", "general"],
    "mysql":        ["database", "general"],
    "postgresql":   ["database", "general"],
    "mssql":        ["database", "general"],
    "oracle":       ["database", "general"],
    "redis":        ["database", "general"],
    "mongodb":      ["database", "general"],
    "elasticsearch":["database", "middleware", "general"],
    "snmp":         ["snmp", "security", "network", "general"],
    "rdp":          ["remote", "general"],
    "vnc":          ["remote", "general"],
    "smb":          ["remote", "database", "network", "general"],
    "ldap":         ["remote", "network", "general"],
    "winrm":        ["remote", "general"],
    "rtsp":         ["web", "camera", "general"],
    "smtp":         ["remote", "network", "general"],
    "imap":         ["remote", "network", "web", "general"],
    "pop3":         ["remote", "network", "web", "general"],
    "unknown":      ["general"],
}

SCAN_TIMEOUT = 5
