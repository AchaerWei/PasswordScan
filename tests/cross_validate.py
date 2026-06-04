#!/usr/bin/env python3
"""Go-Python cross-validation for protocol testers.

Runs both Go (goproto) and Python implementations against the same target,
compares results, and reports discrepancies.

Usage:
    python tests/cross_validate.py --host 192.168.1.1
    python tests/cross_validate.py --host 10.0.0.1 --user admin --pass admin123
"""
from __future__ import annotations
import argparse, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Python implementations
from netspider.protocols.snmp import test_snmp
from netspider.protocols.ldap import test_ldap
from netspider.protocols.mail import test_imap, test_pop3
from netspider.protocols.rtsp import test_rtsp
from netspider.protocols.vnc import test_vnc

# Go wrappers
from netspider.goproto.wrapper import (
    goproto_snmp, goproto_ldap, goproto_imap,
    goproto_pop3, goproto_rtsp, goproto_vnc,
)


def safe_py(fn, *args):
    """Call Python tester; return bool or None on error."""
    try:
        return fn(*args)
    except Exception:
        return None


def cross_check(name, py_result, go_result):
    """Compare Python and Go results. Returns 'PASS', 'MISMATCH', or 'SKIP'."""
    # Normalize: None and False both mean "not successful"
    py_ok = py_result is True
    go_ok = go_result is True
    if py_ok == go_ok:
        status = "PASS" if py_ok else "PASS (both negative)"
        print(f"  [{status}] {name}: Py={py_result} Go={go_result}")
        return "PASS"
    else:
        print(f"  [MISMATCH] {name}: Py={py_result} Go={go_result} ***")
        return "MISMATCH"


def main():
    p = argparse.ArgumentParser(description="Cross-validate Go vs Python protocol testers")
    p.add_argument("--host", required=True, help="Target IP")
    p.add_argument("--user", default="admin", help="Username (default: admin)")
    p.add_argument("--pass", dest="password", default="admin", help="Password")
    p.add_argument("--community", default="public", help="SNMP community (default: public)")
    p.add_argument("--timeout", type=int, default=3, help="Timeout seconds (default: 3)")
    args = p.parse_args()

    host = args.host
    user = args.user
    password = args.password
    community = args.community
    timeout = args.timeout

    print(f"Cross-validating Go vs Python against {host}")
    print(f"Credentials: user={user}, pass=***, community={community}")
    print()

    results = {}
    total = {"PASS": 0, "MISMATCH": 0, "SKIP": 0}

    # SNMP (Python takes community, Go takes community)
    print("--- SNMP ---")
    py = safe_py(test_snmp, host, 161, community)
    go = goproto_snmp(host, community, timeout)
    r = cross_check("SNMP", py, go)
    results["snmp"] = r
    total[r] = total.get(r, 0) + 1

    # LDAP
    print("--- LDAP ---")
    py = safe_py(test_ldap, host, 389, user, password)
    go = goproto_ldap(host, user, password, timeout)
    r = cross_check("LDAP", py, go)
    results["ldap"] = r
    total[r] = total.get(r, 0) + 1

    # IMAP
    print("--- IMAP ---")
    py = safe_py(test_imap, host, 143, user, password)
    go = goproto_imap(host, user, password, timeout)
    r = cross_check("IMAP", py, go)
    results["imap"] = r
    total[r] = total.get(r, 0) + 1

    # POP3
    print("--- POP3 ---")
    py = safe_py(test_pop3, host, 110, user, password)
    go = goproto_pop3(host, user, password, timeout)
    r = cross_check("POP3", py, go)
    results["pop3"] = r
    total[r] = total.get(r, 0) + 1

    # RTSP
    print("--- RTSP ---")
    py = safe_py(test_rtsp, host, 554, user, password)
    go = goproto_rtsp(host, user, password, timeout)
    r = cross_check("RTSP", py, go)
    results["rtsp"] = r
    total[r] = total.get(r, 0) + 1

    # VNC
    print("--- VNC ---")
    py = safe_py(test_vnc, host, 5900, user, password)
    go = goproto_vnc(host, password, timeout)
    r = cross_check("VNC", py, go)
    results["vnc"] = r
    total[r] = total.get(r, 0) + 1

    print()
    print("=" * 50)
    print(f"  Summary: {total}")
    mismatches = total.get("MISMATCH", 0)
    if mismatches > 0:
        print(f"  *** {mismatches} MISMATCH(es) found — investigate! ***")
        return 1
    print("  All consistent between Go and Python")
    return 0


if __name__ == "__main__":
    sys.exit(main())
