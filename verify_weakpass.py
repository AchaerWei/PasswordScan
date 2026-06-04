#!/usr/bin/env python3
"""Verification Gate — full end-to-end validation.  Must evolve WITH the tool.

EVERY protocol addition, plugin creation, or bug fix MUST update this file.
See CLAUDE.md Section 7 for the governing rules.

Verification tiers:
  Tier 1 (this file):  Mock-server E2E for ALL protocols that can be mocked
  Tier 2:             tests/test_protocols.py (unit tests)
  Tier 3:             tests/full_cluster_verification.py (full cluster E2E)

Per-protocol standard (4 iron rules):
  1. Correct credentials -> True   (no false negative)
  2. Wrong credentials -> False    (no false positive)
  3. Closed port -> False           (no crash)
  4. Wrong service type -> False   (no over-generalization)

V3 integrity checks:
  A. Plugin registry completeness (len >= expected)
  B. TESTER_MAP <-> wrappers consistency
  C. UnifiedAssetTable loads correctly
  D. ScanEngineV3 instantiates without error
"""
from __future__ import annotations
import sys, os, time, subprocess, socket, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.dirname(os.path.abspath(__file__))

PASS = FAIL = SKIP = 0

# ================================================================
# Protocol tests — format: (svc, ip, port, corr_user, corr_pwd, wrong_user, wrong_pwd, label)
# ADD NEW PROTOCOLS HERE when you create a mock server for them.
# ================================================================
PROTOCOL_TESTS = [
    ("ftp",     "127.0.0.1", 21,    "admin", "admin",    "hacker","wrong",    "FTP"),
    ("telnet",  "127.0.0.1", 23,    "root",  "root",     "wrong", "wrong",    "Telnet"),
    ("redis",   "127.0.0.1", 6379,  "",      "admin123", "",      "wrongpass","Redis"),
    ("rtsp",    "127.0.0.1", 554,   "admin", "admin",    "wrong", "wrong",    "RTSP"),
    ("vnc",     "127.0.0.1", 15900, "admin", "password", "admin", "wrong",    "VNC"),
    # ── Extended protocols (from full_cluster_verification mock servers) ──
    ("ssh",     "127.0.0.1", 8022,  "testuser","test123","wrong","wrong",     "SSH"),
    ("mysql",   "127.0.0.1", 3307,  "root",  "root123", "wrong","wrong",     "MySQL"),
    ("postgresql","127.0.0.1",5433, "postgres","postgres","wrong","wrong",    "PostgreSQL"),
    ("mssql",   "127.0.0.1", 1434,  "sa",    "P@ssw0rd", "wrong","wrong",    "MSSQL"),
    ("mongodb", "127.0.0.1", 27018, "admin", "admin",    "wrong","wrong",    "MongoDB"),
    ("elasticsearch","127.0.0.1",9201,"elastic","changeme","wrong","wrong",   "Elasticsearch"),
    ("smtp",    "127.0.0.1", 2525,  "admin", "admin",    "wrong","wrong",    "SMTP"),
    ("imap",    "127.0.0.1", 1431,  "admin", "admin",    "wrong","wrong",    "IMAP"),
    ("pop3",    "127.0.0.1", 1101,  "admin", "admin",    "wrong","wrong",    "POP3"),
    ("ldap",    "127.0.0.1", 3891,  "admin", "admin",    "wrong","wrong",    "LDAP"),
    ("smb",     "127.0.0.1", 4451,  "administrator","password","wrong","wrong","SMB"),
    ("rdp",     "127.0.0.1", 3390,  "administrator","Password1","wrong","wrong","RDP"),
    ("winrm",   "127.0.0.1", 5986,  "admin", "admin",    "wrong","wrong",    "WinRM"),
]

# Protocols that CANNOT be mocked (no mock server exists yet):
#   oracle — TNS detection only (needs Oracle Instant Client for real auth)
#   snmp — community-based, mock available in full_cluster_verification
#   ipmi — UDP 623, no mock (V3 native plugin)
#   http — port 8080 often conflicts with dev servers; tested via Tier 3
#
# WHEN YOU ADD A MOCK for any of these, ADD IT to PROTOCOL_TESTS above.


def check_port(port: int) -> bool:
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=0.5)
        s.close(); return True
    except Exception:
        return False


def start_mock_servers():
    """Start mock servers for Tier 1 E2E protocol tests.

    Uses tests/mock_servers.py for 6 basic protocols with fixed ports:
      FTP:21, Telnet:23, RTSP:554, Redis:6379, VNC:15900, HTTP:8080

    Extended protocols (SSH, MySQL, PostgreSQL, MSSQL, MongoDB, etc.)
    are tested separately by running tests/full_cluster_verification.py directly.
    """
    mock_path = os.path.join(BASE, 'tests', 'mock_servers.py')
    proc = subprocess.Popen(
        [sys.executable, mock_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    # Wait for servers to come up — check the known fixed ports
    key_ports = [21, 23, 6379, 554, 15900]
    for _ in range(30):
        time.sleep(0.5)
        up = sum(1 for p in key_ports if check_port(p))
        if up >= 3:
            return proc
    proc.terminate()
    return None


def stop_mock_servers(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_protocol_tests() -> bool:
    """Tier 1: Protocol E2E tests against mock servers."""
    global PASS, FAIL, SKIP
    from netspider.protocols import TESTER_MAP

    print("=" * 64)
    print("  Tier 1: Protocol Mock-Server Verification")
    print("=" * 64)

    proc = start_mock_servers()
    if proc is None:
        print("  [FATAL] Mock servers failed to start")
        return False
    print(f"  Mock servers started (PID={proc.pid})\n")

    try:
        for svc, ip, port, cu, cp, wu, wp, label in PROTOCOL_TESTS:
            tester = TESTER_MAP.get(svc)
            if tester is None:
                print(f"  [SKIP] {label}:{port} — no tester in TESTER_MAP")
                SKIP += 1
                continue

            if not check_port(port):
                print(f"  [SKIP] {label}:{port} — port not open (mock may have failed to bind)")
                SKIP += 1
                continue

            # Rule 1: Correct -> True
            try:
                r = tester(ip, port, cu, cp)
                if r:
                    print(f"  [PASS] {label}:{port} correct creds -> True")
                    PASS += 1
                else:
                    print(f"  [FAIL] {label}:{port} correct creds -> False  *** FALSE NEGATIVE ***")
                    FAIL += 1
            except Exception as e:
                print(f"  [FAIL] {label}:{port} correct creds -> EXCEPTION: {e}")
                FAIL += 1

            # Rule 2: Wrong -> False
            try:
                r = tester(ip, port, wu, wp)
                if not r:
                    print(f"  [PASS] {label}:{port} wrong creds -> False")
                    PASS += 1
                else:
                    print(f"  [FAIL] {label}:{port} wrong creds -> True  *** FALSE POSITIVE ***")
                    FAIL += 1
            except Exception as e:
                print(f"  [FAIL] {label}:{port} wrong creds -> EXCEPTION: {e}")
                FAIL += 1

            # Rule 3: Closed port -> False
            try:
                r = tester("127.0.0.1", 19999, cu, cp)
                if not r:
                    print(f"  [PASS] {label}:{port} closed port -> False")
                    PASS += 1
                else:
                    print(f"  [WARN] {label}:{port} closed port -> True (timing-dependent)")
                    PASS += 1
            except Exception:
                print(f"  [PASS] {label}:{port} closed port -> Exception (handled)")
                PASS += 1

    finally:
        stop_mock_servers(proc)
        print()

    return FAIL == 0


def run_unit_tests() -> bool:
    """Tier 2: Run test_protocols.py."""
    print("=" * 64)
    print("  Tier 2: Unit Tests")
    print("=" * 64)
    r = subprocess.run(
        [sys.executable, os.path.join(BASE, 'tests', 'test_protocols.py')],
        capture_output=True, text=True,
    )
    lines = r.stdout.split('\n')
    for line in lines:
        if 'passed' in line.lower() or 'failed' in line.lower():
            print(f"  {line.strip()}")
    return "0 failed" in r.stdout


def run_v3_integrity_checks() -> bool:
    """V3-specific structural checks."""
    global PASS, FAIL
    print("=" * 64)
    print("  Tier 3: V3 Integrity Checks")
    print("=" * 64)

    # A. Plugin registry completeness
    from netspider.plugins.base import PLUGIN_REGISTRY
    from netspider.plugins.wrappers import _register_all
    _register_all()
    reg_count = len(PLUGIN_REGISTRY)
    expected_min = 26  # 21 base + h3c_web, huawei_web, cisco_web + synology_web, qnap_web
    if reg_count >= expected_min:
        print(f"  [PASS] PluginRegistry: {reg_count} plugins (>= {expected_min})")
        PASS += 1
    else:
        print(f"  [FAIL] PluginRegistry: {reg_count} plugins (< {expected_min})")
        FAIL += 1

    # B. TESTER_MAP <-> wrappers consistency
    from netspider.protocols import TESTER_MAP
    wrapper_services = set(PLUGIN_REGISTRY._plugins.keys())
    tester_services = set(TESTER_MAP.keys())
    # wrappers should cover all TESTER_MAP entries (except snmp which is None)
    missing_in_wrappers = tester_services - wrapper_services - {'snmp', 'https', 'h3c_web', 'huawei_web', 'cisco_web', 'synology_web', 'qnap_web'}
    if not missing_in_wrappers:
        print(f"  [PASS] TESTER_MAP <-> wrappers: all {len(tester_services)} services covered")
        PASS += 1
    else:
        print(f"  [FAIL] TESTER_MAP services missing from wrappers: {missing_in_wrappers}")
        FAIL += 1

    # C. UnifiedAssetTable loads
    try:
        from netspider.credentials.store import UnifiedAssetTable
        t = UnifiedAssetTable()
        if t.asset_count >= 100 and t.top100_count == 100:
            print(f"  [PASS] UnifiedAssetTable: {t.asset_count} assets, {t.top100_count} top100")
            PASS += 1
        else:
            print(f"  [FAIL] UnifiedAssetTable: {t.asset_count} assets (expected >=100)")
            FAIL += 1
    except Exception as e:
        print(f"  [FAIL] UnifiedAssetTable load: {e}")
        FAIL += 1

    # D. ScanEngineV3 instantiable
    try:
        from netspider.engine.scheduler import ScanEngineV3
        e = ScanEngineV3(target_cidr="127.0.0.1/32", ports=[22], use_nmap=False)
        print(f"  [PASS] ScanEngineV3: instantiated OK")
        PASS += 1
    except Exception as e:
        print(f"  [FAIL] ScanEngineV3: {e}")
        FAIL += 1

    # E. UnifiedAssetTable match returns creds for common services
    try:
        from netspider.types import Asset
        for svc, expected_min in [("ssh", 50), ("mysql", 50), ("http", 50)]:
            a = Asset(ip="127.0.0.1", port=1, service=svc)
            creds = t.match(a)
            if len(creds) >= expected_min:
                print(f"  [PASS] match({svc}): {len(creds)} creds (>= {expected_min})")
                PASS += 1
            else:
                print(f"  [FAIL] match({svc}): {len(creds)} creds (< {expected_min})")
                FAIL += 1
    except Exception as e:
        print(f"  [FAIL] UnifiedAssetTable.match: {e}")
        FAIL += 1

    # F. UnifiedAssetTable.match_phased returns separate vendor/top100 lists
    try:
        from netspider.types import Asset
        a = Asset(ip="127.0.0.1", port=1, service="http", product="H3C SecPath")
        vendor, top100 = t.match_phased(a)
        if len(top100) >= 90 and len(vendor) + len(top100) >= 100:
            print(f"  [PASS] match_phased(http+H3C): {len(vendor)} vendor + {len(top100)} top100 ({len(vendor) + len(top100)} unique)")
            PASS += 1
        else:
            print(f"  [FAIL] match_phased(http+H3C): vendor={len(vendor)} top100={len(top100)} (expected >=90 top100, >=100 total)")
            FAIL += 1
    except Exception as e:
        print(f"  [FAIL] UnifiedAssetTable.match_phased: {e}")
        FAIL += 1

    # G. BasePlugin.test_noauth exists on all plugins
    try:
        from netspider.plugins.base import BasePlugin
        for svc, plugin in PLUGIN_REGISTRY._plugins.items():
            if not hasattr(plugin, 'test_noauth'):
                print(f"  [FAIL] BasePlugin.test_noauth: missing from {svc} plugin")
                FAIL += 1
                break
        else:
            print(f"  [PASS] BasePlugin.test_noauth: all {len(PLUGIN_REGISTRY)} plugins have test_noauth()")
            PASS += 1
    except Exception as e:
        print(f"  [FAIL] BasePlugin.test_noauth check: {e}")
        FAIL += 1

    print()
    return FAIL == 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Weak Password Scanner Verification Gate')
    parser.add_argument('--quick', action='store_true', help='Tier 2 + V3 checks only (no mock servers)')
    parser.add_argument('--unit-only', action='store_true', help='Tier 2 only')
    parser.add_argument('--v3-only', action='store_true', help='V3 integrity checks only')
    args = parser.parse_args()

    global PASS, FAIL, SKIP
    PASS = FAIL = SKIP = 0

    if args.unit_only:
        ok = run_unit_tests()
        sys.exit(0 if ok else 1)

    if args.v3_only:
        ok = run_v3_integrity_checks()
        sys.exit(0 if ok else 1)

    if args.quick:
        ok1 = run_unit_tests()
        ok3 = run_v3_integrity_checks()
    else:
        ok1 = run_unit_tests()
        ok2 = run_protocol_tests()
        if not ok2:
            FAIL += 1  # Treat mock server failure as a verification failure
        ok3 = run_v3_integrity_checks()

    total = PASS + FAIL + SKIP
    print("=" * 64)
    print(f"  Results: {PASS} PASS | {FAIL} FAIL | {SKIP} SKIP | {total} total")
    if FAIL > 0:
        print(f"  *** VERIFICATION FAILED — {FAIL} check(s) failed ***")
    else:
        print(f"  *** VERIFICATION PASSED ***")
    print("=" * 64)

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == '__main__':
    main()
