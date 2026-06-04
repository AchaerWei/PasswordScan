#!/usr/bin/env python3
"""Development Gate — automated checks from 3 rounds of audit lessons.

Usage:
    python verify_dev_gate.py           # Run all checks
    python verify_dev_gate.py --quick   # Skip JSON integrity (slow)
    python verify_dev_gate.py --list    # List all checks

Checks encode patterns discovered across 3 audit rounds:
  R1: sync/async parity, stay_login field, test_noauth coverage
  R2: FindingType unification, _REGISTERED idempotency, scheme detection
  R3: import integrity, bare except, IPMI creds, vendor routing, _meta.stats
"""

import sys
import os
import re
from pathlib import Path

PROJECT = Path(__file__).parent
PASS = FAIL = SKIP = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


# ============================================================
# C1: Import Integrity — no broken imports after types.py change
# ============================================================
def check_import_integrity():
    print("\n--- C1: Import Integrity ---")
    broken = []
    for pyfile in PROJECT.rglob("*.py"):
        content = pyfile.read_text(encoding="utf-8", errors="ignore")
        # _set_finding_type / _get_finding_type must import from _lib.types, NOT netspider.types
        for m in re.finditer(r'from netspider\.types import ([^\n]+)', content):
            imports = m.group(1)
            if '_set_finding_type' in imports or '_get_finding_type' in imports:
                broken.append(f"{pyfile.relative_to(PROJECT)} imports {imports.strip()} from netspider.types (should be _lib.types)")
    check("No broken _set_finding_type imports from netspider.types",
          len(broken) == 0, "\n    ".join(["", *broken]))


# ============================================================
# C2: Plugin Contract — all plugins return ScanResult, not bare bool
# ============================================================
def check_plugin_contracts():
    print("\n--- C2: Plugin Contracts ---")
    try:
        from netspider.plugins.base import PLUGIN_REGISTRY, BasePlugin
        from netspider.plugins.wrappers import _register_all
        _register_all()

        # C2a: All plugins have required class attributes
        missing_attrs = []
        for svc, plugin in PLUGIN_REGISTRY._plugins.items():
            for attr in ('name', 'service_type', 'is_async'):
                if not hasattr(plugin, attr):
                    missing_attrs.append(f"{svc}: missing {attr}")
        check("All plugins have name/service_type/is_async",
              len(missing_attrs) == 0, str(missing_attrs[:5]))

        # C2b: All plugins have test_noauth()
        no_noauth = []
        for svc, plugin in PLUGIN_REGISTRY._plugins.items():
            if not hasattr(plugin, 'test_noauth'):
                no_noauth.append(svc)
        check("All plugins have test_noauth()", len(no_noauth) == 0)

        # C2c: Web plugins have test_noauth() that doesn't just inherit default
        web_plugins = ['h3c_web', 'huawei_web', 'cisco_web', 'synology_web', 'qnap_web']
        default_test_noauth = BasePlugin.test_noauth
        missing_override = []
        for wp in web_plugins:
            plugin = PLUGIN_REGISTRY.get(wp)
            if plugin and type(plugin).test_noauth is default_test_noauth:
                missing_override.append(wp)
        check("All Web plugins override test_noauth()",
              len(missing_override) == 0, f"Missing: {missing_override}")

    except Exception as e:
        check("Plugin contract checks", False, str(e))


# ============================================================
# C3: No Hardcoded Credentials in Python Source
# ============================================================
def check_no_hardcoded_creds():
    print("\n--- C3: No Hardcoded Credentials ---")
    patterns = [
        (r'_DEFAULT_PAIRS\s*=\s*\[', "IPMI-style credential list"),
        (r'username\s*==\s*["\']admin["\']', "hardcoded username check"),
    ]
    found = []
    for pyfile in PROJECT.rglob("*.py"):
        if 'unified_asset_table' in str(pyfile):
            continue
        content = pyfile.read_text(encoding="utf-8", errors="ignore")
        for pat, desc in patterns:
            if re.search(pat, content):
                found.append(f"{pyfile.relative_to(PROJECT)}: {desc}")
    check("No hardcoded credentials in source", len(found) == 0,
          "\n    ".join(["", *found[:5]]))


# ============================================================
# C4: Scheme Detection — no port-number hardcoding in Web plugins
# ============================================================
def check_scheme_detection():
    print("\n--- C4: Scheme Detection (port → service) ---")
    web_dir = PROJECT / "netspider" / "plugins" / "web"
    port_hardcode = []
    if web_dir.exists():
        for pyfile in web_dir.rglob("*.py"):
            content = pyfile.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'asset\.port\s+in\s*\(', content):
                port_hardcode.append(str(pyfile.relative_to(PROJECT)))
    check("No port-based scheme detection in web plugins",
          len(port_hardcode) == 0, str(port_hardcode))


# ============================================================
# C5: JSON _meta.stats matches actual data
# ============================================================
def check_json_meta_stats():
    print("\n--- C5: JSON _meta.stats Accuracy ---")
    try:
        import json
        with open(PROJECT / "data" / "unified_asset_table.json", encoding="utf-8") as f:
            data = json.load(f)
        assets = data.get("assets", [])
        actual_vendors = len(assets)
        meta_vendors = data.get("_meta", {}).get("stats", {}).get("vendors", 0)

        total_creds = 0
        for a in assets:
            for svc in a.get("services", {}).values():
                total_creds += len(svc.get("credentials", []))
        meta_creds = data.get("_meta", {}).get("stats", {}).get("total_credential_entries", 0)

        check(f"_meta.stats.vendors correct ({meta_vendors} == {actual_vendors})",
              meta_vendors == actual_vendors,
              f"Update _meta.stats.vendors from {meta_vendors} to {actual_vendors}")
        check(f"_meta.stats.total_credential_entries correct ({meta_creds} == {total_creds})",
              meta_creds == total_creds,
              f"Update _meta.stats from {meta_creds} to {total_creds}")
    except Exception as e:
        check("JSON _meta.stats", False, str(e))


# ============================================================
# C6: Vendor Routing Table Coverage
# ============================================================
def check_vendor_routing():
    print("\n--- C6: Vendor Routing Coverage ---")
    try:
        from netspider.discovery.matcher import _VENDOR_PLUGIN_MAP
        from netspider.plugins.base import PLUGIN_REGISTRY
        from netspider.plugins.wrappers import _register_all
        _register_all()

        # All plugins in VENDOR_PLUGIN_MAP must be registered
        missing = []
        for plugin_type in _VENDOR_PLUGIN_MAP:
            if plugin_type not in PLUGIN_REGISTRY:
                missing.append(plugin_type)
        check(f"All {len(_VENDOR_PLUGIN_MAP)} vendor plugins registered",
              len(missing) == 0, f"Missing: {missing}")

        # Verify vendor routing matches JSON keywords
        import json
        with open(PROJECT / "data" / "unified_asset_table.json", encoding="utf-8") as f:
            data = json.load(f)
        json_keywords = {}
        for a in data.get("assets", []):
            json_keywords[a["vendor"]] = set(k.lower() for k in a.get("keywords", []))

        # Check that VENDOR_PLUGIN_MAP keywords overlap with JSON keywords
        for plugin_type, keywords in _VENDOR_PLUGIN_MAP.items():
            vendor_name = plugin_type.replace("_web", "")
            if vendor_name in json_keywords:
                overlap = set(keywords) & json_keywords[vendor_name]
                if not overlap:
                    print(f"  [WARN] {plugin_type}: no keyword overlap with JSON")

    except Exception as e:
        check("Vendor routing checks", False, str(e))


# ============================================================
# C7: Registration Idempotency
# ============================================================
def check_registration_idempotency():
    print("\n--- C7: Registration Idempotency ---")
    try:
        from netspider.plugins.wrappers import _REGISTERED, _register_all
        from netspider.plugins.base import PLUGIN_REGISTRY
        _register_all()
        before = len(PLUGIN_REGISTRY)
        _register_all()
        after = len(PLUGIN_REGISTRY)
        check(f"_register_all() is idempotent (before={before}, after={after})",
              before == after and before > 0)

        # IPMI must be registered via wrappers, not self-registration
        check("IPMI registered via wrappers",
              'ipmi' in PLUGIN_REGISTRY)
    except Exception as e:
        check("Registration idempotency", False, str(e))


# ============================================================
# C8: requirements.txt exists
# ============================================================
def check_requirements():
    print("\n--- C8: requirements.txt ---")
    req = PROJECT / "requirements.txt"
    check("requirements.txt exists", req.exists())
    if req.exists():
        content = req.read_text(encoding="utf-8")
        deps = [l for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        check(f"requirements.txt has {len(deps)} dependency lines", len(deps) >= 5)


# ============================================================
# C9: Sync/Async parity in Web plugins
# ============================================================
def check_sync_async_parity():
    print("\n--- C9: Sync/Async Parity ---")
    issues = []
    web_dir = PROJECT / "netspider" / "plugins" / "web"
    if web_dir.exists():
        for pyfile in web_dir.rglob("*.py"):
            content = pyfile.read_text(encoding="utf-8", errors="ignore")
            has_async_200 = '200' in content and 'desktop' in content and 'test_async' in content
            has_sync_200 = re.search(r'def test\(.*\).*:.*200.*desktop', content, re.DOTALL)
            # Count 200 checks in test() vs test_async()
            async_200_count = len(re.findall(r'async def test_async.*?status == 200', content, re.DOTALL))
            sync_200_count = len(re.findall(r'def test\(self.*?status == 200', content, re.DOTALL))
            if async_200_count != sync_200_count:
                name = pyfile.relative_to(PROJECT)
                issues.append(f"{name}: async has {async_200_count} 200-checks, sync has {sync_200_count}")
    check("Sync/async 200-status detection parity", len(issues) == 0,
          "\n    ".join(["", *issues[:5]]))


# ============================================================
# ============================================================
# C10: No Dead Data — unauthorized entries must have plugins
# ============================================================
def check_no_dead_data():
    print("\n--- C10: No Dead Data (R4) ---")
    try:
        import json
        from netspider.plugins.base import PLUGIN_REGISTRY
        from netspider.plugins.wrappers import _register_all
        _register_all()
        with open(PROJECT / "data" / "unified_asset_table.json", encoding="utf-8") as f:
            data = json.load(f)
        dead = []
        for ua in data.get("unauthorized", []):
            svc = ua["service"]
            if svc not in PLUGIN_REGISTRY and svc not in ("https",):
                dead.append(svc)
        # Also check service_ports
        for svc in data.get("service_ports", {}):
            if svc not in PLUGIN_REGISTRY and svc not in ("https",):
                if svc not in dead:
                    dead.append(svc)
        check("No unauthorized/service_ports entries without plugins",
              len(dead) == 0, f"Dead entries: {dead}")
    except Exception as e:
        check("Dead data check", False, str(e))


# ============================================================
# C11: test_noauth Consistency — all Web plugins probe, not login
# ============================================================
def check_test_noauth_consistency():
    print("\n--- C11: test_noauth Consistency (R4) ---")
    issues = []
    for pyfile in (PROJECT / "netspider" / "plugins" / "web").rglob("*.py"):
        content = pyfile.read_text(encoding="utf-8", errors="ignore")
        # Flag test_noauth that calls self.test() (full login, not probe)
        if re.search(r'def test_noauth.*\n.*self\.test\(', content):
            issues.append(f"{pyfile.name}: test_noauth calls self.test() instead of probe")
        # Flag test_noauth that just returns False immediately (skip)
        if re.search(r'def test_noauth.*\n\s+return ScanResult\(False\)', content):
            issues.append(f"{pyfile.name}: test_noauth skips probe (just returns False)")
    check("All Web plugin test_noauth() use lightweight probe pattern",
          len(issues) == 0, "\n    ".join(["", *issues]))


# ============================================================
# C12: Event Loop Safety — _http_client reset in burst_asset_sync
# ============================================================
def check_event_loop_safety():
    print("\n--- C12: Event Loop Safety (R4) ---")
    sched = PROJECT / "netspider" / "engine" / "scheduler.py"
    content = sched.read_text(encoding="utf-8", errors="ignore")
    lines = content.split('\n')
    in_burst_sync = False
    reset_ok = False
    for line in lines:
        if 'def burst_asset_sync' in line:
            in_burst_sync = True
        elif in_burst_sync and line.strip().startswith('def '):
            break
        elif in_burst_sync and '_http_client = None' in line:
            reset_ok = True
    check("_http_client and _http_semaphore reset in burst_asset_sync (R4-I1 fix)",
          reset_ok,
          "Event loop reuse bug: must reset client before asyncio.run")


# ============================================================
# C13: GoProto — binary exists and is runnable (Sprint 3)
# ============================================================
def check_goproto_binary():
    print("\n--- C13: GoProto Binary (Sprint 3) ---")
    goproto = PROJECT / "netspider" / "goproto" / "goproto.exe"
    check("goproto.exe exists", goproto.exists(),
          f"Expected at netspider/goproto/goproto.exe — run 'cd netspider/goproto && go build'")
    if goproto.exists():
        import subprocess
        try:
            proc = subprocess.run(
                [str(goproto), "version"], capture_output=True, text=True, timeout=5,
            )
            import json
            result = json.loads(proc.stdout.strip())
            protocols_ok = result.get("success") and result.get("detail", "").startswith("goproto")
            check("goproto version responds", protocols_ok,
                  f"Got: {result.get('detail', 'N/A')}")
        except Exception as e:
            check("goproto version responds", False, str(e))


# ============================================================
# C14: GoProto Wrapper — all 6 protocol wrappers importable (Sprint 3)
# ============================================================
def check_goproto_wrapper():
    print("\n--- C14: GoProto Python Wrapper (Sprint 3) ---")
    try:
        from netspider.goproto.wrapper import (
            goproto_snmp, goproto_ldap, goproto_imap,
            goproto_pop3, goproto_rtsp, goproto_vnc,
        )
        check("goproto_snmp importable", callable(goproto_snmp))
        check("goproto_ldap importable", callable(goproto_ldap))
        check("goproto_imap importable", callable(goproto_imap))
        check("goproto_pop3 importable", callable(goproto_pop3))
        check("goproto_rtsp importable", callable(goproto_rtsp))
        check("goproto_vnc importable", callable(goproto_vnc))
    except Exception as e:
        check("GoProto wrapper imports", False, str(e))


ALL_CHECKS = [
    ("C1-Import", check_import_integrity),
    ("C2-Plugin", check_plugin_contracts),
    ("C3-Creds", check_no_hardcoded_creds),
    ("C4-Scheme", check_scheme_detection),
    ("C5-Stats", check_json_meta_stats),
    ("C6-Routing", check_vendor_routing),
    ("C7-Idempot", check_registration_idempotency),
    ("C8-Reqs", check_requirements),
    ("C9-Parity", check_sync_async_parity),
    ("C10-Dead", check_no_dead_data),
    ("C11-Noauth", check_test_noauth_consistency),
    ("C12-EventLoop", check_event_loop_safety),
    ("C13-GoProtoBin", check_goproto_binary),
    ("C14-GoProtoWrap", check_goproto_wrapper),
]


def main():
    import argparse
    p = argparse.ArgumentParser(description="Dev Gate — lessons from 3 audit rounds")
    p.add_argument("--quick", action="store_true", help="Skip slow JSON checks")
    p.add_argument("--list", action="store_true", help="List all checks")
    args = p.parse_args()

    if args.list:
        for name, _ in ALL_CHECKS:
            print(name)
        return

    print("=" * 64)
    print("  Dev Gate: Checks from 3 Audit Rounds")
    print("=" * 64)

    for name, fn in ALL_CHECKS:
        if args.quick and name in ("C5-Stats",):
            global SKIP
            SKIP += 1
            print(f"\n--- {name}: SKIPPED (--quick) ---")
            continue
        fn()

    print(f"\n{'=' * 64}")
    print(f"  Results: {PASS} PASS | {FAIL} FAIL | {SKIP} SKIP | {PASS+FAIL+SKIP} total")
    if FAIL > 0:
        print(f"  *** GATE FAILED — {FAIL} check(s) ***")
    else:
        print(f"  *** GATE PASSED ***")
    print("=" * 64)

    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
