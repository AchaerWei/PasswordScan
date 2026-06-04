#!/usr/bin/env python3
"""NetSpider-Max v3 — Weak Password Scanner.

Usage:
  python main.py                         # Launch GUI
  python main.py --cli 192.168.1.0/24    # CLI mode
  python main.py --version               # Show version + deps
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if '--cli' in sys.argv:
        _run_cli()
    elif '--version' in sys.argv or '-V' in sys.argv:
        print(f"NetSpider-Max v3.0.0")
        print(f"  Python: {sys.version}")
        _check_deps()
    else:
        _run_gui()


def _run_cli():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description='NetSpider-Max v3')
    parser.add_argument('target', help='Target CIDR')
    parser.add_argument('-p', '--ports', default='22,80,443,3306,3389,5432,6379,8080,8443,27017')
    parser.add_argument('-t', '--threads', type=int, default=100)
    parser.add_argument('--timeout', type=float, default=2.0)
    parser.add_argument('--no-nmap', action='store_true')
    parser.add_argument('-o', '--output', default='')
    parser.add_argument('--verify-ssl', action='store_true',
                        help='Enable SSL certificate verification (disabled by default for internal scanning)')
    parser.add_argument('--insecure', action='store_true', default=True,
                        help='Disable SSL verification for internal networks (default)')
    parser.add_argument('--show-passwords', action='store_true',
                        help='Show full passwords in console output (masked by default)')
    args = parser.parse_args()

    # Configure SSL verification globally
    from netspider.security import set_verify_ssl
    set_verify_ssl(args.verify_ssl and not args.insecure)

    # Validate target
    import re
    if re.search(r'[;&|`$(){}<>\[\]!\\]', args.target):
        print(f"Error: Invalid target (contains shell metacharacters): {args.target}")
        sys.exit(1)
    if args.target.strip().startswith('-'):
        print(f"Error: Invalid target (starts with '-'): {args.target}")
        sys.exit(1)

    ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]

    print(f"NetSpider-Max v3.0.0")
    print(f"Target: {args.target} | Ports: {len(ports)}")
    _check_deps()

    from netspider.engine.scheduler import ScanEngineV3
    engine = ScanEngineV3(
        target_cidr=args.target, ports=ports,
        threads=args.threads, timeout=args.timeout,
        use_nmap=not args.no_nmap,
    )
    engine.run()

    # Mask password helper for safe console output
    def _mask(pwd: str) -> str:
        if args.show_passwords:
            return pwd
        if len(pwd) <= 2:
            return '**'
        return pwd[0] + '*' * (len(pwd) - 2) + pwd[-1]

    found = []
    while True:
        try:
            mtype, payload = engine.result_queue.get_nowait()
            if mtype == 'found':
                found.append(payload)
                # Safe output: mask passwords in console unless --show-passwords
                masked_pwd = _mask(payload['password'])
                print(f"  [!] {payload['ip']}:{payload['port']}/{payload['service']} "
                      f"{payload['username']}:{masked_pwd} [{payload.get('finding_type','')}]")
        except Exception:
            break

    print(f"\nDone. {len(found)} weak passwords found.")

    if args.output and found:
        from netspider.output.exporters import export_json
        export_json({'target':args.target, 'ports':args.ports, 'found':found, 'stats':engine.stats},
                    args.output + '.json')
        print(f"Saved: {args.output}.json")


def _run_gui():
    from netspider.gui import ScannerApp
    ScannerApp().run()


def _check_deps():
    from netspider.discovery.nmap import check_nmap
    from netspider.protocols.network import HAS_PARAMIKO

    nmap_ok, nmap_ver = check_nmap()
    print(f"  {'[OK]' if nmap_ok else '[!]'} Nmap: {nmap_ver}")
    print(f"  {'[OK]' if HAS_PARAMIKO else '[!]'} paramiko (SSH)")
    print(f"  [OK] oracledb (Oracle) — mandatory since Phase 2")
    try:
        import httpx; print(f"  [OK] httpx (async HTTP)")
    except ImportError:
        print(f"  [!] httpx: unavailable")
    try:
        import bs4; print(f"  [OK] beautifulsoup4")
    except ImportError:
        print(f"  [!] beautifulsoup4: unavailable")


if __name__ == '__main__':
    main()
