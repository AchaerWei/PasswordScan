"""Enhanced Nmap XML parser — extracts OS, hostname, product context for v3 engine."""
from __future__ import annotations
import os, re, subprocess, tempfile
from pathlib import Path
from netspider.types import Asset

from netspider._lib.constants import NAMED_PORTS

# ── XML parsing (with bomb protection) ──────────────────────────
# Prefer defusedxml for hardened XML parsing; fall back to stdlib with
# size limit to prevent billion-laughs / quadratic blowup attacks.
_MAX_XML_BYTES = 100 * 1024 * 1024  # 100 MB limit for nmap XML output
try:
    from defusedxml import ElementTree as SafeET  # type: ignore[import-untyped]
    _XML_PARSER = SafeET
except ImportError:
    import xml.etree.ElementTree as ET
    _XML_PARSER = ET


def _validate_target(target: str) -> str:
    """Validate and sanitize nmap target to prevent argument injection.

    Accepts: CIDR notation (e.g. 192.168.1.0/24), single IPs, hostnames.
    Rejects: targets containing nmap option prefixes (--, -) that could
             be misinterpreted as nmap arguments.
    """
    target = target.strip()
    # Reject targets that start with dash (nmap option injection)
    if target.startswith('-'):
        raise ValueError(f"Invalid target (starts with '-'): {target!r}")
    # Reject targets containing shell metacharacters
    if re.search(r'[;&|`$(){}<>\[\]!\\]', target):
        raise ValueError(f"Invalid target (contains shell metacharacters): {target!r}")
    # Basic sanity: target should be non-empty
    if not target:
        raise ValueError("Empty target")
    return target


def _find_nmap() -> str | None:
    candidates = [
        "nmap",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for c in candidates:
        if os.path.isfile(c) or (not c.endswith('.exe') and _which(c)):
            return c
    return None


def _which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


def check_nmap() -> tuple[bool, str]:
    np = _find_nmap()
    if not np:
        return False, "nmap not installed / not in PATH"
    try:
        r = subprocess.run([np, "--version"], capture_output=True, timeout=5, check=True)
        ver = r.stdout.decode('utf-8', errors='ignore').split('\n')[0]
        return True, ver.strip()
    except Exception as e:
        return False, f"nmap check error: {e}"


def _normalize_service(svc_name: str, port: int) -> str:
    """Normalize nmap service name → internal service fingerprint."""
    s = svc_name.lower()
    if s.startswith('http') or s in ('http-proxy', 'ssl/http', 'http-alt', 'www'):
        return 'https' if port in (443, 8443) or 'ssl' in s else 'http'
    if 'mysql' in s:        return 'mysql'
    if 'postgresql' in s:   return 'postgresql'
    if 'ms-sql' in s or 'mssql' in s: return 'mssql'
    if 'ssh' in s:          return 'ssh'
    if 'telnet' in s:       return 'telnet'
    if 'ftp' in s:          return 'ftp'
    if 'redis' in s:        return 'redis'
    if 'snmp' in s:         return 'snmp'
    if 'rdp' in s or 'ms-wbt-server' in s: return 'rdp'
    if 'smb' in s or 'microsoft-ds' in s or 'netbios-ssn' in s or 'cifs' in s: return 'smb'
    if 'vnc' in s:          return 'vnc'
    if 'mongodb' in s or 'mongod' in s: return 'mongodb'
    if 'elasticsearch' in s: return 'elasticsearch'
    if 'oracle' in s or 'tns' in s: return 'oracle'
    if 'rtsp' in s:         return 'rtsp'
    if 'smtp' in s:         return 'smtp'
    if 'imap' in s:         return 'imap'
    if 'pop3' in s or 'pop' in s: return 'pop3'
    return NAMED_PORTS.get(port, s)


def nmap_scan_assets(target: str, ports: list[int], timeout_sec: int = 180) -> tuple[list[Asset], str]:
    """Run nmap -sV -O and return list[Asset] with full context + diagnostics.

    Extracts per-host: hostname, os_family, os_gen.
    Extracts per-port: service fingerprint, product, version, extrainfo.
    """
    nmap_path = _find_nmap()
    if not nmap_path:
        return [], "nmap not found"

    # Validate target to prevent nmap argument injection
    try:
        target = _validate_target(target)
    except ValueError as e:
        return [], str(e)

    port_str = ",".join(str(p) for p in ports)
    with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tf:
        xml_path = tf.name

    cmd = [nmap_path, "-sV", "-O", "--osscan-guess", "-T4", "--open",
           "-p", port_str, target, "-oX", xml_path]
    assets: list[Asset] = []
    diag = ""

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_sec)
        if r.returncode != 0:
            diag = f"nmap exit={r.returncode}: {r.stderr.decode('utf-8', errors='ignore')[:120]}"
            return assets, diag

        if not os.path.exists(xml_path) or os.path.getsize(xml_path) < 50:
            diag = "nmap XML output empty or too small"
            return assets, diag

        # XML bomb protection: reject oversized XML before parsing
        if os.path.getsize(xml_path) > _MAX_XML_BYTES:
            diag = f"nmap XML too large ({os.path.getsize(xml_path)} > {_MAX_XML_BYTES})"
            return assets, diag

        tree = _XML_PARSER.parse(xml_path)
        root = tree.getroot()

        for host in root.findall('host'):
            addr_elem = host.find('./address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
            ip = addr_elem.get('addr', '')

            status_elem = host.find('status')
            if status_elem is not None and status_elem.get('state') != 'up':
                continue

            # ---- Extract hostname ----
            hostname = ""
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                for hn_elem in hostnames_elem.findall('hostname'):
                    hostname = hn_elem.get('name', '')
                    break  # first hostname only

            # ---- Extract OS ----
            os_family = ""
            os_gen = ""
            os_elem = host.find('os')
            if os_elem is not None:
                for osmatch in os_elem.findall('osmatch'):
                    os_family = osmatch.get('name', '')
                    for osclass in osmatch.findall('osclass'):
                        vendor = osclass.get('vendor', '')
                        family = osclass.get('osfamily', '')
                        gen = osclass.get('osgen', '')
                        if vendor:
                            os_family = vendor
                        if family:
                            os_family = os_family or family
                            if vendor and vendor != family:
                                os_family = f"{vendor} {family}"
                        if gen:
                            os_gen = gen
                        break
                    break   # first osmatch only

            # ---- Extract ports ----
            for port_elem in host.findall('./ports/port'):
                port_id = int(port_elem.get('portid', 0))
                state_elem = port_elem.find('state')
                if state_elem is not None and state_elem.get('state') != 'open':
                    continue

                svc_elem = port_elem.find('service')
                if svc_elem is not None:
                    svc_name = svc_elem.get('name', 'unknown')
                    product = svc_elem.get('product', '')
                    version = svc_elem.get('version', '')
                    extrainfo = svc_elem.get('extrainfo', '')
                else:
                    svc_name = NAMED_PORTS.get(port_id, 'unknown')
                    product = version = extrainfo = ''

                normalized = _normalize_service(svc_name, port_id)

                assets.append(Asset(
                    ip=ip, port=port_id, service=normalized,
                    product=product, version=version, extrainfo=extrainfo,
                    os_family=os_family, os_gen=os_gen, hostname=hostname,
                ))

        unique_ips = len(set(a.ip for a in assets))
        diag = f"nmap OK: {unique_ips} hosts, {len(assets)} services"

    except ET.ParseError as e:
        diag = f"nmap XML parse error: {e}"
    except subprocess.TimeoutExpired:
        diag = f"nmap timeout (>{timeout_sec}s)"
    except Exception as e:
        diag = f"nmap scan error: {e}"
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass

    return assets, diag


def nmap_scan_simple(target: str, ports: list[int], timeout_sec: int = 180) -> tuple[list[dict], str]:
    """Backward-compatible wrapper returning list[dict] (v2 format)."""
    assets, diag = nmap_scan_assets(target, ports, timeout_sec)
    services = []
    for a in assets:
        services.append({
            'ip': a.ip, 'port': a.port, 'service': a.service,
            'product': a.product, 'version': a.version,
        })
    return services, diag
