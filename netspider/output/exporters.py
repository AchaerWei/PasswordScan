"""Multi-format report exporters — HTML, CSV, JSON, TXT.

SECURITY NOTE: These exporters write credentials to report files.
This is by design for a password audit tool, but callers should:
  - Use mask_pwd_fn to redact passwords in shared reports
  - Set restrictive file permissions on output files
  - Never commit scan results to version control (add to .gitignore)
"""
from __future__ import annotations
import json, csv, io
from datetime import datetime
from pathlib import Path


def _default_mask_pwd(pwd: str) -> str:
    """Default password mask: show first + last char, hide middle."""
    if len(pwd) <= 2:
        return '**'
    return pwd[0] + '*' * (len(pwd) - 2) + pwd[-1]


FT_LABELS = {
    'weak_password': 'Weak Password',
    'no_auth': 'No Authentication',
    'default_password': 'Default Password',
    'open_service': 'Open Service',
}


def export_json(data: dict, path: str | Path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def export_csv(found: list[dict], path: str | Path, mask_pwd_fn=None):
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Port", "Service", "Risk Type", "Username", "Password"])
        for r in found:
            pwd = mask_pwd_fn(r['password']) if mask_pwd_fn else r['password']
            ft = r.get('finding_type', 'weak_password')
            writer.writerow([r['ip'], r['port'], r['service'], ft, r['username'], pwd])


def export_txt(found: list[dict], path: str | Path, meta: dict | None = None,
               mask_pwd_fn=None):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# Weak Password Scan Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if meta:
            f.write(f"# Target: {meta.get('target', '')}  Ports: {meta.get('ports', '')}\n")
            f.write(f"# Hits: {len(found)}\n")
        f.write("\n")
        for r in found:
            ft = r.get('finding_type', 'weak_password')
            pwd = mask_pwd_fn(r['password']) if mask_pwd_fn else r['password']
            f.write(f"{r['ip']}:{r['port']} | {r['service']:12s} | [{ft}] | {r['username']}:{pwd}\n")


def export_html(data: dict, found: list[dict], path: str | Path, mask_pwd_fn=None):
    rows_html = ""
    for r in found:
        ft = r.get('finding_type', 'weak_password')
        ft_label = FT_LABELS.get(ft, ft)
        ft_class = ft
        pwd = mask_pwd_fn(r['password']) if mask_pwd_fn else r['password']
        rows_html += (
            f'<tr class="{ft_class}">'
            f'<td>{r["ip"]}</td><td>{r["port"]}</td><td>{r["service"]}</td>'
            f'<td>{ft_label}</td><td>{r["username"]}</td>'
            f'<td class="pwd">{pwd}</td></tr>\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Weak Password Scan Report — {data.get('time', '')}</title>
<style>
  body {{ font-family: 'Microsoft YaHei', sans-serif; margin: 20px; background: #f5f5f5; }}
  h1 {{ color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 8px; }}
  .meta {{ color: #666; font-size: 14px; margin-bottom: 20px; }}
  .summary {{ background: #fff; border-radius: 8px; padding: 15px; margin-bottom: 20px;
              box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .summary span {{ margin-right: 25px; font-weight: bold; }}
  .hit-count {{ color: #e74c3c; font-size: 18px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th {{ background: #34495e; color: white; padding: 10px 12px; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
  tr.weak_password td {{ background: #ffe0e0; }}
  tr.no_auth td {{ background: #fff3cd; }}
  tr.default_password td {{ background: #ffe0f0; }}
  tr.open_service td {{ background: #e0e0e0; }}
  .pwd {{ font-family: monospace; color: #c0392b; font-weight: bold; }}
  .footer {{ color: #999; font-size: 12px; margin-top: 20px; text-align: center; }}
</style>
</head>
<body>
<h1>Weak Password Scan Report</h1>
<div class="meta">
  Generated: {data.get('time', '')} | Target: {data.get('target', '')} | Ports: {data.get('ports', '')}
</div>
<div class="summary">
  <span>Weak Passwords: <b class="hit-count">{len(found)}</b></span>
  <span>Open Ports: {data.get('stats', {}).get('ports_open', 0)}</span>
  <span>Credential Tests: {data.get('stats', {}).get('creds_tested', 0)}</span>
</div>
<table>
<tr><th>IP Address</th><th>Port</th><th>Service</th><th>Risk Type</th><th>Username</th><th>Password</th></tr>
{rows_html}
</table>
<div class="footer">NetSpider-Max v3 | Authorized security audit use only</div>
</body>
</html>"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
