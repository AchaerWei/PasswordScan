"""Asset-centric result aggregation — groups findings by IP for risk topology view."""
from __future__ import annotations
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import AssetFindings


def aggregate_findings(found_entries: list[dict],
                       open_ports: list[dict] | None = None) -> list[dict]:
    """Group scan findings by IP address.

    Returns list of per-IP asset summaries:
      {
        "ip": "192.168.1.1",
        "risk_level": "high",
        "finding_count": 3,
        "findings": [...],
        "services": [...],
      }
    """
    by_ip: dict[str, dict] = defaultdict(lambda: {
        "ip": "", "risk_level": "low", "finding_count": 0,
        "findings": [], "services": [],
    })

    if open_ports:
        for p in open_ports:
            ip = p.get('ip', '') or p.get('addr', '')
            if ip:
                by_ip[ip]["ip"] = ip
                by_ip[ip]["services"].append(p)

    for entry in found_entries:
        ip = entry.get('ip', '')
        if not ip:
            continue
        by_ip[ip]["ip"] = ip
        by_ip[ip]["findings"].append(entry)
        by_ip[ip]["finding_count"] += 1

        ft = entry.get('finding_type', '')
        if ft in ('weak_password', 'default_password', 'no_auth'):
            by_ip[ip]["risk_level"] = "high"
        elif ft == 'open_service' and by_ip[ip]["risk_level"] != "high":
            by_ip[ip]["risk_level"] = "medium"

    return sorted(by_ip.values(), key=lambda x: (
        {"high": 0, "medium": 1, "low": 2}.get(x["risk_level"], 3),
        -x["finding_count"],
        x["ip"],
    ))


def build_risk_summary(aggregated: list[dict]) -> dict:
    """Build summary statistics from aggregated results."""
    total_ips = len(aggregated)
    high = sum(1 for a in aggregated if a["risk_level"] == "high")
    medium = sum(1 for a in aggregated if a["risk_level"] == "medium")
    low = sum(1 for a in aggregated if a["risk_level"] == "low")
    total_findings = sum(a["finding_count"] for a in aggregated)

    return {
        "total_ips": total_ips,
        "risk_high": high,
        "risk_medium": medium,
        "risk_low": low,
        "total_findings": total_findings,
    }
