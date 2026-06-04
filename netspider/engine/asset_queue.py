"""Per-asset burst work queue — orders assets by risk priority for vertical scanning.

Strategy (v3): one asset → all credentials → next asset.
Contrast with v2: one (service, credential) pair → all matching assets → next pair.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset, Credential


@dataclass
class BurstTask:
    """A single asset's full credential burst work unit."""
    asset: "Asset"
    credentials: list["Credential"] = field(default_factory=list)
    plugin_name: str = ""


def build_burst_queue(assets: list["Asset"],
                      credential_builder=None) -> list[BurstTask]:
    """Build ordered burst queue from discovered assets.

    Ordering:
      1. By risk_priority descending (database/remote-first, HTTP-last)
      2. Within same priority: by IP then port for determinism
    """
    sorted_assets = sorted(
        assets,
        key=lambda a: (-a.risk_priority, a.ip, a.port),
    )

    tasks = []
    for asset in sorted_assets:
        creds = []
        if credential_builder:
            creds = credential_builder.build(asset)
        tasks.append(BurstTask(
            asset=asset,
            credentials=creds,
            plugin_name=asset.service,
        ))

    return tasks


def asset_stats(assets: list["Asset"]) -> dict:
    """Summary statistics for discovered assets."""
    from collections import Counter
    svc_counts = Counter(a.service for a in assets)
    unique_ips = len(set(a.ip for a in assets))
    return {
        'total_services': len(assets),
        'unique_ips': unique_ips,
        'by_service': dict(svc_counts.most_common()),
    }
