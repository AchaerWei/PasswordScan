"""NetSpider-Max v3 — high-performance weak password scanner engine.

Key modules (lazy-loaded):
  - types → core dataclasses (Asset, Credential, ScanResult, ...)
  - engine/scheduler → DualDriverScheduler (async + thread hybrid)
  - discovery/nmap → Enhanced Nmap XML parsing with OS/hostname
  - credentials/builder → 3-tier dictionary (TOP100 + MFR + mutations)
  - plugins/wrappers → v2 protocol testers as v3 plugins
  - output/ → Multi-format exporters + JSON pipeline
"""
from netspider.types import (
    Asset, Credential, NmapContext, ScanResult,
    FindingType, NetworkError, AssetFindings,
)

__version__ = "3.0.0"
