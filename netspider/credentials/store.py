"""Unified Asset Table — single JSON table drives all credential lookups.

Replaces CredentialStore (txt) + MFRDatabase (json).  One table to rule them all.
Tool code never changes to add new assets — just append JSON entries.

Lookup order (per asset):
  1. TOP 100 — always included, highest priority
  2. Unauthorized access — service-specific (Redis, MongoDB, FTP, SNMP...)
  3. Vendor match — fuzzy keyword matching against product/hostname
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset, Credential

_DEFAULT_PATH = Path(__file__).parent.parent.parent / "data" / "unified_asset_table.json"


class UnifiedAssetTable:
    """Loads and queries the unified asset weak password table."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else _DEFAULT_PATH
        self._data: dict = {}
        self._loaded = False
        if self.path.exists():
            self._load()

    def _load(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            self._data = json.load(f)
        self._loaded = True

    def _ensure_loaded(self):
        if not self._loaded:
            self._load()

    # ---- Primary API ----

    def match(self, asset: "Asset", max_creds: int = 300) -> list["Credential"]:
        """Given a discovered asset, return ordered credential list to test."""
        from netspider.types import Credential
        self._ensure_loaded()
        seen: set[tuple[str, str]] = set()
        results: list[Credential] = []

        # Tier 1: TOP 100
        for entry in self._data.get('top100', []):
            key = (entry['u'], entry['p'])
            if key not in seen:
                seen.add(key)
                results.append(Credential(username=entry['u'], password=entry['p'],
                                          source='top100', priority=0))

        # Tier 2: Unauthorized access
        for ua in self._data.get('unauthorized', []):
            if ua['service'] == asset.service:
                for c in ua.get('creds', []):
                    u = c.get('u', '')
                    p = c.get('p', c.get('community', ''))
                    key = (u, p)
                    if key not in seen:
                        seen.add(key)
                        results.append(Credential(username=u, password=p,
                                                  source='unauthorized', priority=1))

        # Tier 3: Vendor match via keywords
        vendor = self._find_vendor(asset)
        if vendor:
            svc_data = vendor.get('services', {}).get(asset.service, {})
            for c in svc_data.get('credentials', []):
                u = c.get('u', '')
                p = c.get('p', c.get('community', ''))
                key = (u, p)
                if key not in seen:
                    seen.add(key)
                    results.append(Credential(username=u, password=p,
                                              source='vendor', priority=2))

        return results[:max_creds]

    def match_phased(self, asset: "Asset", max_creds: int = 300
                     ) -> tuple[list["Credential"], list["Credential"]]:
        """Return phase-split credentials for cascaded testing.

        Returns (vendor_creds, top100_creds).
        Phase 0 (no-auth) is handled by plugin.test_noauth() — NOT via credentials.
        Phase 1 (vendor defaults) — keyword-matched from vendor asset entries.
        Phase 2 (top100) — generic weak passwords, deduped against Phase 1.
        """
        from netspider.types import Credential
        self._ensure_loaded()
        seen: set[tuple[str, str]] = set()
        vendor_creds: list[Credential] = []
        top100_creds: list[Credential] = []

        # Phase 1: Vendor-specific default credentials
        vendor = self._find_vendor(asset)
        if vendor:
            svc_data = vendor.get('services', {}).get(asset.service, {})
            for c in svc_data.get('credentials', []):
                u = c.get('u', '')
                p = c.get('p', c.get('community', ''))
                key = (u, p)
                if key not in seen:
                    seen.add(key)
                    vendor_creds.append(Credential(username=u, password=p,
                                                   source='vendor', priority=1))

        # Phase 2: TOP 100 generic weak passwords (deduped against vendor)
        for entry in self._data.get('top100', []):
            key = (entry['u'], entry['p'])
            if key not in seen:
                seen.add(key)
                top100_creds.append(Credential(username=entry['u'], password=entry['p'],
                                               source='top100', priority=2))

        return (
            vendor_creds[:max_creds],
            top100_creds[:max_creds],
        )

    def match_service(self, service_type: str, max_creds: int = 100) -> list["Credential"]:
        """Get credentials for a service type without Asset context."""
        from netspider.types import Credential
        self._ensure_loaded()
        seen: set[tuple[str, str]] = set()
        results: list[Credential] = []

        for entry in self._data.get('top100', []):
            key = (entry['u'], entry['p'])
            if key not in seen:
                seen.add(key)
                results.append(Credential(username=entry['u'], password=entry['p'],
                                          source='top100'))

        for ua in self._data.get('unauthorized', []):
            if ua['service'] == service_type:
                for c in ua.get('creds', []):
                    u = c.get('u', '')
                    p = c.get('p', c.get('community', ''))
                    key = (u, p)
                    if key not in seen:
                        seen.add(key)
                        results.append(Credential(username=u, password=p,
                                                  source='unauthorized'))

        return results[:max_creds]

    # ---- Vendor matching ----

    def _find_vendor(self, asset: "Asset") -> dict | None:
        search = (asset.product + ' ' + asset.hostname + ' ' + asset.os_family).lower()
        for entry in self._data.get('assets', []):
            for kw in entry.get('keywords', []):
                if kw.lower() in search:
                    return entry
        return None

    # ---- Port management ----

    def get_service_ports(self, service_type: str) -> list[int]:
        self._ensure_loaded()
        return self._data.get('service_ports', {}).get(service_type, [])

    def get_all_ports(self) -> list[int]:
        self._ensure_loaded()
        ports = set()
        for port_list in self._data.get('service_ports', {}).values():
            ports.update(port_list)
        return sorted(ports)

    @property
    def asset_count(self) -> int:
        self._ensure_loaded()
        return len(self._data.get('assets', []))

    @property
    def top100_count(self) -> int:
        self._ensure_loaded()
        return len(self._data.get('top100', []))

    @property
    def loaded(self) -> bool:
        return self._loaded
