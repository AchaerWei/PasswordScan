"""Dictionary Builder — assembles per-asset credential lists from unified table.

Uses the UnifiedAssetTable as the single data source:
  Tier 1: TOP 100 (always included)
  Tier 2: Unauthorized access (service-specific)
  Tier 3: Vendor match (keyword-based)

Rule-based mutations can be optionally appended as Tier 4.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset, Credential

from netspider.credentials.store import UnifiedAssetTable


class DictionaryBuilder:
    """Assembles per-asset credential lists from the unified asset table."""

    def __init__(self, table: UnifiedAssetTable | None = None,
                 enable_mutations: bool = False, max_credentials: int = 300):
        self.table = table or UnifiedAssetTable()
        self.enable_mutations = enable_mutations
        self.max_credentials = max_credentials

    def build(self, asset: "Asset") -> list["Credential"]:
        """Assemble deduplicated credential list for one asset."""
        results = self.table.match(asset, max_creds=self.max_credentials)

        # Optional: append mutations
        if self.enable_mutations:
            from netspider.credentials.mutator import generate_credential_mutations
            seen = {(c.username, c.password) for c in results}
            from netspider.types import Credential
            for user, pwd in generate_credential_mutations(asset, max_per_user=3):
                if (user, pwd) not in seen:
                    seen.add((user, pwd))
                    results.append(Credential(username=user, password=pwd,
                                              source='mutation', priority=3))
                    if len(results) >= self.max_credentials:
                        break

        return results[:self.max_credentials]

    def build_for_service(self, service_type: str) -> list["Credential"]:
        """Build credential list for a service type without asset context."""
        return self.table.match_service(service_type)
