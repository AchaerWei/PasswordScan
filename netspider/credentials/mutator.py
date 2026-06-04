"""Context-aware password mutation engine.

Generates password variants from asset context using rules like:
  - Capitalize first letter + year + special char (e.g. Baidu@2026)
  - Hostname variants (e.g. H3C-SW-01 → h3csw01, H3CSW01, H3C@2026)
  - Username + common suffixes (e.g. admin123, root2026)
"""
from __future__ import annotations
import itertools
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset

CURRENT_YEAR = str(datetime.now().year)  # 2026
COMMON_SUFFIXES = ["123", "123456", "1234", "!", "@", "#", "1", "2026", CURRENT_YEAR]
COMMON_SPECIAL = ["@", "!", "#", "$", "%", "_", "-", "."]
COMMON_YEARS = [CURRENT_YEAR, str(int(CURRENT_YEAR) - 1), str(int(CURRENT_YEAR) - 2)]


def _extract_tokens(asset: "Asset") -> list[str]:
    """Extract word tokens from asset context for mutation."""
    tokens: list[str] = []

    # Hostname tokens
    if asset.hostname:
        hn = asset.hostname.lower()
        # Split on common separators
        parts = _re_split(r'[.\-_]', hn)
        tokens.extend(p for p in parts if len(p) >= 2)
        # Add the full hostname (first part before dot)
        if '.' in hn:
            tokens.append(hn.split('.')[0])

    # Product tokens
    if asset.product:
        prod = asset.product.lower()
        tokens.extend(p for p in _re_split(r'[\s\-_/]', prod) if len(p) >= 2)

    # OS tokens
    if asset.os_family:
        tokens.append(asset.os_family.lower())
    if asset.os_gen:
        tokens.extend(p for p in re_split(r'[\s\-_]', asset.os_gen.lower()) if len(p) >= 2)

    return list(set(tokens))


def _re_split(pattern: str, text: str) -> list[str]:
    import re
    return [s for s in re.split(pattern, text) if s]


def generate_mutations(asset: "Asset", max_count: int = 80) -> list[str]:
    """Generate password variants from asset context.

    Returns a list of candidate passwords (no usernames — just passwords).
    """
    tokens = _extract_tokens(asset)
    if not tokens:
        return []

    passwords: set[str] = set()

    for token in tokens:
        # skip very short tokens
        if len(token) < 2:
            continue

        cap = token.capitalize()
        upper = token.upper()
        lower = token.lower()

        # Token + year
        for yr in COMMON_YEARS:
            passwords.add(f"{cap}{yr}")
            passwords.add(f"{lower}{yr}")
            passwords.add(f"{upper}{yr}")

        # Token + year + special
        for yr in COMMON_YEARS[:1]:   # only current year
            for sp in COMMON_SPECIAL[:3]:  # @, !, #
                passwords.add(f"{cap}{yr}{sp}")
                passwords.add(f"{cap}{sp}{yr}")
                passwords.add(f"{lower}{yr}{sp}")

        # Token + common suffix
        for suffix in COMMON_SUFFIXES[:4]:
            passwords.add(f"{lower}{suffix}")
            passwords.add(f"{cap}{suffix}")

        # Token@year
        passwords.add(f"{cap}@{CURRENT_YEAR}")
        passwords.add(f"{lower}@{CURRENT_YEAR}")

        # No separator combinations
        if len(tokens) >= 2:
            for t2 in tokens:
                if t2 != token and len(t2) >= 2:
                    passwords.add(f"{lower}{t2.lower()}")
                    passwords.add(f"{cap}{t2.capitalize()}")

    # Limit
    result = list(passwords)[:max_count]
    return result


def generate_credential_mutations(asset: "Asset",
                                  base_usernames: list[str] | None = None,
                                  max_per_user: int = 10) -> list[tuple[str, str]]:
    """Generate (username, password) pairs from mutations.

    Combines common admin usernames with mutated passwords.
    """
    if base_usernames is None:
        base_usernames = ["admin", "root", "administrator", "user", "guest"]

    passwords = generate_mutations(asset, max_count=50)
    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for pwd in passwords:
        for usr in base_usernames:
            pair = (usr, pwd)
            if pair not in seen:
                seen.add(pair)
                results.append(pair)
                if len(results) >= len(base_usernames) * max_per_user:
                    return results

    return results
