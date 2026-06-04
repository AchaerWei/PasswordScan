"""Fingerprint → Plugin binding — matches services to plugins by fingerprint, not port."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.plugins.base import BasePlugin
    from netspider.types import Asset

# Lazy import to avoid circular deps
_PLUGIN_CLASSES: dict[str, type] = {}


def register_plugin_class(service_type: str, plugin_cls: type):
    """Called by plugin modules to register their class."""
    _PLUGIN_CLASSES[service_type] = plugin_cls


def get_plugin_class(service_type: str) -> type | None:
    return _PLUGIN_CLASSES.get(service_type)


# Service fingerprint aliases (e.g. https → http)
SVC_ALIASES = {
    "https": "http",
    "ssl/http": "http",
    "http-proxy": "http",
    "http-alt": "http",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "cifs": "smb",
    "ms-wbt-server": "rdp",
    "mongod": "mongodb",
    "tns": "oracle",
    "pop": "pop3",
}


# Vendor keyword → plugin service_type mapping for HTTP services.
# Must stay aligned with keywords in unified_asset_table.json vendor entries.
_VENDOR_PLUGIN_MAP = {
    'h3c_web':     ('h3c', 'secpath', 'comware'),
    'huawei_web':  ('huawei', 'usg'),
    'cisco_web':   ('cisco', 'ios', 'asa', 'catalyst', 'nexus'),
    'synology_web': ('synology', 'diskstation', 'dsm'),
    'qnap_web':    ('qnap', 'qts', 'turbo nas'),
}


def _match_vendor_plugin(search: str) -> str | None:
    """Return plugin service_type if any vendor keyword matches the search string."""
    search_lower = search.lower()
    for plugin_type, keywords in _VENDOR_PLUGIN_MAP.items():
        if any(kw in search_lower for kw in keywords):
            return plugin_type
    return None


def resolve_plugin(asset: Asset) -> "BasePlugin | None":
    """Resolve the plugin for an asset by its service fingerprint.
    Routes HTTP services to vendor-specific web plugins when product matches.
    Returns None if no plugin is registered for that service type.
    Supports aliased fingerprints (e.g. https → http).
    """
    from netspider.plugins.base import PLUGIN_REGISTRY
    svc = asset.service

    if svc in ('http', 'https'):
        search = (asset.product or '') + ' ' + (asset.hostname or '')
        matched = _match_vendor_plugin(search)
        if matched:
            plugin = PLUGIN_REGISTRY.get(matched)
            if plugin:
                return plugin

    plugin = PLUGIN_REGISTRY.get(svc)
    if plugin is None and svc in SVC_ALIASES:
        plugin = PLUGIN_REGISTRY.get(SVC_ALIASES[svc])
    return plugin


SUPPORTED_FINGERPRINTS: set[str] = set()
"""Populated as plugins register themselves."""


def is_supported(service_type: str) -> bool:
    if service_type in SUPPORTED_FINGERPRINTS:
        return True
    if service_type in SVC_ALIASES:
        return SVC_ALIASES[service_type] in SUPPORTED_FINGERPRINTS
    return False
