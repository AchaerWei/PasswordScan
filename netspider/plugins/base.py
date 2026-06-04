"""Plugin base class and registry for NetSpider-Max v3 engine.

Each plugin wraps a protocol tester.  Plugins declare:
  - service_type: the fingerprint they bind to (e.g. "ssh", not port 22)
  - is_async: True for HTTP/web plugins → asyncio scheduler
              False for native protocol plugins → ThreadPoolExecutor scheduler
"""
from __future__ import annotations
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset, Credential, ScanResult


class BasePlugin:
    """A protocol tester plugin.

    Subclasses MUST define name and service_type.
    Subclasses MUST override either test() (sync) or test_async() (async),
    or both for plugins that support both execution modes.
    """

    name: str = "base"
    service_type: str = "unknown"
    is_async: bool = False

    def test(self, asset: Asset, cred: Credential) -> ScanResult:
        """Synchronous credential test.  Called from ThreadPoolExecutor."""
        raise NotImplementedError(f"{self.name}: test() not implemented")

    async def test_async(self, client, asset: Asset, cred: Credential) -> ScanResult:
        """Async credential test.  Called from asyncio event loop.
        `client` is an httpx.AsyncClient for HTTP plugins.
        """
        raise NotImplementedError(f"{self.name}: test_async() not implemented")

    def test_noauth(self, asset: Asset) -> ScanResult:
        """Probe whether this service is accessible without authentication.

        Returns ScanResult(True, FindingType.NO_AUTH) if no auth is required.
        Default returns False — subclasses MAY override.
        """
        from netspider.types import ScanResult
        return ScanResult(False)

    async def test_noauth_async(self, client, asset: Asset) -> ScanResult:
        """Async variant of test_noauth(). Default returns False."""
        from netspider.types import ScanResult
        return ScanResult(False)

    def __repr__(self):
        return f"<Plugin {self.name} svc={self.service_type} async={self.is_async}>"


class PluginRegistry:
    """Registry mapping service fingerprints → plugin instances."""

    def __init__(self):
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin):
        self._plugins[plugin.service_type] = plugin

    def get(self, service_type: str) -> BasePlugin | None:
        return self._plugins.get(service_type)

    def __contains__(self, service_type: str) -> bool:
        return service_type in self._plugins

    def __iter__(self):
        return iter(self._plugins.values())

    def __len__(self):
        return len(self._plugins)

    @property
    def supported_services(self) -> list[str]:
        return sorted(self._plugins.keys())


# Global plugin registry — populated at import time by each plugin module
PLUGIN_REGISTRY = PluginRegistry()
