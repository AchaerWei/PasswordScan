"""Protocol tester plugins — auto-registered on import."""
from netspider.plugins.base import PLUGIN_REGISTRY

# Import wrappers to auto-register all v2→v3 adapters
from netspider.plugins import wrappers  # noqa: F401 — side-effect: registers plugins
from netspider.plugins import ipmi      # noqa: F401 — registers IPMI plugin
