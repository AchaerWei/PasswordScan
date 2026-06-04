"""DualDriverScheduler — asyncio (HTTP/web) + ThreadPoolExecutor (native protocols).

Routes each plugin to the optimal execution model:
  - HTTP/HTTPS → asyncio + httpx (2000+ concurrent requests on a single core)
  - SSH/MySQL/RDP/etc → ThreadPoolExecutor (200 threads for blocking native I/O)

httpx is optional. When unavailable, HTTP plugins run on ThreadPool with urllib fallback.
"""
from __future__ import annotations
import asyncio, time, logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netspider.types import Asset, Credential, ScanResult
    from netspider.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

# Optional httpx
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    httpx = None


class DualDriverScheduler:
    """Orchestrates per-asset credential bursts across async + threaded executors."""

    def __init__(self, http_concurrency: int = 1000, thread_workers: int = 200,
                 timeout: float = 5.0):
        self.http_concurrency = http_concurrency
        self.thread_workers = thread_workers
        self.timeout = timeout

        self._thread_pool: ThreadPoolExecutor | None = None
        self._http_client = None        # httpx.AsyncClient | None
        self._http_semaphore: asyncio.Semaphore | None = None
        self._stop_flag = False

    # ---- Public API ----

    async def burst_asset(self, plugin: "BasePlugin", asset: "Asset",
                          credentials: list["Credential"]) -> list["ScanResult"]:
        """Fire all credentials against one asset concurrently, return all results."""
        if plugin.is_async and HAS_HTTPX:
            return await self._burst_async(plugin, asset, credentials)
        else:
            return await self._burst_threaded(plugin, asset, credentials)

    def burst_asset_sync(self, plugin: "BasePlugin", asset: "Asset",
                         credentials: list["Credential"]) -> list["ScanResult"]:
        """Synchronous wrapper for callers outside asyncio (e.g. GUI thread).

        Each call may use a fresh event loop (via asyncio.run), so we must
        reset the httpx client bound to the previous loop to avoid silent
        failures from event-loop mismatch.
        """
        if plugin.is_async and HAS_HTTPX:
            self._http_client = None
            self._http_semaphore = None
            return asyncio.run(self._burst_async(plugin, asset, credentials))
        else:
            return asyncio.run(self._burst_threaded(plugin, asset, credentials))

    async def shutdown(self):
        """Clean up resources."""
        self._stop_flag = True
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
        if self._thread_pool is not None:
            self._thread_pool.shutdown(wait=False)
            self._thread_pool = None

    # ---- Internal ----

    async def _burst_async(self, plugin: "BasePlugin", asset: "Asset",
                           credentials: list["Credential"]) -> list["ScanResult"]:
        """asyncio path: fire-and-gather via httpx shared client."""
        if self._http_client is None:
            limits = httpx.Limits(
                max_connections=self.http_concurrency,
                max_keepalive_connections=200,
            )
            from netspider.security import get_verify_ssl
            verify_ssl = get_verify_ssl()
            self._http_client = httpx.AsyncClient(
                limits=limits, verify=verify_ssl,
                timeout=httpx.Timeout(self.timeout),
            )
        if self._http_semaphore is None:
            self._http_semaphore = asyncio.Semaphore(self.http_concurrency)

        sem = self._http_semaphore

        async def _one(cred):
            async with sem:
                try:
                    return await plugin.test_async(self._http_client, asset, cred)
                except Exception:
                    from netspider.types import ScanResult
                    return ScanResult(False)

        tasks = [_one(c) for c in credentials]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        out = []
        for r in results:
            if isinstance(r, Exception):
                from netspider.types import ScanResult
                out.append(ScanResult(False))
            else:
                out.append(r)
        return out

    async def _burst_threaded(self, plugin: "BasePlugin", asset: "Asset",
                              credentials: list["Credential"]) -> list["ScanResult"]:
        """ThreadPool path: run blocking test() calls, gather results."""
        if self._thread_pool is None:
            self._thread_pool = ThreadPoolExecutor(max_workers=self.thread_workers)

        loop = asyncio.get_event_loop()

        def _one(cred):
            if self._stop_flag:
                from netspider.types import ScanResult
                return ScanResult(False)
            try:
                return plugin.test(asset, cred)
            except Exception:
                from netspider.types import ScanResult
                return ScanResult(False)

        futures = [loop.run_in_executor(self._thread_pool, _one, c) for c in credentials]
        results = await asyncio.gather(*futures, return_exceptions=True)

        out = []
        for r in results:
            if isinstance(r, Exception):
                from netspider.types import ScanResult
                out.append(ScanResult(False))
            else:
                out.append(r)
        return out


# ---- Legacy compatibility wrapper ----

class ScanEngineV3:
    """v3 ScanEngine — backward-compatible with v2 ScanEngine.run() interface.

    Uses DualDriverScheduler internally. Provides the same queue-based
    status/result reporting that the GUI expects.
    """

    def __init__(self, target_cidr: str, ports: list[int],
                 threads: int = 100, timeout: float = 2.0,
                 unified_table=None, max_creds_per_svc: int = 100,
                 rate_limit: float = 0.0, use_nmap: bool = True):
        import queue
        from ipaddress import ip_network
        from netspider.discovery.nmap import check_nmap
        from netspider.credentials.store import UnifiedAssetTable

        self.target = target_cidr
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.max_creds_per_svc = max_creds_per_svc
        self.rate_limit = rate_limit

        nmap_avail, _ = check_nmap()
        self.use_nmap = use_nmap and nmap_avail
        self.unified_table = unified_table if unified_table is not None else UnifiedAssetTable()

        self._stop_flag = False
        self._running = False
        self.result_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.stats = {
            'ips_total': 0, 'ports_open': 0, 'services': 0,
            'creds_tested': 0, 'creds_found': 0, 'phase': 'init',
        }

        self.scheduler = DualDriverScheduler(
            http_concurrency=min(1000, threads * 10),
            thread_workers=max(5, min(threads // 2, 200)),
            timeout=timeout,
        )
        self._assets: list[Asset] = []

    @property
    def hosts(self) -> list[str]:
        from ipaddress import ip_network
        net = ip_network(self.target, strict=False)
        return [str(h) for h in net.hosts()]

    def stop(self):
        self._stop_flag = True
        self._running = False
        self.scheduler._stop_flag = True

    def run(self):
        import threading
        self._running = True
        self._stop_flag = False
        try:
            self._run_impl()
        except KeyboardInterrupt:
            self.status_queue.put(('info', "Interrupted by user, shutting down..."))
            self.stop()
        finally:
            self._running = False

    def _run_impl(self):
        self._running = True
        self._stop_flag = False

        # Ensure unified table is loaded
        if not self.unified_table.loaded:
            self.unified_table._ensure_loaded()

        hosts = self.hosts
        self.stats['ips_total'] = len(hosts)
        self.status_queue.put(('info', f"Target: {self.target} ({len(hosts)} IPs, {len(self.ports)} ports)"))

        # ---- Phase 1: Discovery ----
        if self.use_nmap:
            self.status_queue.put(('info', "Phase 1/2: Nmap -sV -O service discovery..."))
            from netspider.discovery.nmap import nmap_scan_assets
            assets, diag = nmap_scan_assets(self.target, self.ports)
            self.status_queue.put(('info', f"Nmap: {diag}"))
        else:
            self.status_queue.put(('info', "Phase 1/2: TCP port scan (no nmap, using built-in)..."))
            assets, diag = self._discover_socket(hosts)

        # Also emit port rows for GUI
        for a in assets:
            self.result_queue.put(('port', {
                'ip': a.ip, 'port': a.port, 'service': a.service,
                'product': a.product or '', 'version': a.version or '',
            }))

        if self._stop_flag:
            self.status_queue.put(('done', None))
            return

        self._assets = assets
        self.stats['services'] = len(assets)
        self.stats['ports_open'] = len(set((a.ip, a.port) for a in assets))
        self.status_queue.put(('info', f"Phase 1 done: {len(assets)} services ({self.stats['ports_open']} open ports)"))

        if not assets:
            self.status_queue.put(('info', "No open services found, scan complete"))
            self.status_queue.put(('done', None))
            self._running = False
            return

        # ---- Phase 2: Per-asset burst ----
        self.status_queue.put(('info', "Phase 2/2: Credential testing (per-asset burst)..."))
        self._run_burst(assets)

        self.status_queue.put(('done', None))
        self._running = False

    def _run_burst(self, assets: list[Asset]):
        """Per-asset phased burst: no-auth → vendor defaults → top100.

        Phase 0: Anonymous/No-Auth probe (1 attempt per asset).
        Phase 1: Vendor-specific default credentials, early exit on first hit.
        Phase 2: TOP100 weak passwords, gather all hits.

        Each phase only activates if the previous phase found nothing.
        """
        from netspider.discovery.matcher import resolve_plugin
        from netspider.types import FindingType

        tested = 0
        sorted_assets = sorted(assets, key=lambda a: a.risk_priority, reverse=True)

        self.status_queue.put(('info', "Phased testing: no-auth → vendor defaults → top100"))
        self.status_queue.put(('phase2_start', len(sorted_assets)))

        for asset in sorted_assets:
            if self._stop_flag:
                break

            plugin = resolve_plugin(asset)
            if plugin is None:
                self.result_queue.put(('info_port', {
                    'ip': asset.ip, 'port': asset.port, 'service': asset.service,
                }))
                continue

            # ---- Phase 0: Anonymous / No-Auth Probe ----
            try:
                result = plugin.test_noauth(asset)
                tested += 1
                if result.success:
                    entry = {
                        'ip': asset.ip, 'port': asset.port,
                        'service': asset.service,
                        'username': '', 'password': '',
                        'finding_type': result.finding_type.value,
                    }
                    self.result_queue.put(('found', entry))
                    self.stats['creds_found'] += 1
                    self.stats['creds_tested'] = tested
                    continue  # Skip to next asset
            except Exception:
                pass

            # ---- Phase 1: Vendor-specific default credentials ----
            vendor_creds, top100_creds = (
                self.unified_table.match_phased(asset, max_creds=self.max_creds_per_svc)
            )

            if vendor_creds:
                results = self.scheduler.burst_asset_sync(plugin, asset, vendor_creds)
                hit = False
                for cred, result in zip(vendor_creds, results):
                    if self._stop_flag:
                        break
                    tested += 1
                    if result.success:
                        ftype = result.finding_type.value if result.finding_type else 'default_password'
                        entry = {
                            'ip': asset.ip, 'port': asset.port,
                            'service': asset.service,
                            'username': cred.username, 'password': cred.password,
                            'finding_type': ftype,
                        }
                        self.result_queue.put(('found', entry))
                        self.stats['creds_found'] += 1
                        hit = True
                        break  # Early exit on first Phase 1 hit
                if hit:
                    self.stats['creds_tested'] = tested
                    continue  # Skip Phase 2

            # ---- Phase 2: TOP100 weak passwords ----
            if top100_creds:
                results = self.scheduler.burst_asset_sync(plugin, asset, top100_creds)
                for cred, result in zip(top100_creds, results):
                    if self._stop_flag:
                        break
                    tested += 1
                    if result.success:
                        ftype = result.finding_type.value if result.finding_type else 'weak_password'
                        entry = {
                            'ip': asset.ip, 'port': asset.port,
                            'service': asset.service,
                            'username': cred.username, 'password': cred.password,
                            'finding_type': ftype,
                        }
                        self.result_queue.put(('found', entry))
                        self.stats['creds_found'] += 1

            self.stats['creds_tested'] = tested
            if tested % 200 == 0 or tested < 200:
                self.status_queue.put(('progress_val',
                    f"Testing: {tested} | Hits: {self.stats['creds_found']}", tested))

    def _discover_socket(self, hosts: list[str]) -> tuple[list[Asset], str]:
        """Fallback TCP connect discovery when nmap is not available."""
        from netspider._lib.tcp_connect import tcp_connect
        from netspider.types import Asset
        assets = []
        total = len(hosts) * len(self.ports)
        done = 0

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {}
            for ip in hosts:
                if self._stop_flag:
                    break
                for port in self.ports:
                    futures[ex.submit(tcp_connect, ip, port, self.timeout)] = (ip, port)

            for f in as_completed(futures):
                if self._stop_flag:
                    break
                ip, port = futures[f]
                done += 1
                try:
                    svc = f.result()
                    if svc:
                        assets.append(Asset(ip=ip, port=port, service=svc))
                except Exception:
                    pass

        return assets, f"TCP scan: {len(assets)} open ports"
