"""
dns_scanner/worker.py
~~~~~~~~~~~~~~~~~~~~~
Multi-threaded scan orchestration.

Drives DNSScanner.probe() across large IP ranges using a thread-pool,
streams results via callbacks, and reports real-time progress.

Usage:
    from dns_scanner.scanner import DNSScanner
    from dns_scanner.worker import ScanWorker

    scanner = DNSScanner(target_hostname="example.com")
    worker  = ScanWorker(scanner, threads=200, verbose=True)
    results = worker.scan_ranges(["2.24.0.0/20"])
"""

import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterator, List, Optional

from .scanner import DNSScanner, ProbeResult

logger = logging.getLogger(__name__)


class ScanWorker:
    """
    Orchestrates parallel DNS probing across one or more CIDR ranges.

    Parameters
    ----------
    scanner     : DNSScanner
        Configured scanner instance.
    threads     : int
        Worker thread count (default 256).  Higher → faster but more
        OS/network load.  For a /16 (~65 k hosts) 256 threads finishes
        in a few minutes on a typical connection.
    on_match    : callable, optional
        Called with (ProbeResult,) for every matched result (thread-safe).
    on_progress : callable, optional
        Called with (done: int, total: int) periodically.
    verbose     : bool
        Print every non-timeout result to stdout.
    skip_errors : bool
        Suppress TIMEOUT / connection errors from stdout (default True).
    """

    def __init__(
        self,
        scanner: DNSScanner,
        threads: int = 256,
        on_match: Optional[Callable[[ProbeResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        verbose: bool = False,
        skip_errors: bool = True,
    ):
        self.scanner = scanner
        self.threads = threads
        self.on_match = on_match
        self.on_progress = on_progress
        self.verbose = verbose
        self.skip_errors = skip_errors

        self._lock = threading.Lock()
        self._done = 0
        self._total = 0
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def stop(self):
        """Signal workers to stop after current batch."""
        self._stop.set()

    def scan_ranges(self, cidr_ranges: List[str]) -> List[ProbeResult]:
        """
        Scan all IPs across *cidr_ranges* and return list of ProbeResults.
        Results with matched=True are always included; others only when
        verbose=True or the error is not a plain timeout.
        """
        # Pre-count for progress
        self._total = sum(self.scanner.range_size(r) for r in cidr_ranges)
        self._done = 0
        self._stop.clear()

        all_results: List[ProbeResult] = []
        matches: List[ProbeResult] = []

        stats = defaultdict(int)

        def _ip_generator() -> Iterator[str]:
            for cidr in cidr_ranges:
                for ip in self.scanner.iter_range(cidr):
                    if self._stop.is_set():
                        return
                    yield ip

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self.scanner.probe, ip): ip
                for ip in _ip_generator()
            }

            for future in as_completed(futures):
                if self._stop.is_set():
                    break

                result: ProbeResult = future.result()

                with self._lock:
                    self._done += 1
                    done = self._done
                    total = self._total

                    stats["total"] += 1
                    if result.matched:
                        stats["matched"] += 1
                        matches.append(result)
                        if self.on_match:
                            self.on_match(result)

                    elif result.success:
                        stats["resolved"] += 1
                    else:
                        stats[result.error or "error"] += 1

                    all_results.append(result)

                # Progress callback (outside lock to reduce contention)
                if self.on_progress and done % 100 == 0:
                    self.on_progress(done, total)

                # Stdout
                if self.verbose:
                    if result.matched:
                        print(f"  {result}")
                    elif result.success and not self.skip_errors:
                        print(f"  {result}")
                    elif not result.success and result.error not in ("TIMEOUT",) and not self.skip_errors:
                        print(f"  {result}")

        logger.info(
            "Scan complete | total=%d matched=%d resolved=%d timeout=%d",
            stats["total"], stats["matched"], stats["resolved"], stats["TIMEOUT"],
        )
        return all_results

    # ------------------------------------------------------------------
    # Progress helpers
    # ------------------------------------------------------------------

    @property
    def progress(self) -> tuple[int, int]:
        """Returns (done, total) thread-safely."""
        with self._lock:
            return self._done, self._total

    @property
    def pct(self) -> float:
        done, total = self.progress
        return (done / total * 100) if total else 0.0