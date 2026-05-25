"""
dns_scanner/scanner.py
~~~~~~~~~~~~~~~~~~~~~
Core DNS scanning logic.

Given one or more CIDR ranges (e.g. "2.24.0.0/16"), iterates every IP,
uses it as a DNS resolver, queries *target_hostname*, and reports whether
the resolver returns the expected answer.

Usage (library):
    from dns_scanner.scanner import DNSScanner

    scanner = DNSScanner(
        target_hostname="example.com",
        expected_ip=None,          # None = accept any A record
        timeout=1.5,
        query_type="A",
    )
    result = scanner.probe("8.8.8.8")
    print(result)
"""

import ipaddress
import socket
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Result of a single DNS probe against one resolver IP."""
    resolver_ip: str
    hostname: str
    success: bool                        # resolved at all
    matched: bool                        # matched expected_ip (or any if expected=None)
    resolved_ips: list[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    error: Optional[str] = None

    def __repr__(self):
        status = "✓ MATCH" if self.matched else ("✗ NO MATCH" if self.success else f"✗ {self.error}")
        ips = ", ".join(self.resolved_ips) if self.resolved_ips else "—"
        return (
            f"[{self.resolver_ip:>15}] {status:15}  "
            f"→ [{ips}]  {self.response_time_ms:.0f}ms"
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class DNSScanner:
    """
    Probes individual IPs (or whole CIDR ranges) as DNS resolvers.

    Parameters
    ----------
    target_hostname : str
        The domain name to query (e.g. "example.com").
    expected_ip : str | None
        If given, a result is considered a *match* only when at least one
        returned A record equals this IP.  Pass None to match any answer.
    timeout : float
        Per-query timeout in seconds.
    query_type : str
        DNS record type to query ("A", "AAAA", "CNAME", …).
    port : int
        DNS port (default 53).
    """

    def __init__(
        self,
        target_hostname: str,
        expected_ip: Optional[str] = None,
        timeout: float = 1.5,
        query_type: str = "A",
        port: int = 53,
    ):
        self.target_hostname = target_hostname.rstrip(".")
        self.expected_ip = expected_ip
        self.timeout = timeout
        self.query_type = query_type.upper()
        self.port = port

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def probe(self, resolver_ip: str) -> ProbeResult:
        """
        Send one DNS query to *resolver_ip* and return a ProbeResult.
        Never raises — all errors are captured in ProbeResult.error.
        """
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.port = self.port
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        t0 = time.perf_counter()
        try:
            answers = resolver.resolve(self.target_hostname, self.query_type)
            elapsed = (time.perf_counter() - t0) * 1000

            resolved = [rdata.to_text().rstrip(".") for rdata in answers]
            matched = (
                self.expected_ip is None          # accept anything
                or self.expected_ip in resolved
            )
            return ProbeResult(
                resolver_ip=resolver_ip,
                hostname=self.target_hostname,
                success=True,
                matched=matched,
                resolved_ips=resolved,
                response_time_ms=round(elapsed, 2),
            )

        except dns.resolver.NXDOMAIN:
            return self._fail(resolver_ip, "NXDOMAIN", t0)
        except dns.resolver.NoAnswer:
            return self._fail(resolver_ip, "NO_ANSWER", t0)
        except dns.resolver.NoNameservers:
            return self._fail(resolver_ip, "NO_NAMESERVERS", t0)
        except dns.exception.Timeout:
            return self._fail(resolver_ip, "TIMEOUT", t0)
        except Exception as exc:
            return self._fail(resolver_ip, str(exc)[:80], t0)

    def iter_range(self, cidr: str):
        """
        Yield every host IP in *cidr* (e.g. "2.24.0.0/16").
        Skips network and broadcast addresses.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR range '{cidr}': {e}") from e

        for ip in network.hosts():
            yield str(ip)

    def range_size(self, cidr: str) -> int:
        """Return the number of host IPs in *cidr* (for progress display)."""
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses - 2  # subtract network + broadcast

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fail(self, resolver_ip: str, error: str, t0: float) -> ProbeResult:
        elapsed = (time.perf_counter() - t0) * 1000
        return ProbeResult(
            resolver_ip=resolver_ip,
            hostname=self.target_hostname,
            success=False,
            matched=False,
            response_time_ms=round(elapsed, 2),
            error=error,
        )