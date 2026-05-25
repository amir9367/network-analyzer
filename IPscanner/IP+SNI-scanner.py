#!/usr/bin/env python3
"""
VLESS IP Scanner — Terminal UI
Tests IPs against a VLESS config by replacing the endpoint IP
and measuring real TLS/HTTP delay, like V2rayN's real delay test.
"""

import asyncio
import ssl
import time
import ipaddress
import socket
import sys
import os
import json
import csv
import re
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from datetime import datetime
import threading

# ── rich imports ──────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, MofNCompleteColumn,
        TaskProgressColumn
    )
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
    from rich.rule import Rule
    from rich.style import Style
    from rich.theme import Theme
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠  rich not installed. Run: pip install rich")
    sys.exit(1)

# ── Theme & console ───────────────────────────────────────────────────────────
THEME = Theme({
    "good":    "bold green",
    "bad":     "bold red",
    "warn":    "bold yellow",
    "info":    "bold cyan",
    "dim":     "dim white",
    "head":    "bold bright_white",
    "latency": "bold magenta",
})
console = Console(theme=THEME, highlight=False)

# ── Data structures ───────────────────────────────────────────────────────────
@dataclass
class VlessConfig:
    uuid:       str
    ip:         str
    port:       int
    sni:        str
    security:   str
    net_type:   str
    path:       str
    host:       str
    alpn:       str
    fp:         str
    encryption: str
    mode:       str
    insecure:   bool
    fragment:   str
    raw_params: dict

    def rebuild(self, new_ip: str) -> str:
        """Rebuild the VLESS URL with a new IP address."""
        params = dict(self.raw_params)
        query = "&".join(
            f"{k}={v[0]}" for k, v in params.items()
        )
        netloc = f"{self.uuid}@{new_ip}:{self.port}"
        url = f"vless://{netloc}?{query}"
        if self.fragment:
            url += f"#{self.fragment}"
        return url


@dataclass
class ScanResult:
    ip:      str
    port:    int
    alive:   bool
    latency: float          # ms, -1 = timeout/error
    note:    str = ""
    ts:      str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


# ── VLESS parser ──────────────────────────────────────────────────────────────
def parse_vless(raw: str) -> VlessConfig:
    raw = raw.strip()
    if not raw.startswith("vless://"):
        raise ValueError("Not a VLESS URI (must start with vless://)")

    parsed   = urlparse(raw)
    uuid     = parsed.username or ""
    ip       = parsed.hostname or ""
    port     = parsed.port or 443
    fragment = parsed.fragment or ""
    params   = parse_qs(parsed.query, keep_blank_values=True)

    def p(key, default=""):
        v = params.get(key)
        return v[0] if v else default

    return VlessConfig(
        uuid       = uuid,
        ip         = ip,
        port       = port,
        sni        = p("sni", ip),
        security   = p("security", "none"),
        net_type   = p("type", "tcp"),
        path       = p("path", "/"),
        host       = p("host", ip),
        alpn       = p("alpn", ""),
        fp         = p("fp", ""),
        encryption = p("encryption", "none"),
        mode       = p("mode", ""),
        insecure   = p("insecure", "0") == "1" or p("allowInsecure", "0") == "1",
        fragment   = fragment,
        raw_params = params,
    )


# ── IP range generator ────────────────────────────────────────────────────────
def expand_ranges(ranges: List[str]) -> List[str]:
    ips = []
    for r in ranges:
        r = r.strip()
        if not r:
            continue
        try:
            net = ipaddress.ip_network(r, strict=False)
            if net.num_addresses == 1:
                ips.append(str(net.network_address))
            else:
                ips.extend(str(h) for h in net.hosts())
        except ValueError:
            # single IP without mask
            try:
                ipaddress.ip_address(r)
                ips.append(r)
            except ValueError:
                console.print(f"[warn]  Skipping invalid range: {r}[/]")
    return ips


# ── Core connectivity test ────────────────────────────────────────────────────
async def test_ip(
    ip: str,
    port: int,
    sni: str,
    host_header: str,
    path: str,
    timeout: float,
    verify_tls: bool,
) -> Tuple[bool, float, str]:
    """
    Full real-delay test:
      1. TCP connect to ip:port
      2. TLS handshake with the given SNI
      3. Send HTTP/1.1 GET request
      4. Read first bytes of response
    Returns (alive, latency_ms, note).
    """
    start = time.perf_counter()
    writer = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        else:
            ctx.load_default_certs()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )

        # HTTP request — mimics what V2rayN's delay test does
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; V2RayN)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000

        if data:
            first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            return True, elapsed, first_line[:60]
        else:
            return False, elapsed, "Empty response"

    except asyncio.TimeoutError:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, "Timeout"
    except ConnectionRefusedError:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, "Connection refused"
    except ssl.SSLError as e:
        elapsed = (time.perf_counter() - start) * 1000
        note    = str(e).split("]")[-1].strip()[:50] if "]" in str(e) else str(e)[:50]
        return False, elapsed, f"SSL: {note}"
    except OSError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, f"OS: {str(e)[:50]}"
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, str(e)[:50]
    finally:
        if writer:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass


# ── Result store (thread-safe) ────────────────────────────────────────────────
class ResultStore:
    def __init__(self):
        self._lock   = asyncio.Lock()
        self.results: List[ScanResult] = []
        self.tested  = 0
        self.alive   = 0
        self.failed  = 0

    async def add(self, r: ScanResult):
        async with self._lock:
            self.results.append(r)
            self.tested += 1
            if r.alive:
                self.alive += 1
            else:
                self.failed += 1

    def avg_latency(self) -> Optional[float]:
        good = [r.latency for r in self.results if r.alive and r.latency > 0]
        return sum(good) / len(good) if good else None

    def best(self) -> Optional[ScanResult]:
        good = [r for r in self.results if r.alive]
        return min(good, key=lambda r: r.latency) if good else None

    def top_n(self, n=20) -> List[ScanResult]:
        good = sorted([r for r in self.results if r.alive], key=lambda r: r.latency)
        return good[:n]


# ── TUI builder ───────────────────────────────────────────────────────────────
def build_config_panel(cfg: VlessConfig, ranges: List[str], total_ips: int) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim", justify="right")
    t.add_column(style="info")

    t.add_row("UUID",     cfg.uuid)
    t.add_row("Original IP", cfg.ip)
    t.add_row("Port",     str(cfg.port))
    t.add_row("SNI",      f"[bold cyan]{cfg.sni}[/]")
    t.add_row("Host",     cfg.host)
    t.add_row("Security", cfg.security)
    t.add_row("Network",  cfg.net_type)
    t.add_row("Path",     cfg.path)
    t.add_row("ALPN",     cfg.alpn or "—")
    t.add_row("Fingerprint", cfg.fp or "—")
    t.add_row("IP Ranges", ", ".join(ranges))
    t.add_row("Total IPs", f"[bold]{total_ips:,}[/]")

    return Panel(t, title="[head]● VLESS Configuration[/]", border_style="cyan", padding=(1, 2))


def build_results_table(store: ResultStore, max_rows: int = 25) -> Table:
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_footer=False,
        padding=(0, 1),
        expand=True,
    )
    tbl.add_column("#",       style="dim",     width=4,  justify="right")
    tbl.add_column("IP Address", style="white", min_width=15)
    tbl.add_column("Port",    style="dim",     width=6,  justify="right")
    tbl.add_column("Status",                   width=10, justify="center")
    tbl.add_column("Latency",                  width=12, justify="right")
    tbl.add_column("Response / Note", style="dim", ratio=1)

    # Show last max_rows results (most recent first)
    rows = list(reversed(store.results[-max_rows:]))
    for i, r in enumerate(rows, 1):
        if r.alive:
            status  = "[good]✔ ALIVE[/]"
            lat_str = f"[latency]{r.latency:.1f} ms[/]"
        else:
            status  = "[bad]✘ DEAD[/]"
            lat_str = f"[dim]{r.latency:.0f} ms[/]" if r.latency > 0 else "[dim]—[/]"

        tbl.add_row(
            str(i),
            r.ip,
            str(r.port),
            status,
            lat_str,
            r.note,
        )
    return tbl


def build_stats_panel(store: ResultStore, total: int) -> Panel:
    avg  = store.avg_latency()
    best = store.best()

    g = Table.grid(padding=(0, 3))
    g.add_column(style="dim",   justify="right")
    g.add_column(style="white", justify="left")

    pct = (store.tested / total * 100) if total else 0
    g.add_row("Tested",  f"[bold]{store.tested:,}[/] / {total:,}  [dim]({pct:.1f}%)[/]")
    g.add_row("Alive",   f"[good]{store.alive:,}[/]")
    g.add_row("Dead",    f"[bad]{store.failed:,}[/]")
    g.add_row("Avg RTT", f"[latency]{avg:.1f} ms[/]" if avg else "[dim]—[/]")
    g.add_row("Best",    f"[good]{best.ip}[/]  [latency]{best.latency:.1f} ms[/]" if best else "[dim]—[/]")

    return Panel(g, title="[head]● Stats[/]", border_style="magenta", padding=(1, 2))


def build_live_layout(
    cfg: VlessConfig,
    ranges: List[str],
    total: int,
    store: ResultStore,
    progress: Progress,
) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=3),
        Layout(name="body"),
        Layout(name="footer",  size=6),
    )
    layout["header"].update(Panel(
        Align.center(
            Text("⚡ VLESS IP SCANNER", style="bold bright_cyan") +
            Text("  —  Real Delay Test", style="dim")
        ),
        border_style="bright_cyan",
    ))
    layout["body"].split_row(
        Layout(name="left",  ratio=2),
        Layout(name="right", ratio=3),
    )
    layout["left"].split_column(
        Layout(build_config_panel(cfg, ranges, total), name="config"),
        Layout(build_stats_panel(store, total),        name="stats"),
    )
    layout["right"].update(Panel(
        build_results_table(store),
        title="[head]● Scan Results[/]",
        border_style="green",
        padding=(0, 1),
    ))
    layout["footer"].update(Panel(
        progress,
        title="[head]● Progress[/]",
        border_style="yellow",
    ))
    return layout


# ── Scanner engine ────────────────────────────────────────────────────────────
async def scanner(
    cfg:         VlessConfig,
    ips:         List[str],
    store:       ResultStore,
    progress:    Progress,
    task_id,
    concurrency: int,
    timeout:     float,
    verify_tls:  bool,
    stop_event:  asyncio.Event,
):
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str):
        if stop_event.is_set():
            return
        async with sem:
            if stop_event.is_set():
                return
            alive, latency, note = await test_ip(
                ip         = ip,
                port       = cfg.port,
                sni        = cfg.sni,
                host_header= cfg.host,
                path       = cfg.path,
                timeout    = timeout,
                verify_tls = verify_tls,
            )
            r = ScanResult(ip=ip, port=cfg.port, alive=alive, latency=latency, note=note)
            await store.add(r)
            progress.advance(task_id)

    await asyncio.gather(*[probe(ip) for ip in ips])


# ── Save results ──────────────────────────────────────────────────────────────
def save_results(store: ResultStore, cfg: VlessConfig, out_path: str):
    ext = os.path.splitext(out_path)[1].lower()

    if ext == ".json":
        data = {
            "sni":     cfg.sni,
            "port":    cfg.port,
            "scanned": store.tested,
            "alive":   store.alive,
            "results": [
                {
                    "ip": r.ip, "port": r.port,
                    "alive": r.alive,
                    "latency_ms": round(r.latency, 2),
                    "note": r.note,
                    "vless_url": cfg.rebuild(r.ip) if r.alive else "",
                    "time": r.ts,
                }
                for r in store.results
            ],
        }
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)

    else:  # CSV default
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Port", "Status", "Latency (ms)", "Note", "VLESS URL", "Time"])
            for r in store.results:
                w.writerow([
                    r.ip, r.port,
                    "ALIVE" if r.alive else "DEAD",
                    f"{r.latency:.2f}",
                    r.note,
                    cfg.rebuild(r.ip) if r.alive else "",
                    r.ts,
                ])

    console.print(f"\n[good]✔[/] Results saved → [bold]{out_path}[/]")


# ── Input helpers ─────────────────────────────────────────────────────────────
def ask_vless() -> VlessConfig:
    while True:
        raw = Prompt.ask(
            "\n[info]Paste VLESS URI[/]",
            default="",
        ).strip()
        if not raw:
            console.print("[warn]  Please enter a VLESS URI.[/]")
            continue
        try:
            cfg = parse_vless(raw)
            return cfg
        except Exception as e:
            console.print(f"[bad]  Parse error: {e}[/]")


def ask_ranges() -> List[str]:
    console.print(
        "\n[info]Enter IP ranges to scan[/]  [dim](comma or newline separated, e.g. 94.130.0.0/24,1.1.1.0/28)[/]"
    )
    while True:
        raw = Prompt.ask("[info]Ranges[/]").strip()
        if not raw:
            console.print("[warn]  At least one range required.[/]")
            continue
        ranges = [r.strip() for r in re.split(r"[,\n\s]+", raw) if r.strip()]
        if ranges:
            return ranges


def ask_settings() -> dict:
    console.print("\n[dim]── Settings (press Enter for defaults) ──[/]")
    concurrency = IntPrompt.ask("[info]Concurrency (parallel workers)[/]", default=50)
    timeout     = float(Prompt.ask("[info]Timeout per IP (seconds)[/]",     default="5"))
    verify_tls  = Confirm.ask("[info]Verify TLS certificate?[/]",           default=False)
    save        = Prompt.ask("[info]Save results to file (leave blank to skip)[/]",
                             default="").strip()
    return {
        "concurrency": max(1, min(concurrency, 512)),
        "timeout":     max(1.0, min(timeout, 30.0)),
        "verify_tls":  verify_tls,
        "save":        save or None,
    }


# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    console.clear()
    console.print(Rule("[bold bright_cyan]⚡  VLESS IP SCANNER[/]  [dim]v1.0[/]", style="cyan"))
    console.print(
        "[dim]Tests IPs by injecting them into your VLESS config and measuring real TLS delay.[/]\n"
    )

    # ── Gather inputs ──────────────────────────────────────────────────────────
    cfg    = ask_vless()
    ranges = ask_ranges()

    console.print("\n[dim]Expanding IP ranges…[/]")
    ips = expand_ranges(ranges)
    if not ips:
        console.print("[bad]No valid IPs found in the given ranges. Exiting.[/]")
        sys.exit(1)

    console.print(f"[good]✔[/] Found [bold]{len(ips):,}[/] IPs across {len(ranges)} range(s).")

    settings = ask_settings()

    console.print(f"\n[dim]Starting scan in 2 seconds… (Ctrl+C to stop early)[/]")
    await asyncio.sleep(2)

    # ── Setup ──────────────────────────────────────────────────────────────────
    store      = ResultStore()
    stop_event = asyncio.Event()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        expand=True,
    )
    task_id = progress.add_task(
        "Scanning", total=len(ips), status=""
    )

    # ── Live TUI ───────────────────────────────────────────────────────────────
    def make_layout():
        return build_live_layout(cfg, ranges, len(ips), store, progress)

    try:
        with Live(
            make_layout(),
            console   = console,
            refresh_per_second = 8,
            screen    = True,
        ) as live:

            async def refresh_loop():
                while not stop_event.is_set():
                    alive_count = store.alive
                    progress.update(task_id, status=f"[good]{alive_count} alive[/]")
                    live.update(make_layout())
                    await asyncio.sleep(0.15)

            refresh_task = asyncio.create_task(refresh_loop())

            try:
                await scanner(
                    cfg         = cfg,
                    ips         = ips,
                    store       = store,
                    progress    = progress,
                    task_id     = task_id,
                    concurrency = settings["concurrency"],
                    timeout     = settings["timeout"],
                    verify_tls  = settings["verify_tls"],
                    stop_event  = stop_event,
                )
            except asyncio.CancelledError:
                pass
            finally:
                stop_event.set()
                refresh_task.cancel()
                try:
                    await refresh_task
                except asyncio.CancelledError:
                    pass
                live.update(make_layout())

    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[warn]⚠  Scan interrupted by user.[/]")

    # ── Final report ───────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]Scan Complete[/]", style="cyan"))

    avg  = store.avg_latency()
    best = store.best()
    top  = store.top_n(10)

    summary = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    summary.add_column(style="dim",   justify="right")
    summary.add_column(style="white")
    summary.add_row("IPs Tested", f"{store.tested:,} / {len(ips):,}")
    summary.add_row("Alive",      f"[good]{store.alive}[/]")
    summary.add_row("Dead",       f"[bad]{store.failed}[/]")
    summary.add_row("Avg RTT",    f"[latency]{avg:.1f} ms[/]" if avg else "—")
    summary.add_row("Best IP",    f"[good]{best.ip}[/]  [latency]{best.latency:.1f} ms[/]" if best else "—")
    console.print(Panel(summary, title="[head]Summary[/]", border_style="cyan"))

    if top:
        console.print("\n[head]Top 10 fastest IPs:[/]")
        t = Table(box=box.SIMPLE, padding=(0, 2))
        t.add_column("#",        style="dim",  width=3,  justify="right")
        t.add_column("IP",       style="good", min_width=15)
        t.add_column("Latency",  style="latency", justify="right")
        t.add_column("Note",     style="dim")
        t.add_column("VLESS URL",style="cyan")
        for i, r in enumerate(top, 1):
            url = cfg.rebuild(r.ip)
            t.add_row(str(i), r.ip, f"{r.latency:.1f} ms", r.note, url)
        console.print(t)

    if settings["save"]:
        save_results(store, cfg, settings["save"])

    # Interactive re-export after scan
    if not settings["save"] and store.alive > 0:
        if Confirm.ask("\n[info]Save results now?[/]", default=True):
            path = Prompt.ask(
                "[info]File path[/]",
                default=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            save_results(store, cfg, path.strip())

    console.print("\n[dim]Done. Goodbye.[/]\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted.[/]")
        sys.exit(0)