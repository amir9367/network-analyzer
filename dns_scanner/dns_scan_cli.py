#!/usr/bin/env python3
"""
dns_scan_cli.py  —  DNS Range Scanner with Terminal UI
Place inside dns_scanner/ folder OR the project root.
Run: python dns_scan_cli.py dns-scan --ranges 2.24.0.0/20 --target example.com
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json as _json
import threading
import time
import logging
from typing import List

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TaskProgressColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from dns_scanner.scanner import DNSScanner, ProbeResult
from dns_scanner.worker import ScanWorker
from dns_scanner.storage import ScanResultStore

logging.basicConfig(level=logging.WARNING)
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """\
 ██████╗ ███╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║  ██║██╔██╗ ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║
 ██║  ██║██║╚██╗██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ██████╔╝██║ ╚████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"""


def print_banner():
    console.print(Align.center(Text(BANNER, style="bold cyan")))
    console.print(
        Align.center(Text("DNS Range Scanner  ·  find resolvers across IP ranges", style="dim"))
    )
    console.print()


def config_panel(args, total_ips: int) -> Panel:
    g = Table.grid(padding=(0, 2))
    g.add_column(style="bold cyan", justify="right")
    g.add_column(style="white")
    g.add_row("Target",      args.target)
    g.add_row("Expected IP", args.expected_ip or "[dim]any response[/dim]")
    g.add_row("Query type",  args.query_type)
    g.add_row("CIDR ranges", "  ".join(f"[yellow]{r}[/yellow]" for r in args.ranges))
    g.add_row("Total IPs",   f"[bold]{total_ips:,}[/bold]")
    g.add_row("Threads",     str(args.threads))
    g.add_row("Timeout",     f"{args.timeout}s")
    g.add_row("Database",    args.db)
    return Panel(g, title="[bold]Scan Configuration[/bold]", border_style="cyan", padding=(1, 2))


def build_matches_table(matches: List[ProbeResult]) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style="bold green", show_edge=False, expand=True)
    t.add_column("Resolver IP",  style="bold white",  min_width=16)
    t.add_column("Resolved IPs", style="green",       min_width=30)
    t.add_column("RTT ms",       style="yellow",      justify="right", min_width=7)
    t.add_column("Hostname",     style="dim",         min_width=20)
    for r in sorted(matches, key=lambda x: x.response_time_ms):
        t.add_row(r.resolver_ip, ", ".join(r.resolved_ips), f"{r.response_time_ms:.0f}", r.hostname)
    return t


def build_stats_panel(probed: int, matched: int, resolved: int, errors: int, rps: float) -> Panel:
    g = Table.grid(padding=(0, 4), expand=True)
    g.add_column(justify="center")
    g.add_column(justify="center")
    g.add_column(justify="center")
    g.add_column(justify="center")
    g.add_column(justify="center")

    def cell(val, label, color):
        return Text.assemble((f"{val}\n", f"bold {color}"), (label, "dim"))

    g.add_row(
        cell(f"{probed:,}",   "Probed",   "cyan"),
        cell(f"{matched:,}",  "Matched",  "green"),
        cell(f"{resolved:,}", "Resolved", "yellow"),
        cell(f"{errors:,}",   "Errors",   "red"),
        cell(f"{rps:.0f}",    "Req/s",    "magenta"),
    )
    return Panel(g, border_style="dim", padding=(0, 1))


# ─────────────────────────────────────────────────────────────────────────────
# Command: dns-scan
# ─────────────────────────────────────────────────────────────────────────────

def cmd_dns_scan(args):
    print_banner()

    scanner = DNSScanner(
        target_hostname=args.target,
        expected_ip=args.expected_ip,
        timeout=args.timeout,
        query_type=args.query_type,
        port=args.port,
    )

    total_ips = sum(scanner.range_size(r) for r in args.ranges)
    console.print(config_panel(args, total_ips))

    store = ScanResultStore(db_path=args.db)
    scan_id = store.create_scan(args.target, args.ranges, args.expected_ip)

    # Shared state
    matches: List[ProbeResult] = []
    all_results: List[ProbeResult] = []
    counters = {"probed": 0, "resolved": 0, "errors": 0}
    lock = threading.Lock()
    t_start = time.perf_counter()

    # Progress bar widget
    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]Scanning[/bold cyan]"),
        BarColumn(bar_width=38, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )
    task = progress.add_task("scan", total=total_ips)

    def make_live_group():
        elapsed = max(time.perf_counter() - t_start, 0.001)
        with lock:
            c = dict(counters)
            m = list(matches)
        rps = c["probed"] / elapsed

        parts = [
            progress,
            build_stats_panel(c["probed"], len(m), c["resolved"], c["errors"], rps),
        ]
        if m:
            parts.append(Panel(
                build_matches_table(m[-12:]),
                title=f"[bold green]✓ Live Matches  ({len(m)})[/bold green]",
                border_style="green",
                padding=(0, 1),
            ))
        return Group(*parts)

    def on_result(result: ProbeResult):
        with lock:
            all_results.append(result)
            counters["probed"] += 1
            if result.matched:
                matches.append(result)
            elif result.success:
                counters["resolved"] += 1
            else:
                counters["errors"] += 1
        progress.advance(task)

    # Patch scanner.probe to capture every result
    original_probe = scanner.probe
    def patched_probe(ip):
        r = original_probe(ip)
        on_result(r)
        return r
    scanner.probe = patched_probe

    worker = ScanWorker(scanner=scanner, threads=args.threads, verbose=False, skip_errors=True)

    console.print(Rule("[dim]Press Ctrl+C to stop early[/dim]"))
    console.print()

    scan_done = threading.Event()

    def run_scan():
        worker.scan_ranges(args.ranges)
        scan_done.set()

    scan_thread = threading.Thread(target=run_scan, daemon=True)

    try:
        with Live(make_live_group(), console=console, refresh_per_second=6,
                  vertical_overflow="visible", auto_refresh=True) as live:
            scan_thread.start()
            while not scan_done.wait(timeout=0.15):
                live.update(make_live_group())
            live.update(make_live_group())  # final frame
    except KeyboardInterrupt:
        worker.stop()
        console.print("\n[yellow]⚠  Interrupted — saving partial results…[/yellow]")
        scan_thread.join(timeout=5)

    elapsed_total = time.perf_counter() - t_start

    # Final summary
    console.print()
    console.print(Rule("[bold]Scan Complete[/bold]"))
    console.print()

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold cyan",  justify="right")
    summary.add_column(style="white")
    summary.add_row("Scan ID",      f"[dim]{scan_id}[/dim]")
    summary.add_row("Elapsed",      f"{elapsed_total:.1f}s")
    summary.add_row("IPs probed",   f"[cyan]{counters['probed']:,}[/cyan]")
    summary.add_row("Matches",      f"[bold green]{len(matches):,}[/bold green]")
    console.print(Panel(summary, border_style="cyan", padding=(1, 2)))

    store.save_results(scan_id, all_results)
    console.print(f"\n  [dim]Saved →[/dim] [cyan]{args.db}[/cyan]  [dim](scan_id: {scan_id})[/dim]")

    if matches:
        console.print()
        console.print(Panel(
            build_matches_table(matches),
            title=f"[bold green]All Matching Resolvers ({len(matches)})[/bold green]",
            border_style="green",
            padding=(1, 2),
        ))
    else:
        console.print("\n  [yellow]No matching resolvers found.[/yellow]")

    if "csv" in args.export:
        console.print(f"  [dim]CSV  →[/dim] [cyan]{store.export_csv(scan_id)}[/cyan]")
    if "json" in args.export:
        console.print(f"  [dim]JSON →[/dim] [cyan]{store.export_json(scan_id)}[/cyan]")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Command: dns-list
# ─────────────────────────────────────────────────────────────────────────────

def cmd_dns_list(args):
    print_banner()
    store = ScanResultStore(db_path=args.db)
    scans = store.list_scans()
    if not scans:
        console.print("[yellow]No scans found.[/yellow]")
        return
    t = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan", expand=True)
    t.add_column("Scan ID",     style="dim",        min_width=35)
    t.add_column("Target",      style="bold white", min_width=25)
    t.add_column("Ranges",      style="yellow",     min_width=20)
    t.add_column("Probed",      justify="right",    style="cyan")
    t.add_column("Matches",     justify="right",    style="green")
    t.add_column("Started",     style="dim",        min_width=20)
    for s in scans:
        try:
            ranges = ", ".join(_json.loads(s["cidr_ranges"]))
        except Exception:
            ranges = s["cidr_ranges"] or "—"
        t.add_row(
            s["scan_id"], s["target"], ranges,
            f"{s['total_probed']:,}",
            f"[bold green]{s['total_matched']:,}[/bold green]",
            (s["started_at"] or "")[:19],
        )
    console.print(Panel(t, title="[bold]Previous Scans[/bold]", border_style="cyan", padding=(1, 1)))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Command: dns-results
# ─────────────────────────────────────────────────────────────────────────────

def cmd_dns_results(args):
    print_banner()
    store = ScanResultStore(db_path=args.db)
    matches = store.get_matches(args.scan_id)
    if not matches:
        console.print(f"[yellow]No matches for:[/yellow] {args.scan_id}")
        return
    t = Table(box=box.ROUNDED, border_style="green", header_style="bold green", expand=True)
    t.add_column("Resolver IP",  style="bold white", min_width=16)
    t.add_column("Resolved IPs", style="green",      min_width=35)
    t.add_column("RTT ms",       justify="right",    style="yellow", min_width=8)
    t.add_column("Hostname",     style="dim",        min_width=20)
    t.add_column("Timestamp",    style="dim",        min_width=20)
    for m in matches:
        t.add_row(
            m["resolver_ip"], m["resolved_ips"], f"{m['response_ms']:.1f}",
            m["hostname"], (m["created_at"] or "")[:19],
        )
    console.print(Panel(
        t, title=f"[bold green]Matches — {args.scan_id}[/bold green]",
        border_style="green", padding=(1, 1),
    ))
    console.print(f"  [dim]Total:[/dim] [bold green]{len(matches)}[/bold green] match(es)\n")


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="dns_scan_cli",
        description="DNS Range Scanner — find resolvers across IP ranges",
    )
    parser.add_argument("--db", default="dns_scan_results.db")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("dns-scan", help="Scan CIDR range(s) for DNS resolvers")
    p.add_argument("--ranges",      nargs="+", required=True, metavar="CIDR")
    p.add_argument("--target",      required=True, metavar="HOSTNAME")
    p.add_argument("--expected-ip", default=None, metavar="IP")
    p.add_argument("--query-type",  default="A",  metavar="TYPE")
    p.add_argument("--port",        type=int,  default=53)
    p.add_argument("--threads",     type=int,  default=256)
    p.add_argument("--timeout",     type=float, default=1.5)
    p.add_argument("--export",      nargs="*", default=[], choices=["csv", "json"])

    sub.add_parser("dns-list", help="List all previous scan runs")

    pr = sub.add_parser("dns-results", help="Show matches from a previous scan")
    pr.add_argument("scan_id")

    return parser


COMMANDS = {"dns-scan": cmd_dns_scan, "dns-list": cmd_dns_list, "dns-results": cmd_dns_results}

if __name__ == "__main__":
    args = build_parser().parse_args()
    COMMANDS[args.command](args)