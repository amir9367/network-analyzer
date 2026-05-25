"""
NetAnalyzer CLI — capture, dashboard, and alerts.

Usage:
  python cli.py capture [--interface IF] [--count N]
  python cli.py dashboard [--port PORT]
  python cli.py alerts [--limit N]
"""
import sys
import click

from storage.database import init_db, query_recent_alerts


@click.group()
def cli():
    """🛡️ NetAnalyzer — real-time network traffic analyzer."""


@cli.command()
@click.option("--interface", "-i", default=None,
              help="Network interface (auto-detected when omitted).")
@click.option("--count", "-c", default=0, show_default=True,
              help="Packets to capture; 0 = unlimited.")
def capture(interface, count):
    """Capture live packets and store them to the database."""
    from capture.sniffer import start_capture
    start_capture(interface=interface, count=count)


@cli.command()
@click.option("--port", "-p", default=5000, show_default=True,
              help="Port to serve the dashboard on.")
def dashboard(port):
    """Launch the live web dashboard."""
    init_db()
    from dashboard.app import app
    click.echo(f"[*] Dashboard → http://localhost:{port}")
    click.echo("[*] Run capture in a separate terminal to see live data.")
    app.run(host="127.0.0.1", port=port, debug=False)


@cli.command()
@click.option("--limit", "-n", default=20, show_default=True,
              help="Number of recent alerts to display.")
def alerts(limit):
    """Print recent anomaly alerts to the terminal."""
    init_db()
    rows = query_recent_alerts(limit)
    if not rows:
        click.echo("No alerts recorded yet.")
        return
    for r in rows:
        click.echo(
            f"[{r['timestamp']}] {r['alert_type']:<15} "
            f"| {r['src_ip']:<18} — {r['detail']}"
        )


if __name__ == "__main__":
    cli()