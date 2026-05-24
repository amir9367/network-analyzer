import click
from storage.database import init_db, query_recent_alerts
from dashboard.app import app

@click.group()
def cli():
    """Network Traffic Analyzer"""
    pass

@cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to capture on")
@click.option("--count", "-c", default=0, help="Number of packets to capture (0 = unlimited)")
def capture(interface, count):
    """Start capturing packets."""
    from capture.sniffer import start_capture
    start_capture(interface=interface, count=count)

@cli.command()
def dashboard():
    """Launch the web dashboard."""
    init_db()
    print("[*] Dashboard running at http://localhost:5000")
    app.run(debug=False, port=5000)

@cli.command()
def alerts():
    """Print recent alerts to terminal."""
    init_db()
    rows = query_recent_alerts(20)
    if not rows:
        print("No alerts recorded yet.")
    for r in rows:
        print(f"[{r['timestamp']}] {r['alert_type']} | {r['src_ip']} — {r['detail']}")

if __name__ == "__main__":
    cli()
