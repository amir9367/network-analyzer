import click
from capture.sniffer import start_capture
from storage.database import init_db, query_recent_alerts
from dashboard.app import app

@click.group()
def cli():
    """Network Traffic Analyzer"""
    pass

@cli.command()
@click.option("--interface", "-i", default="eth0", help="Network interface to capture on")
@cli.command()
def capture(interface):
    """Start capturing packets."""
    start_capture(interface=interface)

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