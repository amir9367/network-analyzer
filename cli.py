#!/usr/bin/env python3
"""
NetAnalyzer — CLI entry point

Commands:
  capture    Start live packet capture
  dashboard  Launch the web dashboard
  alerts     Print recent alerts
"""

import argparse
import sys


def cmd_capture(args):
    from storage.database import init_db
    from capture.sniffer import start_capture
    init_db()
    start_capture(interface=args.interface, count=args.count)


def cmd_dashboard(args):
    from storage.database import init_db
    from dashboard.app import app
    init_db()
    print("  Dashboard → http://localhost:5000  (Ctrl-C to stop)")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


def cmd_alerts(args):
    from storage.database import init_db, query_recent_alerts
    init_db()
    rows = query_recent_alerts(args.limit)
    if not rows:
        print("  No alerts recorded yet.")
        return
    for r in rows:
        print(f"[{r['timestamp']}] {r['alert_type']:<15} | "
              f"{r['src_ip']:<18} {r['detail']}")


def main():
    parser = argparse.ArgumentParser(
        prog="netanalyzer",
        description="Real-time network traffic analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # capture
    p_cap = sub.add_parser("capture", help="Start live packet capture")
    p_cap.add_argument("-i", "--interface", default=None,
                       help="Network interface (default: auto-detect)")
    p_cap.add_argument("-c", "--count", type=int, default=0,
                       help="Packets to capture; 0 = unlimited (default: 0)")
    p_cap.set_defaults(func=cmd_capture)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Launch the web dashboard")
    p_dash.set_defaults(func=cmd_dashboard)

    # alerts
    p_al = sub.add_parser("alerts", help="Print recent anomaly alerts")
    p_al.add_argument("-n", "--limit", type=int, default=20,
                      help="Number of alerts to show (default: 20)")
    p_al.set_defaults(func=cmd_alerts)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()