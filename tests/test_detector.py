"""Unit tests for analysis/detector.py"""

import importlib
import sys
import pytest


def _fresh_detector():
    """Reload the module so each test starts with clean state."""
    mod_name = "analysis.detector"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    return importlib.import_module(mod_name)


# ── Port-scan ──────────────────────────────────────────────────────────────

def test_port_scan_triggers_alert():
    det = _fresh_detector()
    alerts = []
    for port in range(det.PORT_SCAN_THRESHOLD + 1):
        alerts += det.observe("10.0.0.1", port, 64)
    assert any(a["alert_type"] == "PORT_SCAN" for a in alerts)


def test_port_scan_alert_contains_src_ip():
    det = _fresh_detector()
    alerts = []
    for port in range(det.PORT_SCAN_THRESHOLD + 1):
        alerts += det.observe("192.168.1.99", port, 64)
    scan = next(a for a in alerts if a["alert_type"] == "PORT_SCAN")
    assert scan["src_ip"] == "192.168.1.99"


def test_no_false_positive_below_threshold():
    det = _fresh_detector()
    alerts = []
    for port in range(det.PORT_SCAN_THRESHOLD - 1):
        alerts += det.observe("10.0.0.2", port, 64)
    assert not any(a["alert_type"] == "PORT_SCAN" for a in alerts)


def test_same_port_repeated_does_not_trigger():
    det = _fresh_detector()
    alerts = []
    for _ in range(det.PORT_SCAN_THRESHOLD * 3):
        alerts += det.observe("10.0.0.3", 80, 64)
    assert not any(a["alert_type"] == "PORT_SCAN" for a in alerts)


# ── Traffic-spike ──────────────────────────────────────────────────────────

def test_traffic_spike_triggers_alert():
    det = _fresh_detector()
    alerts = []
    chunk = det.TRAFFIC_SPIKE_BYTES // 10
    for _ in range(11):
        alerts += det.observe("10.0.0.4", None, chunk)
    assert any(a["alert_type"] == "TRAFFIC_SPIKE" for a in alerts)


def test_traffic_spike_below_threshold_no_alert():
    det = _fresh_detector()
    alerts = []
    for _ in range(5):
        alerts += det.observe("10.0.0.5", None, det.TRAFFIC_SPIKE_BYTES // 10)
    assert not any(a["alert_type"] == "TRAFFIC_SPIKE" for a in alerts)


def test_no_port_scan_when_port_is_none():
    det = _fresh_detector()
    alerts = []
    for _ in range(det.PORT_SCAN_THRESHOLD * 2):
        alerts += det.observe("10.0.0.6", None, 64)
    assert not any(a["alert_type"] == "PORT_SCAN" for a in alerts)