import pytest
from unittest.mock import patch
from analysis.detector import analyze

def make_packet(src_ip, dst_port, size=100, protocol="TCP"):
    return {
        "src_ip":   src_ip,
        "dst_ip":   "192.168.1.1",
        "src_port": 12345,
        "dst_port": dst_port,
        "protocol": protocol,
        "size":     size,
        "timestamp": "2024-01-01T00:00:00"
    }

def test_port_scan_triggers_alert():
    with patch("analysis.detector.insert_alert") as mock_alert:
        for port in range(1, 20):   # 19 unique ports — above threshold
            analyze(make_packet("10.0.0.1", port))
        mock_alert.assert_called()
        args = mock_alert.call_args[1]
        assert args["alert_type"] == "PORT_SCAN"

def test_no_false_positive_for_normal_traffic():
    with patch("analysis.detector.insert_alert") as mock_alert:
        for _ in range(10):
            analyze(make_packet("10.0.0.2", 443))  # Same port, not a scan
        mock_alert.assert_not_called()