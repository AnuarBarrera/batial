# cybersec/tests/test_port_scanner.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.port_scanner import PortScannerTool
from cybersec.domain.tools import ToolResult

NMAP_OUT = """
Nmap scan report for localhost (127.0.0.1)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
"""

def test_name():
    assert PortScannerTool().name == "scan_ports"

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_parses_open_ports(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=NMAP_OUT, stderr="")
    r = PortScannerTool().execute(host="localhost")
    assert r.success is True
    assert 22 in r.metadata["open_ports"]
    assert 80 in r.metadata["open_ports"]

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_flags_sensitive_port(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=NMAP_OUT, stderr="")
    r = PortScannerTool().execute(host="localhost")
    assert 3306 in r.metadata["sensitive_ports"]
    assert "3306" in r.content

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_nmap_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()
    r = PortScannerTool().execute(host="localhost")
    assert r.success is False
    assert "nmap" in r.error.lower()
