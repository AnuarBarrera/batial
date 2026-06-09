import pytest
from cybersec.infrastructure.tools.log_analyzer import LogAnalyzerTool
from cybersec.domain.tools import ToolResult

AUTH_LOG = "\n".join(
    f"Jun  9 10:01:{i:02d} srv sshd[1]: Failed password for root from 10.10.10.10 port 22 ssh2"
    for i in range(12)
)
NGINX_LOG = (
    '1.1.1.1 - - [09/Jun/2026:10:00:00 +0000] "GET /api HTTP/1.1" 500 512\n'
    '1.1.1.1 - - [09/Jun/2026:10:00:01 +0000] "GET /ok HTTP/1.1" 200 1024\n'
)

def test_name():
    assert LogAnalyzerTool().name == "analyze_logs"

def test_returns_tool_result():
    assert isinstance(LogAnalyzerTool().execute(log_files=[]), ToolResult)

def test_empty_log_files_is_error():
    r = LogAnalyzerTool().execute(log_files=[])
    assert r.success is False

def test_missing_file_is_error():
    r = LogAnalyzerTool().execute(log_files=["/no/existe.log"])
    assert r.success is False

def test_detects_brute_force(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(AUTH_LOG)
    r = LogAnalyzerTool().execute(log_files=[str(f)])
    assert r.success is True
    assert "10.10.10.10" in r.content
    assert r.metadata["brute_force_ips"] == ["10.10.10.10"]

def test_detects_5xx(tmp_path):
    f = tmp_path / "nginx.log"
    f.write_text(NGINX_LOG)
    r = LogAnalyzerTool().execute(log_files=[str(f)])
    assert r.success is True
    assert "500" in r.content
