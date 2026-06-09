from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.config_checker import ConfigCheckerTool

SSH_BAD = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n"
SSH_GOOD = "PermitRootLogin no\nPasswordAuthentication no\nPort 2222\n"

def test_name():
    assert ConfigCheckerTool().name == "check_configs"

def test_detects_root_login(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text(SSH_BAD)
    r = ConfigCheckerTool().execute(ssh_config_path=str(f))
    assert r.success is True
    assert r.metadata["ssh_issues"] != []
    assert "PermitRootLogin" in r.content

def test_clean_ssh_no_issues(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text(SSH_GOOD)
    r = ConfigCheckerTool().execute(ssh_config_path=str(f))
    assert r.success is True
    assert r.metadata["ssh_issues"] == []

@patch("cybersec.infrastructure.tools.config_checker._run_cmd")
def test_inactive_firewall(mock_cmd):
    mock_cmd.return_value = (0, "Status: inactive\n", "")
    r = ConfigCheckerTool().execute(ssh_config_path="/nonexistent")
    assert "inactive" in r.content.lower() or "desactivado" in r.content.lower()
