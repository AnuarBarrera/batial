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

@patch("cybersec.infrastructure.tools.config_checker._run_cmd")
def test_ufw_active_via_systemctl_fallback(mock_cmd):
    # `ufw status` falla por falta de sudo, pero systemctl confirma que está activo
    mock_cmd.side_effect = [
        (1, "", "ERROR: You need to be root to run this script"),  # ufw status
        (0, "active\n", ""),  # systemctl is-active ufw
    ]
    r = ConfigCheckerTool().execute(ssh_config_path="/nonexistent")
    assert "ufw" in r.content.lower()
    assert "activo" in r.content.lower()
    assert "desactivado" not in r.content.lower()
    assert "no detectado" not in r.content.lower()

@patch("cybersec.infrastructure.tools.config_checker._run_cmd")
def test_ufw_inactive_via_systemctl_fallback(mock_cmd):
    # `ufw status` falla por falta de sudo, y systemctl confirma que está inactivo
    mock_cmd.side_effect = [
        (1, "", "ERROR: You need to be root to run this script"),  # ufw status
        (3, "inactive\n", ""),  # systemctl is-active ufw
    ]
    r = ConfigCheckerTool().execute(ssh_config_path="/nonexistent")
    assert "[High]" in r.content
    assert "inactivo" in r.content.lower()

@patch("cybersec.infrastructure.tools.config_checker._run_cmd")
def test_no_firewall_falls_back_to_iptables(mock_cmd):
    # ni ufw ni systemctl disponibles, pero iptables sí responde
    mock_cmd.side_effect = [
        (-1, "", ""),  # ufw status no existe
        (-1, "", ""),  # systemctl no existe
        (0, "Chain INPUT (policy ACCEPT)\n", ""),  # iptables
    ]
    r = ConfigCheckerTool().execute(ssh_config_path="/nonexistent")
    assert "ACCEPT" in r.content
