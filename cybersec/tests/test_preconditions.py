from unittest.mock import patch
from cybersec.infrastructure.preconditions import check_preconditions


@patch("cybersec.infrastructure.preconditions.shutil.which")
def test_no_warnings_when_tools_present(mock_which):
    mock_which.return_value = "/usr/bin/tool"
    assert check_preconditions() == []


@patch("cybersec.infrastructure.preconditions.shutil.which")
def test_warns_when_nmap_missing(mock_which):
    mock_which.side_effect = lambda name: None if name == "nmap" else f"/usr/bin/{name}"
    warnings = check_preconditions()
    assert len(warnings) == 1
    assert "nmap" in warnings[0]
    assert "apt install nmap" in warnings[0]


@patch("cybersec.infrastructure.preconditions.shutil.which")
def test_warns_when_pip_audit_missing(mock_which):
    mock_which.side_effect = lambda name: None if name == "pip-audit" else f"/usr/bin/{name}"
    warnings = check_preconditions()
    assert len(warnings) == 1
    assert "pip-audit" in warnings[0]
    assert "pip install pip-audit" in warnings[0]


@patch("cybersec.infrastructure.preconditions.shutil.which")
def test_warns_when_bandit_missing(mock_which):
    mock_which.side_effect = lambda name: None if name == "bandit" else f"/usr/bin/{name}"
    warnings = check_preconditions()
    assert len(warnings) == 1
    assert "bandit" in warnings[0]
    assert "pip install bandit" in warnings[0]


@patch("cybersec.infrastructure.preconditions.shutil.which")
def test_warns_for_all_missing(mock_which):
    mock_which.return_value = None
    warnings = check_preconditions()
    assert len(warnings) == 3
