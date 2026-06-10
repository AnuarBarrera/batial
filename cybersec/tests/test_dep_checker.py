# cybersec/tests/test_dep_checker.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.dep_checker import DependencyCheckerTool

PIP_AUDIT_JSON = '{"dependencies":[{"name":"requests","version":"2.25.0","vulns":[{"id":"CVE-2023-32681","fix_versions":["2.31.0"],"description":"Proxy header leak"}]}],"fixes":[]}'
PIP_AUDIT_JSON_NO_VULNS = '{"dependencies":[{"name":"requests","version":"2.31.0","vulns":[]}],"fixes":[]}'
NPM_AUDIT_JSON = '{"metadata":{"vulnerabilities":{"critical":1,"high":0}},"vulnerabilities":{"lodash":{"name":"lodash","severity":"critical","via":[{"title":"Proto Pollution","cve":"CVE-2020-8203"}]}}}'

def test_name():
    assert DependencyCheckerTool().name == "check_dependencies"

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_pip_audit_finds_cve(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout=PIP_AUDIT_JSON, stderr="")
    r = DependencyCheckerTool().execute(package_managers=["pip"])
    assert r.success is True
    assert "CVE-2023-32681" in r.content

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_pip_audit_no_vulns(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=PIP_AUDIT_JSON_NO_VULNS, stderr="")
    r = DependencyCheckerTool().execute(package_managers=["pip"])
    assert r.success is True
    assert "Sin vulnerabilidades" in r.content

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_pip_audit_not_installed_graceful(mock_run):
    mock_run.side_effect = FileNotFoundError()
    r = DependencyCheckerTool().execute(package_managers=["pip"])
    assert r.success is True
    assert "pip-audit" in r.content

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_npm_audit_finds_cve(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout=NPM_AUDIT_JSON, stderr="")
    r = DependencyCheckerTool().execute(package_managers=["npm"])
    assert r.success is True
    assert "critical" in r.content.lower()
