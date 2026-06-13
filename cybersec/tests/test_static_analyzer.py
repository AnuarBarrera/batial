# cybersec/tests/test_static_analyzer.py
import json
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.static_analyzer import StaticAnalyzerTool

BANDIT_JSON_WITH_ISSUES = json.dumps({"results": [
    {"filename": "app/utils.py", "issue_severity": "LOW", "test_id": "B311",
     "test_name": "blacklist", "issue_text": "Standard pseudo-random generators are not suitable "
     "for security/cryptographic purposes.", "line_number": 30},
    {"filename": "app/settings.py", "issue_severity": "HIGH", "test_id": "B105",
     "test_name": "hardcoded_password_string", "issue_text": "Possible hardcoded password: 'changeme'",
     "line_number": 12},
]})

BANDIT_JSON_NO_ISSUES = json.dumps({"results": []})


def test_name():
    assert StaticAnalyzerTool().name == "scan_code_security"


def test_requires_directory():
    r = StaticAnalyzerTool().execute()
    assert r.success is False


@patch("cybersec.infrastructure.tools.static_analyzer.subprocess.run")
def test_finds_issues_sorted_by_severity(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout=BANDIT_JSON_WITH_ISSUES, stderr="")
    r = StaticAnalyzerTool().execute(directory="/tmp/proyecto")
    assert r.success is True
    assert "B105" in r.content
    assert "hardcoded_password_string" in r.content
    assert r.content.index("B105") < r.content.index("B311")


@patch("cybersec.infrastructure.tools.static_analyzer.subprocess.run")
def test_no_issues(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=BANDIT_JSON_NO_ISSUES, stderr="")
    r = StaticAnalyzerTool().execute(directory="/tmp/proyecto")
    assert r.success is True
    assert "sin hallazgos" in r.content.lower()


@patch("cybersec.infrastructure.tools.static_analyzer.subprocess.run")
def test_bandit_not_installed_graceful(mock_run):
    mock_run.side_effect = FileNotFoundError()
    r = StaticAnalyzerTool().execute(directory="/tmp/proyecto")
    assert r.success is True
    assert "bandit" in r.content.lower()


@patch("cybersec.infrastructure.tools.static_analyzer.subprocess.run")
def test_invalid_json_returns_error(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="not json", stderr="boom")
    r = StaticAnalyzerTool().execute(directory="/tmp/proyecto")
    assert r.success is False


@patch("cybersec.infrastructure.tools.static_analyzer.subprocess.run")
def test_truncates_results_beyond_max(mock_run):
    results = [
        {"filename": f"f{i}.py", "issue_severity": "LOW", "test_id": "B311",
         "test_name": "blacklist", "issue_text": "y", "line_number": i}
        for i in range(30)
    ]
    mock_run.return_value = MagicMock(returncode=1, stdout=json.dumps({"results": results}), stderr="")
    r = StaticAnalyzerTool().execute(directory="/tmp/proyecto")
    assert "adicionales" in r.content
