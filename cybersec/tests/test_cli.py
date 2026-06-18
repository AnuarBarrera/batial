# cybersec/tests/test_cli.py
from unittest.mock import patch, MagicMock


@patch("cybersec.cli.config")
@patch("cybersec.infrastructure.adapters.gemini.GeminiAdapter")
def test_build_adapter_passes_temperature_to_gemini(mock_gemini_adapter, mock_config):
    mock_config.GEMINI_API_KEY = "fake-key"
    mock_config.GEMINI_MODEL = "gemini-3.1-flash-lite"

    from cybersec.cli import _build_adapter
    _build_adapter("gemini", model="gemini-3.5-flash", temperature=0.0)

    mock_gemini_adapter.assert_called_once_with(
        api_key="fake-key", model="gemini-3.5-flash", temperature=0.0
    )


@patch("cybersec.cli.config")
@patch("cybersec.infrastructure.adapters.gemini.GeminiAdapter")
def test_build_adapter_passes_none_temperature_by_default(mock_gemini_adapter, mock_config):
    mock_config.GEMINI_API_KEY = "fake-key"
    mock_config.GEMINI_MODEL = "gemini-3.1-flash-lite"

    from cybersec.cli import _build_adapter
    _build_adapter("gemini")

    mock_gemini_adapter.assert_called_once_with(
        api_key="fake-key", model="gemini-3.1-flash-lite", temperature=None
    )


from click.testing import CliRunner

@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
def test_scan_creates_trace_file_when_trace_dir_given(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    from cybersec.domain.llm_adapter import TokenUsage
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.",
        TokenUsage(),
    )
    mock_agent_cls.return_value = mock_agent

    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--trace-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    trace_files = list(tmp_path.glob("run-*.jsonl"))
    assert len(trace_files) == 1
    _, kwargs = mock_agent_cls.call_args
    assert kwargs["tracer"] is not None

@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
def test_scan_does_not_create_trace_file_by_default(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    from cybersec.domain.llm_adapter import TokenUsage
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.",
        TokenUsage(),
    )
    mock_agent_cls.return_value = mock_agent

    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 0, result.output
    _, kwargs = mock_agent_cls.call_args
    assert kwargs["tracer"] is None
