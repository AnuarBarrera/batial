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
        api_key="fake-key", model="gemini-3.5-flash", temperature=0.0,
        top_p=None, top_k=None,
    )


@patch("cybersec.cli.config")
@patch("cybersec.infrastructure.adapters.gemini.GeminiAdapter")
def test_build_adapter_passes_none_temperature_by_default(mock_gemini_adapter, mock_config):
    mock_config.GEMINI_API_KEY = "fake-key"
    mock_config.GEMINI_MODEL = "gemini-3.1-flash-lite"

    from cybersec.cli import _build_adapter
    _build_adapter("gemini")

    mock_gemini_adapter.assert_called_once_with(
        api_key="fake-key", model="gemini-3.1-flash-lite", temperature=None,
        top_p=None, top_k=None,
    )


@patch("cybersec.cli.config")
@patch("cybersec.infrastructure.adapters.gemini.GeminiAdapter")
def test_build_adapter_passes_top_p_top_k_to_gemini(mock_gemini_adapter, mock_config):
    mock_config.GEMINI_API_KEY = "fake-key"
    mock_config.GEMINI_MODEL = "gemini-3.1-flash-lite"

    from cybersec.cli import _build_adapter
    _build_adapter("gemini", temperature=0.0, top_p=0.1, top_k=1)

    mock_gemini_adapter.assert_called_once_with(
        api_key="fake-key", model="gemini-3.1-flash-lite", temperature=0.0,
        top_p=0.1, top_k=1,
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
def test_scan_defaults_exploration_to_temperature_zero_and_top_k_one(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check
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
    exploration_call = mock_build_adapter.call_args_list[0]
    assert exploration_call.kwargs["temperature"] == 0.0
    assert exploration_call.kwargs["top_k"] == 1


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


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
@patch("cybersec.cli.PatchProposer")
@patch("cybersec.cli.write_patch_files", return_value={})
def test_scan_does_not_call_patch_proposer_by_default(
    mock_write_patches, mock_patch_proposer_cls, mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check
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
    mock_patch_proposer_cls.assert_not_called()
    mock_write_patches.assert_not_called()


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
@patch("cybersec.cli.PatchProposer")
@patch("cybersec.cli.write_patch_files", return_value={"F001": "/tmp/patches/F001-x.patch"})
def test_scan_calls_patch_proposer_when_flag_given(
    mock_write_patches, mock_patch_proposer_cls, mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    from cybersec.domain.llm_adapter import TokenUsage
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.",
        TokenUsage(),
    )
    mock_agent_cls.return_value = mock_agent
    mock_proposer = MagicMock()
    mock_patch_proposer_cls.return_value = mock_proposer

    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--code-dir", str(tmp_path), "--propose-patches"])

    assert result.exit_code == 0, result.output
    mock_patch_proposer_cls.assert_called_once()
    mock_proposer.propose_all.assert_called_once()
    args, kwargs = mock_write_patches.call_args
    assert args[1] == "./patches"


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
def test_scan_propose_patches_without_code_dir_is_usage_error(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check
):
    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--propose-patches"])

    assert result.exit_code != 0
    assert "--code-dir" in result.output


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
@patch("cybersec.cli.PatchProposer")
@patch("cybersec.cli.write_patch_files", return_value={})
def test_scan_uses_custom_patch_dir(
    mock_write_patches, mock_patch_proposer_cls, mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    from cybersec.domain.llm_adapter import TokenUsage
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.",
        TokenUsage(),
    )
    mock_agent_cls.return_value = mock_agent
    mock_patch_proposer_cls.return_value = MagicMock()

    from cybersec.cli import cli
    runner = CliRunner()
    custom_dir = str(tmp_path / "mis-parches")
    result = runner.invoke(cli, ["scan", "--code-dir", str(tmp_path), "--propose-patches", "--patch-dir", custom_dir])

    assert result.exit_code == 0, result.output
    args, kwargs = mock_write_patches.call_args
    assert args[1] == custom_dir
