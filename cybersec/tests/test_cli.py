# cybersec/tests/test_cli.py
from unittest.mock import patch


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
