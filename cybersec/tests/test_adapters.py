# cybersec/tests/test_adapters.py
import pytest
from unittest.mock import patch, MagicMock
from cybersec.domain.llm_adapter import LLMAdapter, Message
from cybersec.infrastructure.adapters.gemini import GeminiAdapter

def test_gemini_implements_llm_adapter():
    assert issubclass(GeminiAdapter, LLMAdapter)

def test_gemini_supports_tools():
    assert GeminiAdapter(api_key="fake").supports_tools() is True

@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_returns_text(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "Sistema analizado."
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="analiza")])

    assert result.role == "assistant"
    assert result.content == "Sistema analizado."
    assert result.tool_calls is None

@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_returns_tool_call(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    fc = MagicMock()
    fc.name = "scan_ports"
    fc.args = {"host": "localhost"}

    mock_resp = MagicMock()
    mock_resp.text = None
    mock_resp.function_calls = [fc]
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="escanea")], tools=tools)

    assert result.tool_calls is not None
    assert result.tool_calls[0]["name"] == "scan_ports"
    assert result.tool_calls[0]["args"] == {"host": "localhost"}
