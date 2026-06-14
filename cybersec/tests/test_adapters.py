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
def test_gemini_chat_uses_autonomous_system_instruction(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "ok"
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    GeminiAdapter(api_key="fake").chat([Message(role="user", content="analiza")])

    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert "confirmaci" in config.system_instruction.lower()


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_forces_function_call_on_first_message(mock_genai):
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
    GeminiAdapter(api_key="fake").chat([Message(role="user", content="analiza")], tools=tools)

    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.tool_config.function_calling_config.mode == "ANY"


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_does_not_force_function_call_on_later_messages(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "Diagnóstico final."
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    messages = [
        Message(role="user", content="analiza"),
        Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}]),
        Message(role="tool", content="", tool_results=[{"name": "scan_ports", "content": "22/tcp open"}]),
    ]
    GeminiAdapter(api_key="fake").chat(messages, tools=tools)

    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.tool_config is None


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_returns_tool_call(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    fc = MagicMock()
    fc.name = "scan_ports"
    fc.args = {"host": "localhost"}

    part = MagicMock(function_call=fc, thought_signature=None)
    mock_resp = MagicMock()
    mock_resp.text = None
    mock_resp.function_calls = [fc]
    mock_resp.candidates = [MagicMock(content=MagicMock(parts=[part]))]
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="escanea")], tools=tools)

    assert result.tool_calls is not None
    assert result.tool_calls[0]["name"] == "scan_ports"
    assert result.tool_calls[0]["args"] == {"host": "localhost"}


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_includes_thought_signature_in_tool_call(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    fc = MagicMock()
    fc.name = "scan_ports"
    fc.args = {"host": "localhost"}

    part = MagicMock(function_call=fc, thought_signature=b"sig-123")
    mock_resp = MagicMock()
    mock_resp.text = None
    mock_resp.function_calls = [fc]
    mock_resp.candidates = [MagicMock(content=MagicMock(parts=[part]))]
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="escanea")], tools=tools)

    assert result.tool_calls[0]["thought_signature"] == b"sig-123"


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_replays_thought_signature_for_tool_call_message(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "Diagnóstico final."
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    messages = [
        Message(role="user", content="analiza"),
        Message(role="assistant", content="", tool_calls=[
            {"name": "scan_ports", "args": {"host": "localhost"}, "thought_signature": b"sig-123"}
        ]),
        Message(role="tool", content="", tool_results=[{"name": "scan_ports", "content": "22/tcp open"}]),
    ]
    GeminiAdapter(api_key="fake").chat(messages, tools=tools)

    contents = mock_client.models.generate_content.call_args.kwargs["contents"]
    model_content = contents[1]
    assert model_content.parts[0].thought_signature == b"sig-123"


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_passes_temperature_when_configured(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "ok"
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    GeminiAdapter(api_key="fake", temperature=0.0).chat([Message(role="user", content="analiza")])

    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.temperature == 0.0


@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_omits_temperature_by_default(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "ok"
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    GeminiAdapter(api_key="fake").chat([Message(role="user", content="analiza")])

    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.temperature is None


from cybersec.infrastructure.adapters.openai_compat import OpenAICompatAdapter

def test_openai_compat_implements_llm_adapter():
    assert issubclass(OpenAICompatAdapter, LLMAdapter)

@patch("cybersec.infrastructure.adapters.openai_compat.requests.post")
def test_openai_compat_returns_text(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"choices": [{"message": {"role": "assistant", "content": "Hola", "tool_calls": None}}]},
        raise_for_status=lambda: None,
    )
    adapter = OpenAICompatAdapter(base_url="http://localhost:8000", model="Qwen/14B")
    result = adapter.chat([Message(role="user", content="Hola")])
    assert result.content == "Hola"
    assert result.tool_calls is None

@patch("cybersec.infrastructure.adapters.openai_compat.requests.post")
def test_openai_compat_returns_tool_call(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [{"function": {"name": "scan_ports", "arguments": '{"host": "localhost"}'}}]
        }}]},
        raise_for_status=lambda: None,
    )
    adapter = OpenAICompatAdapter(base_url="http://localhost:8000", model="Qwen/14B")
    result = adapter.chat([Message(role="user", content="escanea")], tools=[])
    assert result.tool_calls[0]["name"] == "scan_ports"
    assert result.tool_calls[0]["args"] == {"host": "localhost"}
