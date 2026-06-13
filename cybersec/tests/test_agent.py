# cybersec/tests/test_agent.py
from unittest.mock import MagicMock
from cybersec.domain.llm_adapter import Message
from cybersec.domain.entities import ScanScope
from cybersec.domain.tools import ToolResult
from cybersec.application.agent import SecurityAgent

def _adapter(*responses):
    a = MagicMock()
    a.supports_tools.return_value = True
    a.chat.side_effect = list(responses)
    return a

def _tool(name, content="ok"):
    t = MagicMock()
    t.name = name
    t.execute.return_value = ToolResult(content=content, tool_name=name, success=True)
    return t

def test_agent_returns_text_on_first_response():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert "Sistema seguro" in result
    assert adapter.chat.call_count == 1

def test_agent_calls_tool_then_responds():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {}}]),
        Message(role="assistant", content="2 problemas en SSH encontrados."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool})
    result = agent.run(ScanScope("localhost"))
    assert "2 problemas" in result
    tool.execute.assert_called_once()
    assert adapter.chat.call_count == 2

def test_agent_stops_at_max_iterations():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 10 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3)
    result = agent.run(ScanScope("localhost"))
    assert adapter.chat.call_count <= 5

def test_agent_handles_unknown_tool_gracefully():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "ghost_tool", "args": {}}]),
        Message(role="assistant", content="Análisis completado."),
    )
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert "completado" in result


def test_initial_prompt_requests_next_steps_section():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    sent_messages = adapter.chat.call_args[0][0]
    assert "PRÓXIMOS PASOS:" in sent_messages[0].content


def test_final_report_prompt_requests_next_steps_section():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 10 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3)
    agent.run(ScanScope("localhost"))
    last_messages = adapter.chat.call_args[0][0]
    assert "PRÓXIMOS PASOS:" in last_messages[-1].content


def test_initial_prompt_requests_findings_json_section():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    sent_messages = adapter.chat.call_args[0][0]
    assert "HALLAZGOS_JSON:" in sent_messages[0].content


def test_initial_prompt_instructs_immediate_tool_use():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    sent_messages = adapter.chat.call_args[0][0]
    content = sent_messages[0].content.lower()
    assert "no describas un plan" in content
    assert "actúa de inmediato" in content


def test_initial_prompt_mentions_list_code_files_tool():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost", code_directory="/tmp/proyecto"))
    sent_messages = adapter.chat.call_args[0][0]
    assert "list_code_files" in sent_messages[0].content


def test_initial_prompt_lists_mandatory_security_file_patterns():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost", code_directory="/tmp/proyecto"))
    sent_messages = adapter.chat.call_args[0][0]
    content = sent_messages[0].content.lower()
    for pattern in ["settings", "auth", "docker-compose", "middleware", ".env"]:
        assert pattern in content, f"falta el patrón obligatorio '{pattern}' en el prompt"


def test_final_report_prompt_requests_findings_json_section():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 10 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3)
    agent.run(ScanScope("localhost"))
    last_messages = adapter.chat.call_args[0][0]
    assert "HALLAZGOS_JSON:" in last_messages[-1].content
