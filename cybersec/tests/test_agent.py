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
