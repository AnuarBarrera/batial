# cybersec/tests/test_registry.py
from cybersec.infrastructure.tools.registry import get_registry, get_tool, get_tool_schemas
from cybersec.domain.tools import BaseTool

EXPECTED_TOOLS = {"analyze_logs", "scan_ports", "check_dependencies", "read_code_snippet", "check_configs"}

def test_registry_has_all_tools():
    assert set(get_registry().keys()) == EXPECTED_TOOLS

def test_get_tool_returns_base_tool():
    assert isinstance(get_tool("analyze_logs"), BaseTool)

def test_get_unknown_tool_returns_none():
    assert get_tool("not_a_tool") is None

def test_tool_schemas_structure():
    schemas = get_tool_schemas()
    assert {s["name"] for s in schemas} == EXPECTED_TOOLS
    for s in schemas:
        assert "name" in s
        assert "description" in s
        assert "parameters" in s
