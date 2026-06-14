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
    assert adapter.chat.call_count == 2

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
    assert adapter.chat.call_count == 3

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


def test_initial_prompt_mentions_scan_code_security_tool():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost", code_directory="/tmp/proyecto"))
    sent_messages = adapter.chat.call_args[0][0]
    assert "scan_code_security" in sent_messages[0].content


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


def test_agent_runs_audit_pass_with_report_as_context():
    first_response = Message(
        role="assistant",
        content='Sistema seguro.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.',
    )
    audit_response = Message(
        role="assistant",
        content='Reporte auditado.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada.',
    )
    adapter = _adapter(first_response, audit_response)
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert adapter.chat.call_count == 2
    audit_messages = adapter.chat.call_args[0][0]
    assert "Sistema seguro" in audit_messages[-1].content
    assert result == audit_response.content


def test_audit_prompt_includes_report_and_checklist():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado.")
    adapter = _adapter(first_response, audit_response)
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    audit_prompt = adapter.chat.call_args[0][0][-1].content
    assert "Reporte inicial." in audit_prompt
    assert "scan_code_security" in audit_prompt
    assert "HALLAZGOS_JSON" in audit_prompt


def test_audit_call_does_not_pass_tools():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado.")
    adapter = _adapter(first_response, audit_response)
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert adapter.chat.call_args_list[1].kwargs == {}


def test_audit_falls_back_to_original_report_on_failure():
    first_response = Message(role="assistant", content="Reporte inicial.")
    adapter = _adapter(first_response, RuntimeError("auditor no disponible"))
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert result == "Reporte inicial."


def test_agent_uses_audit_adapter_when_provided():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado por modelo fuerte.")
    main_adapter = _adapter(first_response)
    audit_adapter = _adapter(audit_response)
    result = SecurityAgent(
        adapter=main_adapter, tool_registry={}, audit_adapter=audit_adapter
    ).run(ScanScope("localhost"))
    main_adapter.chat.assert_called_once()
    audit_adapter.chat.assert_called_once()
    assert result == "Reporte auditado por modelo fuerte."


def test_agent_reports_progress_for_each_iteration():
    adapter = _adapter(
        Message(role="assistant", content="Reporte inicial."),
        Message(role="assistant", content="Reporte auditado."),
    )
    progress = []
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"), on_progress=progress.append)
    assert any("Analizando" in m for m in progress)


def test_agent_reports_progress_with_tool_name_when_executing_tool():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {}}]),
        Message(role="assistant", content="Listo."),
        Message(role="assistant", content="Auditado."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool})
    progress = []
    agent.run(ScanScope("localhost"), on_progress=progress.append)
    assert any("check_configs" in m for m in progress)


def test_agent_reports_progress_before_audit_pass():
    adapter = _adapter(
        Message(role="assistant", content="Reporte inicial."),
        Message(role="assistant", content="Reporte auditado."),
    )
    progress = []
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"), on_progress=progress.append)
    assert any("audit" in m.lower() for m in progress)


def test_output_format_instructions_define_severity_criteria():
    from cybersec.application.agent import _OUTPUT_FORMAT_INSTRUCTIONS
    text = _OUTPUT_FORMAT_INSTRUCTIONS
    assert "CRITERIOS DE SEVERIDAD" in text
    assert "Critical" in text and "High" in text and "Medium" in text and "Low" in text
    assert "no inventes hallazgos" in text.lower()
    assert "PERSISTEN" in text


def test_audit_prompt_checklist_aligns_secret_severity_with_persistence():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado.")
    adapter = _adapter(first_response, audit_response)
    SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    audit_prompt = adapter.chat.call_args[0][0][-1].content
    assert "se guarda o persiste" in audit_prompt


def test_agent_traces_run_start_with_scope_info():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(
        ScanScope("localhost", code_directory="/tmp/proyecto",
                  analysis_types=["code"], log_files=["/var/log/auth.log"])
    )
    tracer.record.assert_any_call(
        "run_start",
        host="localhost",
        code_directory="/tmp/proyecto",
        analysis_types=["code"],
        log_files=["/var/log/auth.log"],
        max_iterations=10,
    )


def test_agent_traces_llm_response_with_tool_calls():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {"path": "/etc/ssh"}}]),
        Message(role="assistant", content="2 problemas en SSH encontrados."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    tracer.record.assert_any_call(
        "llm_response",
        iteration=1,
        has_tool_calls=True,
        tool_calls=[{"name": "check_configs", "args": {"path": "/etc/ssh"}}],
        content_preview="",
    )
    tracer.record.assert_any_call(
        "llm_response",
        iteration=2,
        has_tool_calls=False,
        tool_calls=[],
        content_preview="2 problemas en SSH encontrados.",
    )
