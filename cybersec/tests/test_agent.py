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
    result, _ = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert "Sistema seguro" in result
    assert adapter.chat.call_count == 2

def test_agent_calls_tool_then_responds():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {}}]),
        Message(role="assistant", content="2 problemas en SSH encontrados."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool})
    result, _ = agent.run(ScanScope("localhost"))
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
    result, _ = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
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
    assert "sin describir planes" in content
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
    result, _ = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
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
    result, _ = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert result == "Reporte inicial."


def test_agent_uses_audit_adapter_when_provided():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado por modelo fuerte.")
    main_adapter = _adapter(first_response)
    audit_adapter = _adapter(audit_response)
    result, _ = SecurityAgent(
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


def test_on_iteration_called_with_tool_calls_each_loop():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}]),
        Message(role="assistant", content="Listo."),
        Message(role="assistant", content="Auditado."),
    )
    tool = _tool("scan_ports", "22/tcp open")
    iterations = []
    SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}).run(
        ScanScope("localhost"), on_iteration=lambda num, calls: iterations.append((num, calls))
    )
    assert len(iterations) == 2
    assert iterations[0] == (1, [{"name": "scan_ports", "args": {"host": "localhost"}}])
    assert iterations[1] == (2, [])


def test_on_iteration_called_with_empty_list_when_no_tool_calls():
    adapter = _adapter(
        Message(role="assistant", content="Reporte directo."),
        Message(role="assistant", content="Auditado."),
    )
    iterations = []
    SecurityAgent(adapter=adapter, tool_registry={}).run(
        ScanScope("localhost"), on_iteration=lambda num, calls: iterations.append((num, calls))
    )
    assert iterations == [(1, [])]


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
        max_iterations=15,
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


def test_agent_traces_tool_result_with_metadata():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[
            {"name": "read_code_snippet", "args": {"file_path": "/tmp/auth_service.py"}}
        ]),
        Message(role="assistant", content="Listo."),
    )
    content = "# /tmp/auth_service.py\n```python\npassword = 'x'\n```"
    tool = MagicMock()
    tool.name = "read_code_snippet"
    tool.execute.return_value = ToolResult(
        content=content, tool_name="read_code_snippet", success=True,
        metadata={"file_path": "/tmp/auth_service.py", "lines": 3, "truncated": False},
    )
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"read_code_snippet": tool}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    tracer.record.assert_any_call(
        "tool_result",
        iteration=1,
        name="read_code_snippet",
        args={"file_path": "/tmp/auth_service.py"},
        success=True,
        metadata={"file_path": "/tmp/auth_service.py", "lines": 3, "truncated": False},
        content_length=len(content),
    )


def test_agent_traces_tool_result_for_unknown_tool():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "ghost_tool", "args": {}}]),
        Message(role="assistant", content="Listo."),
    )
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    expected_content = "Herramienta 'ghost_tool' no disponible."
    tracer.record.assert_any_call(
        "tool_result",
        iteration=1,
        name="ghost_tool",
        args={},
        success=False,
        metadata={},
        content_length=len(expected_content),
    )


def test_agent_traces_tool_result_when_tool_raises():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}]),
        Message(role="assistant", content="Listo."),
    )
    tool = MagicMock()
    tool.name = "scan_ports"
    tool.execute.side_effect = RuntimeError("boom")
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    expected_content = "Error en scan_ports: boom"
    tracer.record.assert_any_call(
        "tool_result",
        iteration=1,
        name="scan_ports",
        args={"host": "localhost"},
        success=False,
        metadata={},
        content_length=len(expected_content),
    )


def test_agent_traces_loop_end_reason_no_tool_calls():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    tracer.record.assert_any_call("loop_end", reason="no_tool_calls", iteration=1)


def test_agent_traces_loop_end_reason_max_iterations():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 3 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3, tracer=tracer)
    agent.run(ScanScope("localhost"))
    tracer.record.assert_any_call("loop_end", reason="max_iterations", iteration=3)


def test_agent_traces_audit_result_on_success():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado.")
    adapter = _adapter(first_response, audit_response)
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    calls = [str(c) for c in tracer.record.call_args_list]
    assert any("audit_result" in c and "success=True" in c and "Reporte auditado." in c for c in calls)


def test_agent_traces_audit_result_on_failure():
    first_response = Message(role="assistant", content="Reporte inicial.")
    adapter = _adapter(first_response, RuntimeError("auditor no disponible"))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    calls = [str(c) for c in tracer.record.call_args_list]
    assert any("audit_result" in c and "success=False" in c and "Reporte inicial." in c for c in calls)


def test_prefetch_returns_empty_when_no_code_directory():
    agent = SecurityAgent(adapter=_adapter(), tool_registry={})
    assert agent._prefetch_mandatory_files(None) == ""


def test_prefetch_returns_empty_when_list_code_files_tool_missing():
    agent = SecurityAgent(adapter=_adapter(), tool_registry={})
    assert agent._prefetch_mandatory_files("/tmp/proyecto") == ""


def test_prefetch_filters_reads_and_traces_mandatory_files():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="\n".join([
            "/tmp/proyecto/saas_chatbot/settings.py",
            "/tmp/proyecto/core/tenant_management/services/auth_service.py",
            "/tmp/proyecto/core/auth_config.py",
            "/tmp/proyecto/docker-compose.yml",
            "/tmp/proyecto/core/views.py",
        ]),
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 5},
    )

    def fake_read(file_path="", **kwargs):
        content = f"# {file_path}\n```python\n# contenido de {file_path}\n```"
        return ToolResult(
            content=content, tool_name="read_code_snippet", success=True,
            metadata={"file_path": file_path, "lines": 1, "truncated": False},
        )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.side_effect = fake_read

    tracer = MagicMock()
    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    }, tracer=tracer)
    result = agent._prefetch_mandatory_files("/tmp/proyecto")

    assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in result
    assert "settings.py" in result
    assert "auth_service.py" in result
    assert "auth_config.py" in result
    assert "docker-compose.yml" in result
    assert "core/views.py" not in result
    assert read_tool.execute.call_count == 4

    list_tool.execute.assert_called_once_with(directory="/tmp/proyecto")
    list_content_length = len(list_tool.execute.return_value.content)
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="list_code_files",
        args={"directory": "/tmp/proyecto"}, success=True,
        metadata={"directory": "/tmp/proyecto", "count": 5},
        content_length=list_content_length,
    )
    settings_content = (
        "# /tmp/proyecto/saas_chatbot/settings.py\n"
        "```python\n# contenido de /tmp/proyecto/saas_chatbot/settings.py\n```"
    )
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="read_code_snippet",
        args={"file_path": "/tmp/proyecto/saas_chatbot/settings.py"}, success=True,
        metadata={"file_path": "/tmp/proyecto/saas_chatbot/settings.py", "lines": 1, "truncated": False},
        content_length=len(settings_content),
    )


def test_prefetch_returns_empty_when_list_code_files_fails():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="Directorio no existe: /tmp/proyecto",
        tool_name="list_code_files", success=False,
        error="Directorio no existe: /tmp/proyecto",
    )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    tracer = MagicMock()
    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    }, tracer=tracer)
    assert agent._prefetch_mandatory_files("/tmp/proyecto") == ""
    read_tool.execute.assert_not_called()
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="list_code_files",
        args={"directory": "/tmp/proyecto"}, success=False,
        metadata={}, content_length=len("Directorio no existe: /tmp/proyecto"),
    )


def test_prefetch_returns_message_when_no_files_match():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/core/views.py\n/tmp/proyecto/core/models.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 2},
    )
    agent = SecurityAgent(adapter=_adapter(), tool_registry={"list_code_files": list_tool})
    result = agent._prefetch_mandatory_files("/tmp/proyecto")
    assert "No se encontraron archivos" in result


def test_prefetch_includes_error_line_when_read_code_snippet_fails():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="\n".join([
            "/tmp/proyecto/saas_chatbot/settings.py",
            "/tmp/proyecto/core/tenant_management/services/auth_service.py",
        ]),
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 2},
    )

    def fake_read(file_path="", **kwargs):
        if "auth_service" in file_path:
            return ToolResult(
                content=f"Archivo no existe: {file_path}",
                tool_name="read_code_snippet", success=False,
                error=f"Archivo no existe: {file_path}",
            )
        return ToolResult(
            content=f"# {file_path}\n```python\nDEBUG = True\n```",
            tool_name="read_code_snippet", success=True,
            metadata={"file_path": file_path, "lines": 1, "truncated": False},
        )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.side_effect = fake_read

    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    })
    result = agent._prefetch_mandatory_files("/tmp/proyecto")

    assert "settings.py" in result
    assert "DEBUG = True" in result
    assert "error al leer este archivo" in result
    assert "auth_service.py" in result


def test_prefetch_handles_missing_read_code_snippet_tool():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/saas_chatbot/settings.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 1},
    )
    agent = SecurityAgent(adapter=_adapter(), tool_registry={"list_code_files": list_tool})
    result = agent._prefetch_mandatory_files("/tmp/proyecto")
    assert "settings.py" in result
    assert "error al leer este archivo" in result


def test_run_includes_prefetched_mandatory_files_in_initial_prompt():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/core/tenant_management/services/auth_service.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 1},
    )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.return_value = ToolResult(
        content=(
            "# /tmp/proyecto/core/tenant_management/services/auth_service.py\n"
            "```python\n'password': password,\n```"
        ),
        tool_name="read_code_snippet", success=True,
        metadata={
            "file_path": "/tmp/proyecto/core/tenant_management/services/auth_service.py",
            "lines": 1, "truncated": False,
        },
    )
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    agent = SecurityAgent(adapter=adapter, tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    })
    agent.run(ScanScope("localhost", code_directory="/tmp/proyecto"))

    sent_messages = adapter.chat.call_args_list[0][0][0]
    assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in sent_messages[0].content
    assert "auth_service.py" in sent_messages[0].content
    assert "'password': password," in sent_messages[0].content
