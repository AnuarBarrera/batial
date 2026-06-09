from datetime import datetime
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.application.report import ReportGenerator, format_report_text, _extract_next_steps


def test_report_has_required_sections():
    scope = ScanScope(target_host="192.168.1.1")
    report = SecurityReport(
        findings=[Finding("F001", "MySQL expuesto", "Critical", "3306/tcp open", "Restringir con firewall")],
        scope=scope, generated_at=datetime(2026, 6, 9),
        analysis_text="Análisis del agente aquí."
    )
    text = format_report_text(report)
    assert "REPORTE DE SEGURIDAD" in text
    assert "2026" in text
    assert "192.168.1.1" in text
    assert "RESUMEN EJECUTIVO" in text
    assert "Critical: 1" in text
    assert "HALLAZGOS" in text
    assert "F001" in text
    assert "PRÓXIMOS PASOS" in text


def test_report_orders_by_severity():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(findings=[
        Finding("F001", "Low issue", "Low", "e", "r"),
        Finding("F002", "Critical issue", "Critical", "e", "r"),
    ], scope=scope)
    text = format_report_text(report)
    assert text.index("Critical") < text.index("Low")


def test_report_generator_wraps_agent_output():
    scope = ScanScope(target_host="localhost")
    r = ReportGenerator().from_agent_output("Diagnóstico del agente", scope)
    assert r.scope == scope
    assert r.analysis_text == "Diagnóstico del agente"
    assert r.generated_at is not None


def test_extract_next_steps_from_numbered_list():
    text = (
        "RESUMEN: 2 problemas detectados.\n\n"
        "PRÓXIMOS PASOS:\n"
        "1. Deshabilitar PermitRootLogin\n"
        "2. Restringir Redis con firewall\n"
    )
    main, steps = _extract_next_steps(text)
    assert "RESUMEN" in main
    assert "PRÓXIMOS PASOS" not in main
    assert steps == ["Deshabilitar PermitRootLogin", "Restringir Redis con firewall"]


def test_extract_next_steps_returns_empty_when_absent():
    text = "Solo un resumen, sin secciones especiales."
    main, steps = _extract_next_steps(text)
    assert main == text
    assert steps == []


def test_report_generator_extracts_next_steps():
    scope = ScanScope(target_host="localhost")
    text = "Diagnóstico.\n\nPRÓXIMOS PASOS:\n1. Actualizar paquetes\n2. Cerrar puerto 6379"
    r = ReportGenerator().from_agent_output(text, scope)
    assert r.next_steps == ["Actualizar paquetes", "Cerrar puerto 6379"]
    assert "PRÓXIMOS PASOS" not in r.analysis_text


def test_report_shows_next_steps_from_agent_output():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(
        findings=[], scope=scope, generated_at=datetime(2026, 6, 9),
        analysis_text="Diagnóstico del agente.",
        next_steps=["Actualizar paquetes", "Cerrar puerto 6379"],
    )
    text = format_report_text(report)
    assert "1. Actualizar paquetes" in text
    assert "2. Cerrar puerto 6379" in text
    assert "Sin hallazgos críticos" not in text


def test_report_default_message_when_no_next_steps_and_no_urgent_findings():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(findings=[], scope=scope, generated_at=datetime(2026, 6, 9), analysis_text="Todo bien.")
    text = format_report_text(report)
    assert "Sin hallazgos críticos o altos" in text
