from datetime import datetime
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.application.report import ReportGenerator, format_report_text, _extract_next_steps, _extract_findings


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


def test_extract_findings_from_json_block():
    text = (
        "Análisis narrativo aquí.\n\n"
        "HALLAZGOS_JSON:\n"
        "```json\n"
        '[{"title": "MySQL expuesto", "severity": "Critical", "evidence": "3306/tcp open", "recommendation": "Restringir con firewall"}]\n'
        "```\n\n"
        "PRÓXIMOS PASOS:\n"
        "1. Cerrar el puerto 3306\n"
    )
    main, next_steps = _extract_next_steps(text)
    main, findings = _extract_findings(main)
    assert "HALLAZGOS_JSON" not in main
    assert "Análisis narrativo" in main
    assert len(findings) == 1
    assert findings[0].id == "F001"
    assert findings[0].title == "MySQL expuesto"
    assert findings[0].severity == "Critical"
    assert findings[0].evidence == "3306/tcp open"
    assert findings[0].recommendation == "Restringir con firewall"


def test_extract_findings_returns_empty_when_absent():
    text = "Solo un análisis, sin sección de hallazgos."
    main, findings = _extract_findings(text)
    assert main == text
    assert findings == []


def test_extract_findings_normalizes_spanish_severity():
    text = (
        "HALLAZGOS_JSON:\n"
        "```json\n"
        '[{"title": "Actividad sudo", "severity": "Baja", "evidence": "...", "recommendation": "Revisar logs"}]\n'
        "```\n"
    )
    _, findings = _extract_findings(text)
    assert findings[0].severity == "Low"


def test_extract_findings_handles_invalid_json():
    text = "HALLAZGOS_JSON:\n```json\nesto no es json\n```\n"
    main, findings = _extract_findings(text)
    assert findings == []
    assert main == text


def test_report_generator_populates_findings_from_json():
    scope = ScanScope(target_host="localhost")
    text = (
        "Diagnóstico narrativo.\n\n"
        "HALLAZGOS_JSON:\n"
        "```json\n"
        '[{"title": "pip vulnerable", "severity": "High", "evidence": "pip 24.0", "recommendation": "Actualizar pip"}]\n'
        "```\n\n"
        "PRÓXIMOS PASOS:\n"
        "1. Actualizar pip\n"
    )
    r = ReportGenerator().from_agent_output(text, scope)
    assert len(r.findings) == 1
    assert r.findings[0].title == "pip vulnerable"
    assert r.findings[0].severity == "High"
    assert r.summary() == {"total": 1, "Critical": 0, "High": 1, "Medium": 0, "Low": 0}
    assert "HALLAZGOS_JSON" not in r.analysis_text
    assert "Diagnóstico narrativo" in r.analysis_text


def test_report_shows_both_analysis_and_structured_findings():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(
        findings=[Finding("F001", "pip vulnerable", "High", "pip 24.0", "Actualizar pip")],
        scope=scope, generated_at=datetime(2026, 6, 9),
        analysis_text="Diagnóstico narrativo del agente.",
    )
    text = format_report_text(report)
    assert "Total hallazgos: 1 (Critical: 0, High: 1, Medium: 0, Low: 0)" in text
    assert "ANÁLISIS DEL AGENTE" in text
    assert "Diagnóstico narrativo del agente." in text
    assert "HALLAZGOS" in text
    assert "F001" in text


def test_report_proximos_pasos_prefers_next_steps_over_findings():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(
        findings=[Finding("F001", "pip vulnerable", "High", "pip 24.0", "Actualizar pip a la última versión")],
        scope=scope, generated_at=datetime(2026, 6, 9),
        analysis_text="Diagnóstico.",
        next_steps=["Actualizar pip", "Cerrar puerto 8080"],
    )
    text = format_report_text(report)
    assert "1. Actualizar pip" in text
    assert "2. Cerrar puerto 8080" in text
    assert "[High] Actualizar pip a la última versión" not in text
