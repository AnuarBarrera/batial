from datetime import datetime
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.application.report import ReportGenerator, format_report_text


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
