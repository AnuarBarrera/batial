from datetime import datetime
from cybersec.domain.entities import ScanScope, SecurityReport

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def format_report_text(report: SecurityReport) -> str:
    now = report.generated_at or datetime.now()
    host = report.scope.target_host if report.scope else "desconocido"
    s = report.summary()

    lines = [
        "=" * 60,
        f"REPORTE DE SEGURIDAD — {now.strftime('%Y-%m-%d %H:%M')} — {host}",
        "=" * 60,
        "",
        "RESUMEN EJECUTIVO",
        f"  Total hallazgos: {s['total']} (Critical: {s['Critical']}, High: {s['High']}, Medium: {s['Medium']}, Low: {s['Low']})",
        "",
    ]

    sorted_findings = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
    )

    if sorted_findings:
        lines += ["HALLAZGOS", "-" * 40]
        for f in sorted_findings:
            lines += [
                f"  [{f.id}] {f.title}",
                f"  Severidad: {f.severity}",
                f"  Evidencia: {f.evidence}",
                f"  Recomendación: {f.recommendation}",
                "",
            ]
    elif report.analysis_text:
        lines += ["ANÁLISIS DEL AGENTE", "-" * 40, report.analysis_text, ""]

    urgent = [f for f in sorted_findings if f.severity in ("Critical", "High")]
    lines += ["PRÓXIMOS PASOS", "-" * 40]
    if urgent:
        for i, f in enumerate(urgent, 1):
            lines.append(f"  {i}. [{f.severity}] {f.recommendation}")
    else:
        lines.append("  Sin hallazgos críticos o altos que requieran acción inmediata.")

    lines += ["", "=" * 60]
    return "\n".join(lines)


class ReportGenerator:
    def from_agent_output(self, agent_text: str, scope: ScanScope) -> SecurityReport:
        return SecurityReport(
            findings=[],
            scope=scope,
            generated_at=datetime.now(),
            analysis_text=agent_text,
        )
