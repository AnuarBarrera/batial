import re
from datetime import datetime
from cybersec.domain.entities import ScanScope, SecurityReport

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

_NEXT_STEPS_HEADER_RE = re.compile(r"^[#>\s*]*pr[oó]ximos\s+pasos[:\s]*$", re.IGNORECASE | re.MULTILINE)
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+(.+)$")


def _extract_next_steps(text: str) -> tuple[str, list[str]]:
    """Separa una sección "PRÓXIMOS PASOS:" del texto del agente.

    Devuelve el texto restante (sin esa sección) y la lista de pasos
    extraídos de sus ítems numerados o con viñetas.
    """
    match = _NEXT_STEPS_HEADER_RE.search(text)
    if not match:
        return text, []
    main_text = text[:match.start()].rstrip()
    section = text[match.end():]
    steps = [m.group(1).strip() for line in section.splitlines() if (m := _LIST_ITEM_RE.match(line))]
    return main_text, steps


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
    elif report.next_steps:
        for i, step in enumerate(report.next_steps, 1):
            lines.append(f"  {i}. {step}")
    else:
        lines.append("  Sin hallazgos críticos o altos que requieran acción inmediata.")

    lines += ["", "=" * 60]
    return "\n".join(lines)


class ReportGenerator:
    def from_agent_output(self, agent_text: str, scope: ScanScope) -> SecurityReport:
        main_text, next_steps = _extract_next_steps(agent_text)
        return SecurityReport(
            findings=[],
            scope=scope,
            generated_at=datetime.now(),
            analysis_text=main_text,
            next_steps=next_steps,
        )
