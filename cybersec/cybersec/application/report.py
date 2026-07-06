import json
import logging
import re
from datetime import datetime
from cybersec.domain.entities import Finding, ScanScope, SecurityReport

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

_NEXT_STEPS_HEADER_RE = re.compile(r"^[#>\s*]*pr[oó]ximos\s+pasos[:\s*]*$", re.IGNORECASE | re.MULTILINE)
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+(.+)$")
_FINDINGS_HEADER_RE = re.compile(r"^[#>\s*]*hallazgos_json[:\s*]*$", re.IGNORECASE | re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

_SEVERITY_ALIASES = {
    "critical": "Critical", "crítica": "Critical", "critica": "Critical",
    "high": "High", "alta": "High",
    "medium": "Medium", "media": "Medium",
    "low": "Low", "baja": "Low", "informativo": "Low", "informational": "Low", "info": "Low",
}


def _extract_next_steps(text: str) -> tuple[str, list[str]]:
    """Separa una sección "PRÓXIMOS PASOS:" del texto del agente.

    Devuelve el texto restante (sin esa sección) y la lista de pasos
    extraídos de sus ítems numerados o con viñetas.
    """
    match = _NEXT_STEPS_HEADER_RE.search(text)
    if not match:
        logger.warning("Sección 'PRÓXIMOS PASOS:' no encontrada en la respuesta del LLM")
        logger.debug("Texto recibido:\n%s", text)
        return text, []
    main_text = text[:match.start()].rstrip()
    section = text[match.end():]
    steps = [m.group(1).strip() for line in section.splitlines() if (m := _LIST_ITEM_RE.match(line))]
    return main_text, steps


def _normalize_severity(severity: str) -> str:
    return _SEVERITY_ALIASES.get(severity.strip().lower(), severity if severity in SEVERITY_ORDER else "Low")


def _extract_findings(text: str) -> tuple[str, list[Finding]]:
    """Separa una sección "HALLAZGOS_JSON:" con un bloque ```json del texto del agente.

    Devuelve el texto restante (sin esa sección) y los Finding parseados.
    """
    match = _FINDINGS_HEADER_RE.search(text)
    if not match:
        logger.warning("Sección 'HALLAZGOS_JSON:' no encontrada en la respuesta del LLM")
        logger.debug("Texto recibido:\n%s", text)
        return text, []
    json_match = _JSON_BLOCK_RE.search(text[match.end():])
    if not json_match:
        logger.warning("Sección 'HALLAZGOS_JSON:' presente pero sin bloque ```json```")
        logger.debug("Contenido de la sección:\n%s", text[match.end():])
        return text, []
    try:
        data = json.loads(json_match.group(1))
    except json.JSONDecodeError as e:
        logger.error("JSON inválido en HALLAZGOS_JSON: %s", e)
        logger.debug("Texto problemático:\n%s", json_match.group(1))
        return text, []
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        return text, []

    main_text = text[:match.start()].rstrip()
    findings = [
        Finding(
            id=f"F{i:03d}",
            title=item.get("title", ""),
            severity=_normalize_severity(str(item.get("severity", "Low"))),
            evidence=item.get("evidence", ""),
            recommendation=item.get("recommendation", ""),
            status=item.get("status", ""),
            accepted_reason=item.get("accepted_reason", ""),
            file_path=item.get("file_path", ""),
        )
        for i, item in enumerate(data, 1)
        if isinstance(item, dict)
    ]
    return main_text, findings


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

    def _sort_key(f: Finding) -> int:
        return SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99

    active = sorted([f for f in report.findings if f.status != "accepted"], key=_sort_key)
    accepted = sorted([f for f in report.findings if f.status == "accepted"], key=_sort_key)

    if active:
        lines += ["HALLAZGOS", "-" * 40]
        for f in active:
            lines += [
                f"  [{f.id}] {f.title}",
                f"  Severidad: {f.severity}",
                f"  Evidencia: {f.evidence}",
                f"  Recomendación: {f.recommendation}",
                "",
            ]

    if report.analysis_text:
        lines += ["ANÁLISIS DEL AGENTE", "-" * 40, report.analysis_text, ""]

    urgent = [f for f in active if f.severity in ("Critical", "High")]
    lines += ["PRÓXIMOS PASOS", "-" * 40]
    if report.next_steps:
        for i, step in enumerate(report.next_steps, 1):
            lines.append(f"  {i}. {step}")
    elif urgent:
        for i, f in enumerate(urgent, 1):
            lines.append(f"  {i}. [{f.severity}] {f.recommendation}")
    else:
        lines.append("  Sin hallazgos críticos o altos que requieran acción inmediata.")

    if accepted:
        lines += ["", "HALLAZGOS ACEPTADOS", "-" * 40]
        lines.append("  (Revisados y aprobados formalmente — excluidos de próximos pasos)")
        lines.append("")
        for f in accepted:
            reason = f.accepted_reason or "sin razón registrada"
            lines += [
                f"  [{f.id}] {f.title}  [{f.severity}]",
                f"  Razón: {reason}",
                "",
            ]

    lines += ["", "=" * 60]
    return "\n".join(lines)


class ReportGenerator:
    def from_agent_output(self, agent_text: str, scope: ScanScope) -> SecurityReport:
        main_text, next_steps = _extract_next_steps(agent_text)
        main_text, findings = _extract_findings(main_text)
        return SecurityReport(
            findings=findings,
            scope=scope,
            generated_at=datetime.now(),
            analysis_text=main_text,
            next_steps=next_steps,
        )
