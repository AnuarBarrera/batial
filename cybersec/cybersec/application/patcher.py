import json
import logging
import re
from pathlib import Path
from cybersec.domain.entities import Finding
from cybersec.domain.llm_adapter import LLMAdapter, Message

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

_PATCH_PROMPT = """Eres un ingeniero de seguridad senior. Genera un parche para
corregir la siguiente vulnerabilidad, aplicable con 'git apply'.

Hallazgo:
  Título: {title}
  Severidad: {severity}
  Evidencia: {evidence}
  Recomendación: {recommendation}

Archivo afectado ({file_path}):
```
{file_content}
```

Responde ÚNICAMENTE con un bloque ```json con un objeto con las claves:
- "diff": el parche completo en formato unified diff (git diff estándar,
  con headers "--- a/{file_path}" y "+++ b/{file_path}"), listo para
  'git apply'. Usa SIEMPRE la ruta {file_path} en los headers del diff.
- "explanation": explicación breve del cambio, en lenguaje no técnico,
  para alguien sin conocimiento profundo de programación.

Si no es posible generar un parche seguro y mínimo para este hallazgo con
la información disponible, responde con "diff": "" y explica por qué en
"explanation"."""


def _parse_json_block(text: str) -> dict | None:
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


class PatchProposer:
    def __init__(self, adapter: LLMAdapter, tool_registry: dict):
        self._adapter = adapter
        self._registry = tool_registry

    def propose_all(self, findings: list[Finding], code_directory: str) -> None:
        for finding in findings:
            if finding.status == "accepted" or not finding.file_path:
                continue
            self._propose_one(finding, code_directory)

    def _propose_one(self, finding: Finding, code_directory: str) -> None:
        full_path = self._resolve_path(finding.file_path, code_directory)
        if full_path is None:
            finding.patch_status = "not_applicable"
            return

        read_tool = self._registry.get("read_code_snippet")
        if read_tool is None:
            finding.patch_status = "not_applicable"
            return
        result = read_tool.execute(file_path=str(full_path))
        if not result.success:
            finding.patch_status = "not_applicable"
            return

        prompt = _PATCH_PROMPT.format(
            title=finding.title, severity=finding.severity,
            evidence=finding.evidence, recommendation=finding.recommendation,
            file_path=finding.file_path, file_content=result.content,
        )
        try:
            response = self._adapter.chat([Message(role="user", content=prompt)])
            data = _parse_json_block(response.content or "")
            diff = (data or {}).get("diff", "").strip()
            if not diff:
                finding.patch_status = "error"
                return
            finding.patch_diff = diff
            finding.patch_explanation = (data or {}).get("explanation", "")
            finding.patch_status = "proposed"
        except Exception:
            logger.exception("Error generando parche para %s", finding.id)
            finding.patch_status = "error"

    @staticmethod
    def _resolve_path(file_path: str, code_directory: str) -> Path | None:
        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = Path(code_directory) / file_path
        return candidate if candidate.is_file() else None
