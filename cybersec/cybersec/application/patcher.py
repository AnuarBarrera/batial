import json
import logging
import re
from pathlib import Path
from cybersec.domain.entities import Finding
from cybersec.domain.llm_adapter import LLMAdapter, Message

logger = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")

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


def _fix_hunk_headers(diff_text: str) -> str:
    """Recalcula los conteos de líneas ('@@ -a,b +c,d @@') de cada hunk.

    Los modelos generan con frecuencia diffs con el conteo de líneas mal
    calculado en el header (aunque el contenido del hunk sea correcto),
    lo que hace que 'git apply' rechace el parche con "corrupt patch".
    Mantiene el número de línea inicial (a, c) tal como lo dio el LLM —
    solo recalcula b y d contando las líneas reales del cuerpo del hunk.
    """
    lines = diff_text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        match = _HUNK_HEADER_RE.match(lines[i])
        if not match:
            out.append(lines[i])
            i += 1
            continue
        old_start, new_start, trailer = match.groups()
        i += 1
        old_count = 0
        new_count = 0
        body = []
        while i < len(lines) and not lines[i].startswith(("@@ ", "--- ", "+++ ")):
            body_line = lines[i]
            if body_line.startswith("-"):
                old_count += 1
            elif body_line.startswith("+"):
                new_count += 1
            elif not body_line.startswith("\\"):
                old_count += 1
                new_count += 1
            body.append(body_line)
            i += 1
        out.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{trailer}")
        out.extend(body)
    fixed = "\n".join(out)
    if diff_text.endswith("\n") and not fixed.endswith("\n"):
        fixed += "\n"
    return fixed


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

        try:
            result = read_tool.execute(file_path=str(full_path))
            if not result.success:
                finding.patch_status = "not_applicable"
                return

            prompt = _PATCH_PROMPT.format(
                title=finding.title, severity=finding.severity,
                evidence=finding.evidence, recommendation=finding.recommendation,
                file_path=finding.file_path, file_content=result.content,
            )
            response = self._adapter.chat([Message(role="user", content=prompt)])
            data = _parse_json_block(response.content or "")
            diff = (data or {}).get("diff", "").strip()
            if not diff:
                finding.patch_status = "error"
                return
            finding.patch_diff = _fix_hunk_headers(diff)
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
        try:
            resolved = candidate.resolve()
            base = Path(code_directory).resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(base):
            return None
        return resolved if resolved.is_file() else None


def _slugify(text: str, max_len: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len].rstrip("-") or "patch"


def write_patch_files(findings: list[Finding], patch_dir: str) -> dict[str, str]:
    proposed = [f for f in findings if f.patch_status == "proposed"]
    if not proposed:
        return {}
    Path(patch_dir).mkdir(parents=True, exist_ok=True)
    paths = {}
    for finding in proposed:
        filename = f"{finding.id}-{_slugify(finding.title)}.patch"
        full_path = Path(patch_dir) / filename
        content = finding.patch_diff
        if not content.endswith("\n"):
            content += "\n"
        full_path.write_text(content, encoding="utf-8")
        paths[finding.id] = str(full_path)
    return paths
