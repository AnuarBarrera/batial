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


def _relocate_hunk_start(old_body_lines: list[str], file_lines: list[str]) -> int | None:
    """Busca old_body_lines como bloque contiguo exacto dentro de file_lines.

    Retorna la posición 1-indexed donde empieza si hay exactamente una
    coincidencia; None si es ambiguo (>1 match) o no se encuentra — en
    ambos casos el llamador debe conservar el valor que dio el LLM.
    """
    if not old_body_lines:
        return None
    n = len(old_body_lines)
    matches = [i for i in range(len(file_lines) - n + 1) if file_lines[i:i + n] == old_body_lines]
    return matches[0] + 1 if len(matches) == 1 else None


_TRAILING_CONTEXT_LINES = 3


def _fix_hunk_headers(diff_text: str, original_content: str = None) -> str:
    """Recalcula los headers ('@@ -a,b +c,d @@') de cada hunk.

    Los modelos generan con frecuencia diffs con el header mal calculado
    (aunque el contenido del hunk sea correcto), lo que hace que 'git apply'
    rechace el parche. Tres correcciones independientes:

    1. Conteo de líneas (b, d): siempre se recalcula contando las líneas
       reales del cuerpo del hunk — nunca se confía en lo que dio el LLM.
    2. Línea de inicio (a): si se provee original_content (el contenido real
       del archivo antes del parche), se busca el bloque de contexto+removidas
       del hunk dentro de ese contenido y se usa la posición real encontrada.
       Si no se provee original_content, o el bloque no se encuentra de forma
       inequívoca, se conserva el valor que dio el LLM (fallback seguro) — el
       offset acumulado (c) se calcula siempre a partir de (a) más el
       desplazamiento neto de los hunks anteriores, sea cual sea su origen.
    3. Contexto trailing: 'git apply' rechaza un hunk que termina justo en
       una línea +/- sin ninguna línea de contexto después, aun cuando el
       contenido y la posición sean correctos. Si el hunk se pudo relocalizar
       (paso 2), se completa con hasta _TRAILING_CONTEXT_LINES líneas de
       contexto real tomadas del archivo original inmediatamente después del
       hunk. Sin relocalización exitosa no se agrega nada — no hay forma
       segura de saber qué línea real sigue.
    """
    file_lines = original_content.splitlines() if original_content is not None else None
    lines = diff_text.splitlines()
    out = []
    i = 0
    cumulative_offset = 0
    while i < len(lines):
        match = _HUNK_HEADER_RE.match(lines[i])
        if not match:
            out.append(lines[i])
            i += 1
            continue
        old_start, _new_start, trailer = match.groups()
        old_start = int(old_start)
        i += 1
        old_count = 0
        new_count = 0
        old_body_lines = []
        body = []
        while i < len(lines) and not lines[i].startswith(("@@ ", "--- ", "+++ ")):
            body_line = lines[i]
            if body_line.startswith("-"):
                old_count += 1
                old_body_lines.append(body_line[1:])
            elif body_line.startswith("+"):
                new_count += 1
            elif not body_line.startswith("\\"):
                old_count += 1
                new_count += 1
                old_body_lines.append(body_line[1:] if body_line.startswith(" ") else body_line)
            body.append(body_line)
            i += 1
        relocated = _relocate_hunk_start(old_body_lines, file_lines) if file_lines is not None else None
        if relocated is not None:
            old_start = relocated
            ends_without_context = not body or not body[-1].startswith(" ")
            if ends_without_context:
                next_line_idx = relocated - 1 + old_count  # 0-indexed, primera línea no consumida
                trailing = file_lines[next_line_idx:next_line_idx + _TRAILING_CONTEXT_LINES]
                for extra_line in trailing:
                    body.append(f" {extra_line}")
                    old_count += 1
                    new_count += 1
        new_start = old_start + cumulative_offset
        cumulative_offset += new_count - old_count
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

            # Siempre relativo a code_directory en el prompt/headers del diff —
            # un file_path absoluto (a veces el LLM lo devuelve así en
            # HALLAZGOS_JSON) rompe 'git apply -p1' si se usa tal cual.
            relative_path = str(full_path.relative_to(Path(code_directory).resolve()))
            original_content = full_path.read_text(errors="replace")

            prompt = _PATCH_PROMPT.format(
                title=finding.title, severity=finding.severity,
                evidence=finding.evidence, recommendation=finding.recommendation,
                file_path=relative_path, file_content=result.content,
            )
            response = self._adapter.chat([Message(role="user", content=prompt)])
            data = _parse_json_block(response.content or "")
            diff = (data or {}).get("diff", "").strip()
            if not diff:
                finding.patch_status = "error"
                return
            finding.patch_diff = _fix_hunk_headers(diff, original_content=original_content)
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
