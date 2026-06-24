import fnmatch
import logging
import os
from typing import Callable, Optional
from cybersec.domain.llm_adapter import LLMAdapter, Message, TokenUsage
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_tool_schemas

logger = logging.getLogger(__name__)

MANDATORY_FILE_PATTERNS = [
    "*settings*", "*config*",
    "*auth*", "*login*", "*password*", "*credential*",
    "docker-compose*", "Dockerfile*", "*.env*",
    "*middleware*",
]

_SEVERITY_CRITERIA = """CRITERIOS DE SEVERIDAD — usa exactamente estas definiciones al clasificar:
  Critical : Explotable remotamente sin autenticación con evidencia de explotación
             activa en logs, O credenciales/contraseñas/secretos en texto plano que
             se ALMACENAN o PERSISTEN (en base de datos, archivos, tokens, sesiones)
             y permitirían comprometer cuentas directamente.
  High     : CVE con CVSS >= 7.0, o secretos/claves hardcodeadas en código o
             configuración que aún no se persisten en runtime, o configuración que
             expone datos sensibles directamente.
  Medium   : CVE con CVSS 4.0-6.9, o configuración mejorable sin impacto directo
             inmediato.
  Low      : Mala práctica sin impacto directo, hallazgo informativo.

REGLAS:
- Solo reporta hallazgos respaldados por los resultados de herramientas o el código
  mostrados en esta conversación. No inventes hallazgos ni rellenes con suposiciones.
- Un análisis con HALLAZGOS_JSON: [] (cero hallazgos) es un resultado válido y
  correcto si no se detectó nada relevante.
- Ante ambigüedad sobre la severidad de un hallazgo, clasifica de forma
  conservadora (sube de nivel, no bajes)."""

_OUTPUT_FORMAT_INSTRUCTIONS = _SEVERITY_CRITERIA + "\n\nTu respuesta final debe incluir, en este orden:\n" + (
    "1. Un análisis narrativo con resumen ejecutivo, hallazgos y recomendaciones.\n"
    '2. Una sección llamada exactamente "HALLAZGOS_JSON:" seguida de un bloque de código '
    '```json con un array de objetos, cada uno con las claves "title" (string), '
    '"severity" (uno de "Critical", "High", "Medium", "Low" en inglés, según los '
    'CRITERIOS DE SEVERIDAD anteriores), "evidence" (string breve) y "recommendation" '
    '(string). Si el hallazgo coincide con uno de los HALLAZGOS ACEPTADOS FORMALMENTE, '
    'agrégale además "status": "accepted" y "accepted_reason": "<razón indicada>". '
    'Incluye solo problemas de seguridad reales, no estados positivos. '
    'Reporta TODOS los hallazgos que hayas identificado — no existe un número máximo. '
    'Si encontraste 10 hallazgos, incluye los 10 ordenados de mayor a menor severidad. '
    'No descartes un hallazgo porque ya tienes "suficientes".\n'
    '3. Una sección llamada exactamente "PRÓXIMOS PASOS:" seguida de una lista numerada '
    "(1. 2. 3. ...) con las acciones más urgentes a tomar, ordenadas por prioridad."
)

_PROMPT = """Eres un analista de ciberseguridad certificado (OSCP, CEH) ejecutando
una auditoría de seguridad autorizada, defensiva y de caja blanca (white-box)
sobre el sistema indicado. Tu rol es identificar y documentar vulnerabilidades
para que el equipo pueda remediarlas — nunca para explotarlas. Operas de forma
autónoma: no hay humanos disponibles para preguntas ni confirmaciones.
Actúa de inmediato usando las herramientas disponibles, sin describir planes
ni pedir permiso.

<meta>
Realizar un análisis de seguridad EXHAUSTIVO del sistema: identificar TODAS las
vulnerabilidades presentes — en infraestructura, dependencias y código fuente —
sin omitir ninguna por considerarla menor o evidente. No generes el reporte final
hasta haber agotado todas las rutas de investigación relevantes disponibles.
La cobertura completa es más valiosa que la velocidad.
</meta>

Scope del análisis:

Host: {host}
Análisis solicitado: {types}
Archivos de log: {logs}
Directorio de código: {code}
Ventana de tiempo: últimas {hours} horas

Usa todas las herramientas disponibles para cubrir las siguientes áreas:

- Red y sistema: escanea el host con las herramientas de red disponibles.
  Revisa los logs en busca de patrones de ataque, accesos sospechosos o errores
  de autenticación.
- Dependencias: ejecuta check_dependencies y examina cada CVE reportado para
  determinar si es explotable en este contexto.
- Código (si se especifica directorio distinto de "ninguno"):
  1. Ejecuta SIEMPRE scan_code_security — análisis estático (bandit) que detecta
     secretos hardcodeados, funciones peligrosas y criptografía débil. Incluye
     todos sus hallazgos en HALLAZGOS_JSON.
  2. Los archivos de seguridad obligatorios (settings, config, auth, login,
     password, credential, docker-compose, Dockerfile, .env*, middleware) ya
     fueron leídos automáticamente — analiza su contenido sin releerlos.
  3. Usa list_code_files para obtener el árbol completo del proyecto. Luego usa
     read_code_snippet sobre todos los archivos relevantes para seguridad que no
     hayan sido pre-cargados: vistas HTTP, autenticación/autorización, sesiones,
     validación de inputs, permisos, APIs expuestas, servicios críticos de negocio,
     configuración de servicios externos.
  4. Por cada resultado de herramienta o archivo leído: evalúa si apunta a nuevas
     áreas que investigar y, si las hay, investígalas antes de concluir.

""" + _OUTPUT_FORMAT_INSTRUCTIONS

_FINAL_REPORT_PROMPT = "Genera el reporte final con los hallazgos recopilados. " + _OUTPUT_FORMAT_INSTRUCTIONS

_AUDIT_PROMPT = """Eres un auditor de seguridad senior. Tu tarea es revisar el
siguiente reporte generado por otro analista, comparándolo con toda la
evidencia (resultados de herramientas, logs, código fuente) que aparece en
esta misma conversación. Tu meta es producir una versión corregida y completa
del reporte — no expliques los cambios, entrega directamente el reporte final.

Reporte a auditar:
---
{report}
---

Antes de responder, verifica punto por punto contra la evidencia disponible:
1. Si se ejecutó scan_code_security y reportó hallazgos de severidad Medium o
   High, confirma que TODOS estén reflejados en HALLAZGOS_JSON. Agrega los
   que falten.
2. Revisa cada read_code_snippet: si aparece una contraseña, secreto, token o
   credencial en texto plano — sin importar el nombre de la variable
   (password, pwd, secret, key, token, credential, etc.) — confirma que esté
   reportado en HALLAZGOS_JSON con la severidad que corresponda según los
   CRITERIOS DE SEVERIDAD: Critical si ese valor se asigna a un atributo,
   diccionario u objeto que luego se guarda o persiste (base de datos, archivo,
   token, sesión); High si es solo una credencial o clave hardcodeada que no se
   persiste. Si el hallazgo falta, agrégalo.
3. Confirma que se hayan revisado los archivos obligatorios de seguridad
   (settings, config, auth, login, password, credential, docker-compose,
   Dockerfile, .env, middleware) que existan en el código analizado. Si el
   análisis se detuvo antes de hacerlo, complétalo con lo que puedas inferir
   de la evidencia disponible.
4. Si se ejecutó check_dependencies y reportó CVEs con CVSS >= 7.0, confirma
   que TODOS estén reflejados en HALLAZGOS_JSON con severidad High o Critical
   según corresponda. Agrega los que falten.

Si el reporte original ya cumple todo lo anterior, repítelo sin cambios.

""" + _OUTPUT_FORMAT_INSTRUCTIONS


class SecurityAgent:
    def __init__(self, adapter: LLMAdapter, tool_registry: dict, max_iterations: int = 15,
                 audit_adapter: LLMAdapter = None, tracer=None):
        self._adapter = adapter
        self._registry = tool_registry
        self._max_iterations = max_iterations
        self._audit_adapter = audit_adapter
        self._tracer = tracer

    def _trace(self, event: str, **fields) -> None:
        if self._tracer is not None:
            self._tracer.record(event, **fields)

    def _prefetch_mandatory_files(self, code_directory: Optional[str]) -> str:
        if code_directory is None:
            return ""

        list_tool = self._registry.get("list_code_files")
        if list_tool is None:
            return ""

        list_result = list_tool.execute(directory=code_directory)
        self._trace(
            "tool_result", iteration=0, name="list_code_files",
            args={"directory": code_directory}, success=list_result.success,
            metadata=list_result.metadata, content_length=len(list_result.content),
        )

        if not list_result.success:
            return ""

        paths = []
        for line in list_result.content.splitlines():
            if not line.startswith("/"):
                continue
            basename = os.path.basename(line).lower()
            if any(fnmatch.fnmatch(basename, pattern.lower()) for pattern in MANDATORY_FILE_PATTERNS):
                paths.append(line)

        if not paths:
            return (
                "ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático):\n\n"
                "No se encontraron archivos que coincidan con los patrones de "
                "seguridad obligatorios en este proyecto."
            )

        read_tool = self._registry.get("read_code_snippet")
        sections = []
        for path in paths:
            if read_tool is None:
                sections.append(f"# {path}\n(error al leer este archivo: herramienta read_code_snippet no disponible)")
                continue
            result = read_tool.execute(file_path=path)
            self._trace(
                "tool_result", iteration=0, name="read_code_snippet",
                args={"file_path": path}, success=result.success,
                metadata=result.metadata, content_length=len(result.content),
            )
            if result.success:
                sections.append(result.content)
            else:
                sections.append(f"# {path}\n(error al leer este archivo: {result.content})")

        return "ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático, ya leídos):\n\n" + "\n\n".join(sections)

    def run(self, scope: ScanScope, on_progress: Optional[Callable[[str], None]] = None,
            on_iteration: Optional[Callable[[int, list[dict]], None]] = None,
            project_context: str = "", accepted_findings: str = "") -> tuple[str, TokenUsage]:
        def notify(message: str) -> None:
            if on_progress:
                on_progress(message)

        initial = _PROMPT.format(
            host=scope.target_host,
            types=", ".join(scope.analysis_types) or "general",
            logs=", ".join(scope.log_files) or "ninguno",
            code=scope.code_directory or "ninguno",
            hours=scope.time_range_hours,
        )
        if project_context:
            initial += "\n\n" + project_context
        if accepted_findings:
            initial += "\n\n" + accepted_findings
        prefetch_text = self._prefetch_mandatory_files(scope.code_directory)
        if prefetch_text:
            initial += "\n\n" + prefetch_text
        messages: list[Message] = [Message(role="user", content=initial)]
        tools = get_tool_schemas()

        self._trace(
            "run_start",
            host=scope.target_host,
            code_directory=scope.code_directory,
            analysis_types=scope.analysis_types,
            log_files=scope.log_files,
            max_iterations=self._max_iterations,
        )

        total_usage = TokenUsage()

        for i in range(self._max_iterations):
            notify(f"Analizando (paso {i + 1}/{self._max_iterations})...")
            response = self._adapter.chat(messages, tools=tools)
            if response.token_usage:
                total_usage = total_usage + response.token_usage

            tool_calls_summary = [
                {"name": tc["name"], "args": tc.get("args", {})}
                for tc in (response.tool_calls or [])
            ]
            self._trace(
                "llm_response",
                iteration=i + 1,
                has_tool_calls=bool(response.tool_calls),
                tool_calls=tool_calls_summary,
                content_preview=(response.content or "")[:200],
            )

            if not response.tool_calls:
                if on_iteration:
                    on_iteration(i + 1, [])
                report = response.content or "(sin respuesta)"
                self._trace("loop_end", reason="no_tool_calls", iteration=i + 1)
                return self._audit(messages, response, report, notify, total_usage)

            if on_iteration:
                on_iteration(i + 1, tool_calls_summary)

            messages.append(response)
            tool_results = []

            for tc in response.tool_calls:
                name, args = tc["name"], tc.get("args", {})
                notify(f"Ejecutando {name}...")
                tool = self._registry.get(name)
                success = False
                metadata = {}
                if tool is None:
                    content = f"Herramienta '{name}' no disponible."
                    logger.warning(content)
                else:
                    try:
                        result = tool.execute(**args)
                        content = result.content
                        success = result.success
                        metadata = result.metadata
                    except Exception as e:
                        content = f"Error en {name}: {e}"
                        logger.error(content, exc_info=True)
                tool_results.append({"name": name, "content": content})
                self._trace(
                    "tool_result",
                    iteration=i + 1,
                    name=name,
                    args=args,
                    success=success,
                    metadata=metadata,
                    content_length=len(content),
                )

            messages.append(Message(role="tool", content="", tool_results=tool_results))

        self._trace("loop_end", reason="max_iterations", iteration=self._max_iterations)
        notify("Generando reporte final...")
        messages.append(Message(role="user", content=_FINAL_REPORT_PROMPT))
        final = self._adapter.chat(messages)
        if final.token_usage:
            total_usage = total_usage + final.token_usage
        report = final.content or "(análisis incompleto)"
        return self._audit(messages, final, report, notify, total_usage)

    def _audit(self, messages: list[Message], last_response: Message, report: str,
               notify: Callable[[str], None], total_usage: TokenUsage = None) -> tuple[str, TokenUsage]:
        notify("Auditando el reporte...")
        usage = total_usage or TokenUsage()
        audit_messages = messages + [
            last_response,
            Message(role="user", content=_AUDIT_PROMPT.format(report=report)),
        ]
        adapter = self._audit_adapter or self._adapter
        try:
            audit_response = adapter.chat(audit_messages)
            if audit_response.token_usage:
                usage = usage + audit_response.token_usage
            result = audit_response.content or report
            self._trace("audit_result", success=True, report=result,
                        input_tokens=usage.input_tokens, output_tokens=usage.output_tokens)
            return result, usage
        except Exception:
            logger.exception("Error en la auditoría del reporte, se conserva el original")
            self._trace("audit_result", success=False, report=report,
                        input_tokens=usage.input_tokens, output_tokens=usage.output_tokens)
            return report, usage
