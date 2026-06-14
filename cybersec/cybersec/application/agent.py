import logging
from typing import Callable, Optional
from cybersec.domain.llm_adapter import LLMAdapter, Message
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_tool_schemas

logger = logging.getLogger(__name__)

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
    '(string). Incluye solo problemas de seguridad reales, no estados positivos.\n'
    '3. Una sección llamada exactamente "PRÓXIMOS PASOS:" seguida de una lista numerada '
    "(1. 2. 3. ...) con las acciones más urgentes a tomar, ordenadas por prioridad."
)

_PROMPT = """Eres un agente de ciberseguridad autónomo ejecutándose en un proceso
automatizado: no hay ningún humano disponible para responder preguntas ni dar
confirmaciones. No describas un plan ni pidas permiso — actúa de inmediato
llamando a las herramientas disponibles.

Analiza el sistema con este scope:

Host: {host}
Análisis solicitado: {types}
Archivos de log: {logs}
Directorio de código: {code}
Ventana de tiempo: últimas {hours} horas

Usa las herramientas disponibles para recopilar información real del sistema.
Si se especifica un directorio de código (distinto de "ninguno"):
1. Ejecuta SIEMPRE scan_code_security sobre ese directorio — es un análisis
   estático determinista (bandit) que detecta secretos hardcodeados, funciones
   peligrosas, criptografía débil y otros patrones inseguros. Incluye sus
   hallazgos en HALLAZGOS_JSON (ajusta la severidad si corresponde).
2. Usa list_code_files para descubrir los archivos disponibles. De esa lista,
   usa read_code_snippet para leer SIEMPRE, sin excepción y aunque ya creas
   tener suficientes hallazgos, cualquier archivo cuyo nombre coincida con
   estos patrones (son los puntos críticos de seguridad de cualquier proyecto):
     - *settings*, *config* (configuración de la app)
     - *auth*, *login*, *password*, *credential* (autenticación y credenciales)
     - docker-compose*, Dockerfile*, *.env*, .env.example (infraestructura y secretos)
     - *middleware* (seguridad de requests: CSP, rate limiting, headers)
   Además, revisa cualquier otro archivo que consideres relevante desde el
   punto de vista de seguridad (manejo de inputs, sesiones, permisos).
Cuando hayas ejecutado scan_code_security, revisado los archivos obligatorios
que existan en el directorio, y tengas suficientes hallazgos, genera un
diagnóstico con severidad y recomendaciones concretas.

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

Si el reporte original ya cumple todo lo anterior, repítelo sin cambios.

""" + _OUTPUT_FORMAT_INSTRUCTIONS


class SecurityAgent:
    def __init__(self, adapter: LLMAdapter, tool_registry: dict, max_iterations: int = 10,
                 audit_adapter: LLMAdapter = None):
        self._adapter = adapter
        self._registry = tool_registry
        self._max_iterations = max_iterations
        self._audit_adapter = audit_adapter

    def run(self, scope: ScanScope, on_progress: Optional[Callable[[str], None]] = None) -> str:
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
        messages: list[Message] = [Message(role="user", content=initial)]
        tools = get_tool_schemas()

        for i in range(self._max_iterations):
            notify(f"Analizando (paso {i + 1}/{self._max_iterations})...")
            response = self._adapter.chat(messages, tools=tools)

            if not response.tool_calls:
                report = response.content or "(sin respuesta)"
                return self._audit(messages, response, report, notify)

            messages.append(response)
            tool_results = []

            for tc in response.tool_calls:
                name, args = tc["name"], tc.get("args", {})
                notify(f"Ejecutando {name}...")
                tool = self._registry.get(name)
                if tool is None:
                    content = f"Herramienta '{name}' no disponible."
                    logger.warning(content)
                else:
                    try:
                        content = tool.execute(**args).content
                    except Exception as e:
                        content = f"Error en {name}: {e}"
                        logger.error(content, exc_info=True)
                tool_results.append({"name": name, "content": content})

            messages.append(Message(role="tool", content="", tool_results=tool_results))

        notify("Generando reporte final...")
        messages.append(Message(role="user", content=_FINAL_REPORT_PROMPT))
        final = self._adapter.chat(messages)
        report = final.content or "(análisis incompleto)"
        return self._audit(messages, final, report, notify)

    def _audit(self, messages: list[Message], last_response: Message, report: str,
               notify: Callable[[str], None]) -> str:
        notify("Auditando el reporte...")
        audit_messages = messages + [
            last_response,
            Message(role="user", content=_AUDIT_PROMPT.format(report=report)),
        ]
        adapter = self._audit_adapter or self._adapter
        try:
            audit_response = adapter.chat(audit_messages)
            return audit_response.content or report
        except Exception:
            logger.exception("Error en la auditoría del reporte, se conserva el original")
            return report
