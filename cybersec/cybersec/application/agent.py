import logging
from cybersec.domain.llm_adapter import LLMAdapter, Message
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_tool_schemas

logger = logging.getLogger(__name__)

_OUTPUT_FORMAT_INSTRUCTIONS = (
    "Tu respuesta final debe incluir, en este orden:\n"
    "1. Un análisis narrativo con resumen ejecutivo, hallazgos y recomendaciones.\n"
    '2. Una sección llamada exactamente "HALLAZGOS_JSON:" seguida de un bloque de código '
    '```json con un array de objetos, cada uno con las claves "title" (string), '
    '"severity" (uno de "Critical", "High", "Medium", "Low" en inglés; usa "Low" para '
    'hallazgos informativos), "evidence" (string breve) y "recommendation" (string). '
    "Incluye solo problemas de seguridad reales, no estados positivos.\n"
    '3. Una sección llamada exactamente "PRÓXIMOS PASOS:" seguida de una lista numerada '
    "(1. 2. 3. ...) con las acciones más urgentes a tomar, ordenadas por prioridad."
)

_PROMPT = """Eres un agente de ciberseguridad. Analiza el sistema con este scope:

Host: {host}
Análisis solicitado: {types}
Archivos de log: {logs}
Directorio de código: {code}
Ventana de tiempo: últimas {hours} horas

Usa las herramientas disponibles para recopilar información real del sistema.
Si se especifica un directorio de código (distinto de "ninguno"), usa primero
list_code_files para descubrir los archivos disponibles y luego read_code_snippet
para revisar los más relevantes desde el punto de vista de seguridad
(configuración, autenticación, manejo de inputs, credenciales).
Cuando tengas suficientes hallazgos, genera un diagnóstico con severidad y recomendaciones concretas.

""" + _OUTPUT_FORMAT_INSTRUCTIONS

_FINAL_REPORT_PROMPT = "Genera el reporte final con los hallazgos recopilados. " + _OUTPUT_FORMAT_INSTRUCTIONS


class SecurityAgent:
    def __init__(self, adapter: LLMAdapter, tool_registry: dict, max_iterations: int = 10):
        self._adapter = adapter
        self._registry = tool_registry
        self._max_iterations = max_iterations

    def run(self, scope: ScanScope) -> str:
        initial = _PROMPT.format(
            host=scope.target_host,
            types=", ".join(scope.analysis_types) or "general",
            logs=", ".join(scope.log_files) or "ninguno",
            code=scope.code_directory or "ninguno",
            hours=scope.time_range_hours,
        )
        messages: list[Message] = [Message(role="user", content=initial)]
        tools = get_tool_schemas()

        for _ in range(self._max_iterations):
            response = self._adapter.chat(messages, tools=tools)

            if not response.tool_calls:
                return response.content or "(sin respuesta)"

            messages.append(response)
            tool_results = []

            for tc in response.tool_calls:
                name, args = tc["name"], tc.get("args", {})
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

        messages.append(Message(role="user", content=_FINAL_REPORT_PROMPT))
        final = self._adapter.chat(messages)
        return final.content or "(análisis incompleto)"
