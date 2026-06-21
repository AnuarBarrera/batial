import logging
import random
import time
from google import genai
from google.genai import types, errors as genai_errors
from cybersec.domain.llm_adapter import LLMAdapter, Message, TokenUsage

logger = logging.getLogger(__name__)

_SYSTEM = (
    "Eres un agente experto en ciberseguridad ejecutándose de forma autónoma, sin "
    "supervisión humana. Nadie puede responder preguntas ni dar confirmaciones: "
    "actúa de inmediato usando las herramientas disponibles, sin describir planes "
    "ni pedir permiso. Recopila información real del sistema y genera un "
    "diagnóstico con hallazgos, severidad y recomendaciones concretas."
)


def _to_fn_declaration(spec: dict) -> types.FunctionDeclaration:
    props = {}
    for name, info in spec.get("parameters", {}).items():
        param: dict = {"type": info.get("type", "string"), "description": info.get("description", "")}
        if param["type"] == "array":
            param["items"] = {"type": info.get("items_type", "string")}
        props[name] = param
    return types.FunctionDeclaration(
        name=spec["name"],
        description=spec["description"],
        parameters={"type": "object", "properties": props},
    )


class GeminiAdapter(LLMAdapter):
    def __init__(self, api_key: str = "", model: str = "gemini-3.1-flash-lite",
                 temperature: float = None, project: str = "", location: str = "us-west4"):
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._project = project
        self._location = location

    def _client(self) -> genai.Client:
        if self._project:
            return genai.Client(vertexai=True, project=self._project, location=self._location)
        return genai.Client(api_key=self._api_key)

    def supports_tools(self) -> bool:
        return True

    def chat(self, messages: list[Message], tools: list = None) -> Message:
        client = self._client()
        contents = []

        for m in messages:
            if m.role == "user":
                contents.append(types.Content(role="user", parts=[types.Part(text=m.content)]))
            elif m.role == "assistant":
                if m.tool_calls:
                    parts = [
                        types.Part(
                            function_call=types.FunctionCall(name=tc["name"], args=tc["args"]),
                            thought_signature=tc.get("thought_signature"),
                        )
                        for tc in m.tool_calls
                    ]
                    contents.append(types.Content(role="model", parts=parts))
                else:
                    contents.append(types.Content(role="model", parts=[types.Part(text=m.content or "")]))
            elif m.role == "tool" and m.tool_results:
                parts = [
                    types.Part(function_response=types.FunctionResponse(
                        name=tr["name"], response={"result": tr["content"]}
                    ))
                    for tr in m.tool_results
                ]
                contents.append(types.Content(role="user", parts=parts))

        cfg_kwargs = {"system_instruction": _SYSTEM}
        if self._temperature is not None:
            cfg_kwargs["temperature"] = self._temperature
        if tools:
            cfg_kwargs["tools"] = [types.Tool(function_declarations=[_to_fn_declaration(t) for t in tools])]
            if len(messages) == 1:
                # Forzar una llamada a herramienta en el primer turno: evita que el
                # modelo responda con texto describiendo un plan y pidiendo confirmación.
                cfg_kwargs["tool_config"] = types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode="ANY")
                )

        config = types.GenerateContentConfig(**cfg_kwargs)
        max_retries = 4
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=self._model,
                    contents=contents,
                    config=config,
                )
                break
            except genai_errors.ServerError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt + random.uniform(0, 1)
                    logger.warning(f"Gemini 503, reintentando en {wait:.1f}s (intento {attempt + 1}/{max_retries})")
                    time.sleep(wait)
                else:
                    raise
            except genai_errors.ClientError as e:
                if e.code == 429 and attempt < max_retries - 1:
                    wait = min(60, 15 * (2 ** attempt)) + random.uniform(0, 1)
                    logger.warning(f"Gemini rate limit (429), reintentando en {wait:.1f}s (intento {attempt + 1}/{max_retries})")
                    time.sleep(wait)
                else:
                    raise

        usage = None
        if response.usage_metadata:
            usage = TokenUsage(
                input_tokens=response.usage_metadata.prompt_token_count or 0,
                output_tokens=response.usage_metadata.candidates_token_count or 0,
            )

        if response.function_calls:
            tool_calls = []
            for part in response.candidates[0].content.parts:
                if part.function_call is not None:
                    tc = {"name": part.function_call.name, "args": dict(part.function_call.args)}
                    if part.thought_signature is not None:
                        tc["thought_signature"] = part.thought_signature
                    tool_calls.append(tc)
            return Message(role="assistant", content="", tool_calls=tool_calls, token_usage=usage)
        return Message(role="assistant", content=response.text or "", token_usage=usage)
