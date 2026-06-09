import logging
from google import genai
from google.genai import types
from cybersec.domain.llm_adapter import LLMAdapter, Message

logger = logging.getLogger(__name__)

_SYSTEM = (
    "Eres un agente experto en ciberseguridad. Usa las herramientas disponibles para "
    "recopilar información del sistema y genera un diagnóstico con hallazgos, "
    "severidad y recomendaciones concretas."
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
    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self._api_key = api_key
        self._model = model

    def supports_tools(self) -> bool:
        return True

    def chat(self, messages: list[Message], tools: list = None) -> Message:
        client = genai.Client(api_key=self._api_key)
        contents = []

        for m in messages:
            if m.role == "user":
                contents.append(types.Content(role="user", parts=[types.Part(text=m.content)]))
            elif m.role == "assistant":
                if m.tool_calls:
                    parts = [
                        types.Part(function_call=types.FunctionCall(name=tc["name"], args=tc["args"]))
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
        if tools:
            cfg_kwargs["tools"] = [types.Tool(function_declarations=[_to_fn_declaration(t) for t in tools])]

        response = client.models.generate_content(
            model=self._model,
            contents=contents,
            config=types.GenerateContentConfig(**cfg_kwargs),
        )

        if response.function_calls:
            return Message(
                role="assistant", content="",
                tool_calls=[{"name": fc.name, "args": dict(fc.args)} for fc in response.function_calls],
            )
        return Message(role="assistant", content=response.text or "")
