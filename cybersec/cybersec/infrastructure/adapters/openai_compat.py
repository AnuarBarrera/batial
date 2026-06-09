import json
import logging
import requests
from cybersec.domain.llm_adapter import LLMAdapter, Message

logger = logging.getLogger(__name__)

_SYSTEM = (
    "Eres un agente experto en ciberseguridad. Usa las herramientas disponibles para "
    "recopilar información del sistema y genera un diagnóstico con hallazgos, "
    "severidad y recomendaciones concretas."
)


def _to_openai_tool(spec: dict) -> dict:
    props = {
        name: {"type": info.get("type", "string"), "description": info.get("description", "")}
        for name, info in spec.get("parameters", {}).items()
    }
    required = [n for n, i in spec.get("parameters", {}).items() if i.get("required")]
    return {
        "type": "function",
        "function": {
            "name": spec["name"],
            "description": spec["description"],
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


class OpenAICompatAdapter(LLMAdapter):
    def __init__(self, base_url: str, model: str, api_key: str = ""):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key

    def supports_tools(self) -> bool:
        return True

    def chat(self, messages: list[Message], tools: list = None) -> Message:
        oai_messages = [{"role": "system", "content": _SYSTEM}]

        for m in messages:
            if m.role == "user":
                oai_messages.append({"role": "user", "content": m.content})
            elif m.role == "assistant":
                if m.tool_calls:
                    oai_messages.append({
                        "role": "assistant", "content": None,
                        "tool_calls": [
                            {"type": "function", "function": {
                                "name": tc["name"], "arguments": json.dumps(tc["args"])
                            }} for tc in m.tool_calls
                        ],
                    })
                else:
                    oai_messages.append({"role": "assistant", "content": m.content or ""})
            elif m.role == "tool" and m.tool_results:
                for tr in m.tool_results:
                    oai_messages.append({"role": "tool", "name": tr["name"], "content": tr["content"]})

        payload = {"model": self._model, "messages": oai_messages}
        if tools:
            payload["tools"] = [_to_openai_tool(t) for t in tools]
            payload["tool_choice"] = "auto"

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = requests.post(f"{self._base_url}/v1/chat/completions", json=payload, headers=headers, timeout=120)
        resp.raise_for_status()
        choice = resp.json()["choices"][0]["message"]

        if choice.get("tool_calls"):
            return Message(
                role="assistant", content="",
                tool_calls=[
                    {"name": tc["function"]["name"], "args": json.loads(tc["function"]["arguments"])}
                    for tc in choice["tool_calls"]
                ],
            )
        return Message(role="assistant", content=choice.get("content") or "")
