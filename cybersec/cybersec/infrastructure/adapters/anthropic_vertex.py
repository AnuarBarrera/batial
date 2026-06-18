import logging
import random
import time

import anthropic
from anthropic import AnthropicVertex

from cybersec.domain.llm_adapter import LLMAdapter, Message, TokenUsage

logger = logging.getLogger(__name__)

_SYSTEM = (
    "Eres un agente experto en ciberseguridad ejecutándose de forma autónoma, sin "
    "supervisión humana. Nadie puede responder preguntas ni dar confirmaciones: "
    "actúa de inmediato usando las herramientas disponibles, sin describir planes "
    "ni pedir permiso. Recopila información real del sistema y genera un "
    "diagnóstico con hallazgos, severidad y recomendaciones concretas."
)


def _to_anthropic_tool(spec: dict) -> dict:
    props = {}
    required = []
    for name, info in spec.get("parameters", {}).items():
        prop: dict = {"type": info.get("type", "string")}
        if "description" in info:
            prop["description"] = info["description"]
        if info.get("type") == "array":
            prop["items"] = {"type": info.get("items_type", "string")}
        props[name] = prop
        if info.get("required"):
            required.append(name)
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"name": spec["name"], "description": spec["description"], "input_schema": schema}


class AnthropicVertexAdapter(LLMAdapter):
    def __init__(self, model: str = "claude-sonnet-4-5", project: str = "agente-cosmic",
                 region: str = "us-east5", temperature: float = None):
        self._model = model
        self._project = project
        self._region = region
        self._temperature = temperature

    def supports_tools(self) -> bool:
        return True

    def chat(self, messages: list[Message], tools: list = None) -> Message:
        client = AnthropicVertex(project_id=self._project, region=self._region)

        anthropic_messages = []
        last_tool_ids: list[str] = []

        for i, m in enumerate(messages):
            if m.role == "user":
                anthropic_messages.append({"role": "user", "content": m.content})
            elif m.role == "assistant":
                if m.tool_calls:
                    content = []
                    last_tool_ids = []
                    for j, tc in enumerate(m.tool_calls):
                        tool_id = tc.get("id", f"toolu_{i}_{j}")
                        content.append({
                            "type": "tool_use",
                            "id": tool_id,
                            "name": tc["name"],
                            "input": tc.get("args", {}),
                        })
                        last_tool_ids.append(tool_id)
                    anthropic_messages.append({"role": "assistant", "content": content})
                else:
                    anthropic_messages.append({"role": "assistant", "content": m.content or ""})
            elif m.role == "tool" and m.tool_results:
                content = []
                for j, tr in enumerate(m.tool_results):
                    tool_id = last_tool_ids[j] if j < len(last_tool_ids) else f"toolu_fallback_{j}"
                    content.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": tr["content"],
                    })
                anthropic_messages.append({"role": "user", "content": content})

        kwargs: dict = {
            "model": self._model,
            "max_tokens": 8192,
            "system": _SYSTEM,
            "messages": anthropic_messages,
        }
        if self._temperature is not None:
            kwargs["temperature"] = self._temperature
        if tools:
            kwargs["tools"] = [_to_anthropic_tool(t) for t in tools]
            if len(messages) == 1:
                kwargs["tool_choice"] = {"type": "any"}

        max_retries = 4
        for attempt in range(max_retries):
            try:
                response = client.messages.create(**kwargs)
                break
            except anthropic.APIStatusError as e:
                if e.status_code in (503, 529) and attempt < max_retries - 1:
                    wait = 2 ** attempt + random.uniform(0, 1)
                    logger.warning(
                        f"Anthropic {e.status_code}, reintentando en {wait:.1f}s (intento {attempt + 1})"
                    )
                    time.sleep(wait)
                else:
                    raise

        usage = TokenUsage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

        tool_calls = []
        text_parts = []
        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append({"name": block.name, "args": dict(block.input), "id": block.id})
            elif block.type == "text":
                text_parts.append(block.text)

        if tool_calls:
            return Message(role="assistant", content="", tool_calls=tool_calls, token_usage=usage)
        return Message(role="assistant", content="".join(text_parts), token_usage=usage)
