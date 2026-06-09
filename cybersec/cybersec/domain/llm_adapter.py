from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Message:
    role: str  # "user" | "assistant" | "tool"
    content: str
    tool_calls: Optional[list] = None    # [{"name": str, "args": dict}]
    tool_results: Optional[list] = None  # [{"name": str, "content": str}]

class LLMAdapter(ABC):
    @abstractmethod
    def chat(self, messages: list[Message], tools: list = None) -> Message:
        pass

    @abstractmethod
    def supports_tools(self) -> bool:
        pass
