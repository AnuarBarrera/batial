from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


@dataclass
class Message:
    role: str  # "user" | "assistant" | "tool"
    content: str
    tool_calls: Optional[list] = None    # [{"name": str, "args": dict}]
    tool_results: Optional[list] = None  # [{"name": str, "content": str}]
    token_usage: Optional[TokenUsage] = None

class LLMAdapter(ABC):
    @abstractmethod
    def chat(self, messages: list[Message], tools: list = None) -> Message:
        pass

    @abstractmethod
    def supports_tools(self) -> bool:
        pass
