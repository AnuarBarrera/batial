# Cybersec Agent — Fase 1 (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir un CLI standalone de ciberseguridad que analiza un sistema Linux, ejecuta 5 herramientas de diagnóstico, orquesta el análisis vía LLM y genera un reporte estructurado enviado por email.

**Architecture:** Proyecto Python independiente en `cybersec/` (sin Django). El CLI corre localmente en el sistema auditado. El LLM vive en GCP (vLLM) o Gemini como fallback. La abstracción `LLMAdapter` permite cambiar de proveedor con una línea. El agente corre un loop: LLM → tool calls → resultados → LLM → reporte final.

**Tech Stack:** Python 3.11+, Click 8.1, google-genai, requests, python-dotenv, pytest, pytest-mock

---

## Estructura de Archivos

```
cybersec/                                 ← nuevo proyecto standalone
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── .env.example
├── cybersec/
│   ├── __init__.py
│   ├── __main__.py                       ← python -m cybersec
│   ├── config.py                         ← lee .env, expone constantes
│   ├── cli.py                            ← comandos Click
│   ├── domain/
│   │   ├── __init__.py
│   │   ├── entities.py                   ← ScanScope, Finding, SecurityReport
│   │   ├── llm_adapter.py                ← Message dataclass + LLMAdapter ABC
│   │   └── tools.py                      ← BaseTool + ToolResult
│   ├── infrastructure/
│   │   ├── __init__.py
│   │   ├── adapters/
│   │   │   ├── __init__.py
│   │   │   ├── gemini.py                 ← GeminiAdapter(LLMAdapter) con tool calling
│   │   │   └── openai_compat.py          ← OpenAICompatAdapter (vLLM/Ollama/Groq)
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── registry.py               ← get_registry(), get_tool_schemas()
│   │   │   ├── log_analyzer.py           ← analyze_logs()
│   │   │   ├── port_scanner.py           ← scan_ports() vía nmap
│   │   │   ├── dep_checker.py            ← check_dependencies() vía pip-audit/npm audit
│   │   │   ├── code_reader.py            ← read_code_snippet() lee archivo
│   │   │   └── config_checker.py         ← check_configs() SSH/firewall/permisos
│   │   └── notifiers/
│   │       ├── __init__.py
│   │       └── email.py                  ← MailgunNotifier vía HTTP directo
│   └── application/
│       ├── __init__.py
│       ├── agent.py                      ← SecurityAgent (loop agentico)
│       └── report.py                     ← ReportGenerator + format_report_text()
└── tests/
    ├── conftest.py
    ├── test_domain.py
    ├── test_adapters.py
    ├── test_log_analyzer.py
    ├── test_port_scanner.py
    ├── test_dep_checker.py
    ├── test_code_reader.py
    ├── test_config_checker.py
    ├── test_registry.py
    ├── test_agent.py
    ├── test_report.py
    └── test_email.py
```

---

### Task 1: Project Scaffold + Domain

**Files:**
- Create: `cybersec/requirements.txt`
- Create: `cybersec/requirements-dev.txt`
- Create: `cybersec/pytest.ini`
- Create: `cybersec/.env.example`
- Create: `cybersec/cybersec/__init__.py`
- Create: `cybersec/cybersec/domain/__init__.py`
- Create: `cybersec/cybersec/domain/entities.py`
- Create: `cybersec/cybersec/domain/tools.py`
- Create: `cybersec/cybersec/domain/llm_adapter.py`
- Test: `cybersec/tests/test_domain.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_domain.py
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.domain.tools import BaseTool, ToolResult
from cybersec.domain.llm_adapter import LLMAdapter, Message
import inspect

def test_scan_scope_defaults():
    scope = ScanScope(target_host="localhost")
    assert scope.log_files == []
    assert scope.code_directory is None
    assert scope.analysis_types == []

def test_finding_fields():
    f = Finding(id="F001", title="SSH root", severity="High",
                evidence="PermitRootLogin yes", recommendation="Cambiarlo a no")
    assert f.severity == "High"

def test_security_report_summary():
    report = SecurityReport(findings=[
        Finding("F001", "A", "Critical", "e", "r"),
        Finding("F002", "B", "High", "e", "r"),
        Finding("F003", "C", "High", "e", "r"),
    ])
    s = report.summary()
    assert s["total"] == 3
    assert s["Critical"] == 1
    assert s["High"] == 2
    assert s["Medium"] == 0

def test_llm_adapter_is_abstract():
    assert inspect.isabstract(LLMAdapter)

def test_message_defaults():
    m = Message(role="user", content="hola")
    assert m.tool_calls is None
    assert m.tool_results is None

def test_base_tool_error_helper():
    class Dummy(BaseTool):
        name = "dummy"
        def execute(self, **kwargs) -> ToolResult:
            return self._error("fallo")
    r = Dummy().execute()
    assert r.success is False
    assert r.tool_name == "dummy"
    assert r.error == "fallo"
```

- [ ] **Step 2: Correr el test — debe fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_domain.py -v
```

Expected: `ModuleNotFoundError: No module named 'cybersec'`

- [ ] **Step 3: Crear estructura de directorios y archivos base**

```bash
mkdir -p cybersec/cybersec/domain cybersec/cybersec/infrastructure/adapters \
         cybersec/cybersec/infrastructure/tools cybersec/cybersec/infrastructure/notifiers \
         cybersec/cybersec/application cybersec/tests
touch cybersec/cybersec/__init__.py cybersec/cybersec/domain/__init__.py \
      cybersec/cybersec/infrastructure/__init__.py cybersec/cybersec/infrastructure/adapters/__init__.py \
      cybersec/cybersec/infrastructure/tools/__init__.py cybersec/cybersec/infrastructure/notifiers/__init__.py \
      cybersec/cybersec/application/__init__.py cybersec/tests/__init__.py
```

- [ ] **Step 4: Crear `requirements.txt`**

```
click>=8.1,<8.2
google-genai>=0.8.0
requests>=2.31.0
python-dotenv>=1.0.0
```

- [ ] **Step 5: Crear `requirements-dev.txt`**

```
pytest>=8.0.0
pytest-mock>=3.12.0
```

- [ ] **Step 6: Crear `pytest.ini`**

```ini
[pytest]
pythonpath = .
testpaths = tests
```

- [ ] **Step 7: Crear `.env.example`**

```
GEMINI_API_KEY=your-gemini-key
OPENAI_COMPAT_BASE_URL=http://your-vllm-server:8000
OPENAI_COMPAT_MODEL=Qwen/Qwen2.5-Coder-14B-Instruct
MAILGUN_API_KEY=your-mailgun-key
MAILGUN_SENDER_EMAIL=security@yourdomain.com
MAILGUN_DOMAIN=yourdomain.com
```

- [ ] **Step 8: Crear `cybersec/domain/entities.py`**

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class ScanScope:
    target_host: str
    log_files: list[str] = field(default_factory=list)
    code_directory: Optional[str] = None
    time_range_hours: int = 24
    analysis_types: list[str] = field(default_factory=list)
    email_report_to: Optional[str] = None

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # "Critical" | "High" | "Medium" | "Low"
    evidence: str
    recommendation: str
    tool: str = ""

@dataclass
class SecurityReport:
    findings: list[Finding] = field(default_factory=list)
    scope: Optional[ScanScope] = None
    generated_at: Optional[datetime] = None
    analysis_text: str = ""

    def summary(self) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return {"total": len(self.findings), **counts}
```

- [ ] **Step 9: Crear `cybersec/domain/tools.py`**

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ToolResult:
    content: str
    tool_name: str
    success: bool
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

class BaseTool(ABC):
    name: str = ""

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        pass

    def _error(self, message: str) -> ToolResult:
        return ToolResult(content=message, tool_name=self.name, success=False, error=message)
```

- [ ] **Step 10: Crear `cybersec/domain/llm_adapter.py`**

```python
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
```

- [ ] **Step 11: Instalar dependencias y correr tests — deben pasar**

```bash
cd /home/anuarbarrera/batial/cybersec && pip install -r requirements.txt -r requirements-dev.txt -q
pytest tests/test_domain.py -v
```

Expected: `6 passed`

- [ ] **Step 12: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): project scaffold + domain entities, LLMAdapter, BaseTool"
```

---

### Task 2: Config

**Files:**
- Create: `cybersec/cybersec/config.py`
- Create: `cybersec/tests/test_config.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_config.py
import os
from importlib import reload
from unittest.mock import patch

def test_config_reads_gemini_key():
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-123"}):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.GEMINI_API_KEY == "test-key-123"

def test_config_openai_default_empty():
    clean = {k: v for k, v in os.environ.items() if k != "OPENAI_COMPAT_BASE_URL"}
    with patch.dict(os.environ, clean, clear=True):
        import cybersec.config as cfg
        reload(cfg)
        assert cfg.OPENAI_COMPAT_BASE_URL == ""
```

- [ ] **Step 2: Correr — debe fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_config.py -v
```

Expected: `ModuleNotFoundError: No module named 'cybersec.config'`

- [ ] **Step 3: Crear `cybersec/config.py`**

```python
import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
OPENAI_COMPAT_BASE_URL: str = os.getenv("OPENAI_COMPAT_BASE_URL", "")
OPENAI_COMPAT_MODEL: str = os.getenv("OPENAI_COMPAT_MODEL", "Qwen/Qwen2.5-Coder-14B-Instruct")
MAILGUN_API_KEY: str = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_SENDER_EMAIL: str = os.getenv("MAILGUN_SENDER_EMAIL", "")
MAILGUN_DOMAIN: str = os.getenv("MAILGUN_DOMAIN", "")
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_config.py -v
```

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): add config module reading from .env"
```

---

### Task 3: GeminiAdapter (con tool calling)

**Files:**
- Create: `cybersec/cybersec/infrastructure/adapters/gemini.py`
- Create: `cybersec/tests/test_adapters.py`

> Nota: Este adapter es diferente al `GeminiAdapter` del chatbot. Este soporta function calling para el loop agentico.

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_adapters.py
import pytest
from unittest.mock import patch, MagicMock
from cybersec.domain.llm_adapter import LLMAdapter, Message
from cybersec.infrastructure.adapters.gemini import GeminiAdapter

def test_gemini_implements_llm_adapter():
    assert issubclass(GeminiAdapter, LLMAdapter)

def test_gemini_supports_tools():
    assert GeminiAdapter(api_key="fake").supports_tools() is True

@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_returns_text(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.text = "Sistema analizado."
    mock_resp.function_calls = []
    mock_client.models.generate_content.return_value = mock_resp

    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="analiza")])

    assert result.role == "assistant"
    assert result.content == "Sistema analizado."
    assert result.tool_calls is None

@patch("cybersec.infrastructure.adapters.gemini.genai")
def test_gemini_chat_returns_tool_call(mock_genai):
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    fc = MagicMock()
    fc.name = "scan_ports"
    fc.args = {"host": "localhost"}

    mock_resp = MagicMock()
    mock_resp.text = None
    mock_resp.function_calls = [fc]
    mock_client.models.generate_content.return_value = mock_resp

    tools = [{"name": "scan_ports", "description": "Escanea puertos", "parameters": {
        "host": {"type": "string", "description": "Host objetivo"}
    }}]
    result = GeminiAdapter(api_key="fake").chat([Message(role="user", content="escanea")], tools=tools)

    assert result.tool_calls is not None
    assert result.tool_calls[0]["name"] == "scan_ports"
    assert result.tool_calls[0]["args"] == {"host": "localhost"}
```

- [ ] **Step 2: Correr — debe fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_adapters.py -v
```

Expected: `ModuleNotFoundError: No module named 'cybersec.infrastructure.adapters.gemini'`

- [ ] **Step 3: Crear `cybersec/infrastructure/adapters/gemini.py`**

```python
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
    props = {
        name: {"type": info.get("type", "string"), "description": info.get("description", "")}
        for name, info in spec.get("parameters", {}).items()
    }
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
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_adapters.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): GeminiAdapter with function calling support"
```

---

### Task 4: OpenAICompatAdapter

**Files:**
- Create: `cybersec/cybersec/infrastructure/adapters/openai_compat.py`
- Modify: `cybersec/tests/test_adapters.py`

- [ ] **Step 1: Agregar tests al archivo existente**

```python
# Agregar al final de cybersec/tests/test_adapters.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.adapters.openai_compat import OpenAICompatAdapter

def test_openai_compat_implements_llm_adapter():
    assert issubclass(OpenAICompatAdapter, LLMAdapter)

@patch("cybersec.infrastructure.adapters.openai_compat.requests.post")
def test_openai_compat_returns_text(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"choices": [{"message": {"role": "assistant", "content": "Hola", "tool_calls": None}}]},
        raise_for_status=lambda: None,
    )
    adapter = OpenAICompatAdapter(base_url="http://localhost:8000", model="Qwen/14B")
    result = adapter.chat([Message(role="user", content="Hola")])
    assert result.content == "Hola"
    assert result.tool_calls is None

@patch("cybersec.infrastructure.adapters.openai_compat.requests.post")
def test_openai_compat_returns_tool_call(mock_post):
    mock_post.return_value = MagicMock(
        json=lambda: {"choices": [{"message": {
            "role": "assistant", "content": None,
            "tool_calls": [{"function": {"name": "scan_ports", "arguments": '{"host": "localhost"}'}}]
        }}]},
        raise_for_status=lambda: None,
    )
    adapter = OpenAICompatAdapter(base_url="http://localhost:8000", model="Qwen/14B")
    result = adapter.chat([Message(role="user", content="escanea")], tools=[])
    assert result.tool_calls[0]["name"] == "scan_ports"
    assert result.tool_calls[0]["args"] == {"host": "localhost"}
```

- [ ] **Step 2: Correr — deben fallar los nuevos tests**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_adapters.py -v
```

Expected: `4 passed, 3 failed`

- [ ] **Step 3: Crear `cybersec/infrastructure/adapters/openai_compat.py`**

```python
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
```

- [ ] **Step 4: Correr — todos deben pasar**

```bash
pytest tests/test_adapters.py -v
```

Expected: `7 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): OpenAICompatAdapter for vLLM/Ollama/Groq"
```

---

### Task 5: Tool — analyze_logs()

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/log_analyzer.py`
- Create: `cybersec/tests/test_log_analyzer.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_log_analyzer.py
import pytest
from cybersec.infrastructure.tools.log_analyzer import LogAnalyzerTool
from cybersec.domain.tools import ToolResult

AUTH_LOG = "\n".join(
    f"Jun  9 10:01:{i:02d} srv sshd[1]: Failed password for root from 10.10.10.10 port 22 ssh2"
    for i in range(12)
)
NGINX_LOG = (
    '1.1.1.1 - - [09/Jun/2026:10:00:00 +0000] "GET /api" HTTP/1.1" 500 512\n'
    '1.1.1.1 - - [09/Jun/2026:10:00:01 +0000] "GET /ok" HTTP/1.1" 200 1024\n'
)

def test_name():
    assert LogAnalyzerTool().name == "analyze_logs"

def test_returns_tool_result():
    assert isinstance(LogAnalyzerTool().execute(log_files=[]), ToolResult)

def test_empty_log_files_is_error():
    r = LogAnalyzerTool().execute(log_files=[])
    assert r.success is False

def test_missing_file_is_error():
    r = LogAnalyzerTool().execute(log_files=["/no/existe.log"])
    assert r.success is False

def test_detects_brute_force(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(AUTH_LOG)
    r = LogAnalyzerTool().execute(log_files=[str(f)])
    assert r.success is True
    assert "10.10.10.10" in r.content
    assert r.metadata["brute_force_ips"] == ["10.10.10.10"]

def test_detects_5xx(tmp_path):
    f = tmp_path / "nginx.log"
    f.write_text(NGINX_LOG)
    r = LogAnalyzerTool().execute(log_files=[str(f)])
    assert r.success is True
    assert "500" in r.content
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_log_analyzer.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/log_analyzer.py`**

```python
import re
import logging
from collections import defaultdict
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_FAILED_SSH = re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)")
_NGINX_5XX = re.compile(r'" [5]\d{2} ')
_SUDO = re.compile(r"sudo:.*COMMAND=")
BRUTE_THRESHOLD = 10


class LogAnalyzerTool(BaseTool):
    name = "analyze_logs"

    def execute(self, log_files: list[str] = None, **kwargs) -> ToolResult:
        if not log_files:
            return self._error("No se proporcionaron archivos de log.")

        found = [p for p in log_files if Path(p).exists()]
        if not found:
            return self._error(f"Archivos no encontrados: {log_files}")

        failed: defaultdict[str, int] = defaultdict(int)
        errors_5xx: list[str] = []
        sudo_events: list[str] = []
        total_lines = 0

        for path in found:
            try:
                lines = Path(path).read_text(errors="replace").splitlines()
            except OSError as e:
                logger.warning(f"No se pudo leer {path}: {e}")
                continue
            total_lines += len(lines)
            for line in lines:
                m = _FAILED_SSH.search(line)
                if m:
                    failed[m.group(1)] += 1
                if _NGINX_5XX.search(line):
                    errors_5xx.append(line.strip())
                if _SUDO.search(line):
                    sudo_events.append(line.strip())

        findings = []
        brute_ips = []
        for ip, count in failed.items():
            if count > BRUTE_THRESHOLD:
                findings.append(f"⚠️  Brute force SSH desde {ip}: {count} intentos fallidos")
                brute_ips.append(ip)
            else:
                findings.append(f"ℹ️  Intentos SSH fallidos desde {ip}: {count}")

        for line in errors_5xx[:10]:
            findings.append(f"⚠️  Error HTTP 5xx: {line[:120]}")

        for line in sudo_events[:5]:
            findings.append(f"ℹ️  Evento sudo: {line[:120]}")

        content = (
            f"✅ Análisis completado. {total_lines} líneas. Sin anomalías."
            if not findings
            else f"Análisis de logs ({total_lines} líneas, {len(found)} archivos):\n\n" + "\n".join(findings)
        )
        return ToolResult(
            content=content, tool_name=self.name, success=True,
            metadata={
                "lines_processed": total_lines,
                "brute_force_ips": brute_ips,
                "errors_5xx_count": len(errors_5xx),
            },
        )
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_log_analyzer.py -v
```

Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): analyze_logs tool — brute force SSH, 5xx HTTP, sudo"
```

---

### Task 6: Tool — scan_ports()

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/port_scanner.py`
- Create: `cybersec/tests/test_port_scanner.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_port_scanner.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.port_scanner import PortScannerTool
from cybersec.domain.tools import ToolResult

NMAP_OUT = """
Nmap scan report for localhost (127.0.0.1)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
"""

def test_name():
    assert PortScannerTool().name == "scan_ports"

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_parses_open_ports(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=NMAP_OUT, stderr="")
    r = PortScannerTool().execute(host="localhost")
    assert r.success is True
    assert 22 in r.metadata["open_ports"]
    assert 80 in r.metadata["open_ports"]

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_flags_sensitive_port(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout=NMAP_OUT, stderr="")
    r = PortScannerTool().execute(host="localhost")
    assert 3306 in r.metadata["sensitive_ports"]
    assert "3306" in r.content

@patch("cybersec.infrastructure.tools.port_scanner.subprocess.run")
def test_nmap_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()
    r = PortScannerTool().execute(host="localhost")
    assert r.success is False
    assert "nmap" in r.error.lower()
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_port_scanner.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/port_scanner.py`**

```python
import re
import subprocess
import logging
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)

SENSITIVE = {
    21: "FTP sin cifrado",
    23: "Telnet sin cifrado",
    3306: "MySQL expuesto",
    5432: "PostgreSQL expuesto",
    6379: "Redis expuesto",
    27017: "MongoDB expuesto",
    5900: "VNC expuesto",
    9200: "Elasticsearch expuesto",
}


class PortScannerTool(BaseTool):
    name = "scan_ports"

    def execute(self, host: str = "localhost", **kwargs) -> ToolResult:
        try:
            proc = subprocess.run(
                ["nmap", "--top-ports", "100", "-T4", host],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            return self._error("nmap no instalado. Instala con: sudo apt install nmap")
        except subprocess.TimeoutExpired:
            return self._error(f"Timeout escaneando {host}")

        if proc.returncode != 0:
            return self._error(f"nmap error: {proc.stderr[:200]}")

        matches = _PORT_RE.findall(proc.stdout)
        open_ports = [(int(p), svc) for p, svc in matches]
        sensitive = {p: SENSITIVE[p] for p, _ in open_ports if p in SENSITIVE}

        lines = [f"Escaneo de puertos — {host} (top 100):"]
        for port, svc in open_ports:
            warn = SENSITIVE.get(port, "")
            lines.append(f"  {'⚠️ ' if warn else '  '}{port}/tcp  {svc}  {warn}")

        if not open_ports:
            lines.append("  Sin puertos abiertos en top 100.")

        return ToolResult(
            content="\n".join(lines), tool_name=self.name, success=True,
            metadata={"host": host, "open_ports": [p for p, _ in open_ports], "sensitive_ports": sensitive},
        )
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_port_scanner.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): scan_ports tool wrapping nmap top-100"
```

---

### Task 7: Tool — check_dependencies()

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/dep_checker.py`
- Create: `cybersec/tests/test_dep_checker.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_dep_checker.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.dep_checker import DependencyCheckerTool

PIP_AUDIT_JSON = '[{"name":"requests","version":"2.25.0","vulns":[{"id":"CVE-2023-32681","fix_versions":["2.31.0"],"description":"Proxy header leak"}]}]'
NPM_AUDIT_JSON = '{"metadata":{"vulnerabilities":{"critical":1,"high":0}},"vulnerabilities":{"lodash":{"name":"lodash","severity":"critical","via":[{"title":"Proto Pollution","cve":"CVE-2020-8203"}]}}}'

def test_name():
    from cybersec.infrastructure.tools.dep_checker import DependencyCheckerTool
    assert DependencyCheckerTool().name == "check_dependencies"

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_pip_audit_finds_cve(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout=PIP_AUDIT_JSON, stderr="")
    r = DependencyCheckerTool().execute(package_managers=["pip"])
    assert r.success is True
    assert "CVE-2023-32681" in r.content

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_pip_audit_not_installed_graceful(mock_run):
    mock_run.side_effect = FileNotFoundError()
    r = DependencyCheckerTool().execute(package_managers=["pip"])
    assert r.success is True
    assert "pip-audit" in r.content

@patch("cybersec.infrastructure.tools.dep_checker.subprocess.run")
def test_npm_audit_finds_cve(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout=NPM_AUDIT_JSON, stderr="")
    r = DependencyCheckerTool().execute(package_managers=["npm"])
    assert r.success is True
    assert "critical" in r.content.lower()
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_dep_checker.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/dep_checker.py`**

```python
import json
import subprocess
import logging
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return -1, ""
    except subprocess.TimeoutExpired:
        return -2, ""


def _check_pip() -> str:
    code, out = _run(["pip-audit", "--format", "json"])
    if code == -1:
        return "ℹ️  pip-audit no disponible. Instala con: pip install pip-audit"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "⚠️  No se pudo parsear salida de pip-audit."
    vulns = [p for p in data if p.get("vulns")]
    if not vulns:
        return "✅ pip: Sin vulnerabilidades conocidas."
    lines = ["pip — vulnerabilidades encontradas:"]
    for pkg in vulns:
        for v in pkg["vulns"]:
            fix = v.get("fix_versions", ["?"])[0]
            lines.append(f"  ⚠️  {pkg['name']} {pkg['version']}: {v['id']} → fix en {fix}")
    return "\n".join(lines)


def _check_npm() -> str:
    code, out = _run(["npm", "audit", "--json"], timeout=30)
    if code == -1:
        return "ℹ️  npm no disponible."
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "⚠️  No se pudo parsear npm audit."
    meta = data.get("metadata", {}).get("vulnerabilities", {})
    critical, high = meta.get("critical", 0), meta.get("high", 0)
    if critical == 0 and high == 0:
        return "✅ npm: Sin vulnerabilidades críticas o altas."
    lines = [f"npm — {critical} críticas, {high} altas:"]
    for name, vuln in data.get("vulnerabilities", {}).items():
        via = vuln.get("via", [{}])
        cve = via[0].get("cve", "") if isinstance(via[0], dict) else ""
        lines.append(f"  ⚠️  {name} [{vuln.get('severity')}] {cve}")
    return "\n".join(lines)


class DependencyCheckerTool(BaseTool):
    name = "check_dependencies"

    def execute(self, package_managers: list[str] = None, **kwargs) -> ToolResult:
        managers = package_managers or ["pip", "npm"]
        sections = []
        if "pip" in managers:
            sections.append(_check_pip())
        if "npm" in managers:
            sections.append(_check_npm())
        content = "\n\n".join(sections) if sections else "Sin gestores de paquetes configurados."
        return ToolResult(content=content, tool_name=self.name, success=True, metadata={"managers": managers})
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_dep_checker.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): check_dependencies tool via pip-audit and npm audit"
```

---

### Task 8: Tool — read_code_snippet()

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/code_reader.py`
- Create: `cybersec/tests/test_code_reader.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_code_reader.py
import pytest
from cybersec.infrastructure.tools.code_reader import CodeReaderTool

def test_name():
    assert CodeReaderTool().name == "read_code_snippet"

def test_reads_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('import os\npassword = "hardcoded"\n')
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert "import os" in r.content
    assert r.metadata["lines"] == 2

def test_missing_file():
    r = CodeReaderTool().execute(file_path="/no/existe.py")
    assert r.success is False

def test_truncates_large_file(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("x = 1\n" * 500)
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert r.metadata["truncated"] is True
    assert "truncado" in r.content.lower()

def test_rejects_binary_extension(tmp_path):
    f = tmp_path / "app.exe"
    f.write_bytes(b"\x00\x01")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is False
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_code_reader.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/code_reader.py`**

```python
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

MAX_LINES = 300
ALLOWED = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".sh",
           ".yaml", ".yml", ".env", ".conf", ".cfg", ".ini", ".toml"}


class CodeReaderTool(BaseTool):
    name = "read_code_snippet"

    def execute(self, file_path: str = "", **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return self._error(f"Archivo no existe: {file_path}")
        if path.suffix.lower() not in ALLOWED:
            return self._error(f"Extensión no permitida: {path.suffix}")
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as e:
            return self._error(f"Error leyendo {file_path}: {e}")

        truncated = len(lines) > MAX_LINES
        snippet = "\n".join(lines[:MAX_LINES])
        suffix = f"\n\n[archivo truncado — primeras {MAX_LINES} de {len(lines)} líneas]" if truncated else ""
        ext = path.suffix.lstrip(".")
        content = f"# {file_path}\n```{ext}\n{snippet}{suffix}\n```"
        return ToolResult(
            content=content, tool_name=self.name, success=True,
            metadata={"file_path": str(path), "lines": len(lines), "truncated": truncated},
        )
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_code_reader.py -v
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): read_code_snippet tool for static analysis input"
```

---

### Task 9: Tool — check_configs()

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/config_checker.py`
- Create: `cybersec/tests/test_config_checker.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_config_checker.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.tools.config_checker import ConfigCheckerTool

SSH_BAD = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n"
SSH_GOOD = "PermitRootLogin no\nPasswordAuthentication no\nPort 2222\n"

def test_name():
    assert ConfigCheckerTool().name == "check_configs"

def test_detects_root_login(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text(SSH_BAD)
    r = ConfigCheckerTool().execute(ssh_config_path=str(f))
    assert r.success is True
    assert r.metadata["ssh_issues"] != []
    assert "PermitRootLogin" in r.content

def test_clean_ssh_no_issues(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text(SSH_GOOD)
    r = ConfigCheckerTool().execute(ssh_config_path=str(f))
    assert r.success is True
    assert r.metadata["ssh_issues"] == []

@patch("cybersec.infrastructure.tools.config_checker._run_cmd")
def test_inactive_firewall(mock_cmd):
    mock_cmd.return_value = (0, "Status: inactive\n", "")
    r = ConfigCheckerTool().execute(ssh_config_path="/nonexistent")
    assert "inactive" in r.content.lower() or "desactivado" in r.content.lower()
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_config_checker.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/config_checker.py`**

```python
import re
import stat
import subprocess
import logging
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

SSH_CHECKS = [
    (re.compile(r"^\s*PermitRootLogin\s+yes", re.I | re.M),
     "PermitRootLogin yes — login directo como root via SSH", "High"),
    (re.compile(r"^\s*PasswordAuthentication\s+yes", re.I | re.M),
     "PasswordAuthentication yes — vulnerable a brute force", "Medium"),
    (re.compile(r"^\s*Port\s+22\b", re.I | re.M),
     "Puerto 22 por defecto — expuesto a scanners", "Low"),
]

SENSITIVE_FILES = [
    ("/etc/passwd", 0o644, "Permisos incorrectos en /etc/passwd"),
    ("/etc/shadow", 0o640, "Permisos incorrectos en /etc/shadow"),
]


def _run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, p.stdout, p.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def _check_ssh(path: str) -> tuple[list[str], list[dict]]:
    p = Path(path)
    if not p.exists():
        return [f"ℹ️  sshd_config no encontrado en {path}"], []
    content = p.read_text(errors="replace")
    issues, raw = [], []
    for pattern, msg, severity in SSH_CHECKS:
        if pattern.search(content):
            issues.append(f"⚠️  [{severity}] {msg}")
            raw.append({"severity": severity, "message": msg})
    return issues or ["✅ SSH config sin problemas detectados."], raw


def _check_permissions() -> list[str]:
    lines = []
    for path, expected, msg in SENSITIVE_FILES:
        p = Path(path)
        if p.exists() and stat.S_IMODE(p.stat().st_mode) > expected:
            lines.append(f"⚠️  {msg} (actual: {oct(stat.S_IMODE(p.stat().st_mode))})")
    return lines or ["✅ Permisos de archivos sensibles: OK"]


def _check_firewall() -> list[str]:
    code, out, _ = _run_cmd(["ufw", "status"])
    if code == 0:
        first_line = out.strip().splitlines()[0] if out.strip() else ""
        if "inactive" in first_line.lower():
            return [f"⚠️  [High] UFW desactivado ({first_line})"]
        return [f"✅ UFW: {first_line}"]
    code2, out2, _ = _run_cmd(["iptables", "-L", "-n"])
    if code2 == 0:
        if out2.splitlines() and "ACCEPT" in out2.splitlines()[0]:
            return ["⚠️  [High] iptables: política por defecto ACCEPT"]
        return ["✅ iptables activo"]
    return ["ℹ️  Sin firewall detectado (ufw/iptables no disponibles)"]


class ConfigCheckerTool(BaseTool):
    name = "check_configs"

    def execute(self, ssh_config_path: str = "/etc/ssh/sshd_config", **kwargs) -> ToolResult:
        ssh_lines, ssh_issues = _check_ssh(ssh_config_path)
        content = "\n\n".join([
            "=== SSH Config ===\n" + "\n".join(ssh_lines),
            "=== Permisos ===\n" + "\n".join(_check_permissions()),
            "=== Firewall ===\n" + "\n".join(_check_firewall()),
        ])
        return ToolResult(content=content, tool_name=self.name, success=True,
                          metadata={"ssh_issues": ssh_issues})
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_config_checker.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): check_configs tool — SSH, file permissions, firewall"
```

---

### Task 10: Tool Registry

**Files:**
- Create: `cybersec/cybersec/infrastructure/tools/registry.py`
- Create: `cybersec/tests/test_registry.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_registry.py
from cybersec.infrastructure.tools.registry import get_registry, get_tool, get_tool_schemas
from cybersec.domain.tools import BaseTool

EXPECTED_TOOLS = {"analyze_logs", "scan_ports", "check_dependencies", "read_code_snippet", "check_configs"}

def test_registry_has_all_tools():
    assert set(get_registry().keys()) == EXPECTED_TOOLS

def test_get_tool_returns_base_tool():
    assert isinstance(get_tool("analyze_logs"), BaseTool)

def test_get_unknown_tool_returns_none():
    assert get_tool("not_a_tool") is None

def test_tool_schemas_structure():
    schemas = get_tool_schemas()
    assert {s["name"] for s in schemas} == EXPECTED_TOOLS
    for s in schemas:
        assert "name" in s
        assert "description" in s
        assert "parameters" in s
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_registry.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/infrastructure/tools/registry.py`**

```python
from .log_analyzer import LogAnalyzerTool
from .port_scanner import PortScannerTool
from .dep_checker import DependencyCheckerTool
from .code_reader import CodeReaderTool
from .config_checker import ConfigCheckerTool

TOOL_SCHEMAS = [
    {
        "name": "analyze_logs",
        "description": "Analiza archivos de log (auth.log, syslog, nginx, apache) buscando brute force SSH, IPs repetidas y errores HTTP 5xx.",
        "parameters": {
            "log_files": {"type": "array", "description": "Lista de rutas absolutas a archivos de log", "required": True},
        },
    },
    {
        "name": "scan_ports",
        "description": "Escanea los top 100 puertos TCP con nmap. Detecta puertos abiertos y servicios sensibles expuestos.",
        "parameters": {
            "host": {"type": "string", "description": "IP o hostname a escanear (ej. localhost, 192.168.1.1)", "required": True},
        },
    },
    {
        "name": "check_dependencies",
        "description": "Verifica paquetes pip/npm instalados contra CVEs conocidos usando pip-audit y npm audit.",
        "parameters": {
            "package_managers": {"type": "array", "description": "Lista de gestores a revisar: ['pip', 'npm']"},
        },
    },
    {
        "name": "read_code_snippet",
        "description": "Lee un archivo de código fuente (.py, .js, .ts, .go, .sh, .env, .conf, .yaml, etc.) para análisis estático.",
        "parameters": {
            "file_path": {"type": "string", "description": "Ruta absoluta al archivo a analizar", "required": True},
        },
    },
    {
        "name": "check_configs",
        "description": "Revisa configuración SSH (sshd_config), permisos de /etc/passwd y /etc/shadow, y estado del firewall (ufw/iptables).",
        "parameters": {
            "ssh_config_path": {"type": "string", "description": "Ruta al sshd_config (default: /etc/ssh/sshd_config)"},
        },
    },
]

_REGISTRY = None


def get_registry() -> dict:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = {
            "analyze_logs": LogAnalyzerTool(),
            "scan_ports": PortScannerTool(),
            "check_dependencies": DependencyCheckerTool(),
            "read_code_snippet": CodeReaderTool(),
            "check_configs": ConfigCheckerTool(),
        }
    return _REGISTRY


def get_tool(name: str):
    return get_registry().get(name)


def get_tool_schemas() -> list[dict]:
    return TOOL_SCHEMAS
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_registry.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): tool registry with schemas for LLM function calling"
```

---

### Task 11: SecurityAgent (loop agentico)

**Files:**
- Create: `cybersec/cybersec/application/agent.py`
- Create: `cybersec/tests/test_agent.py`

- [ ] **Step 1: Escribir el test que falla**

```python
# cybersec/tests/test_agent.py
from unittest.mock import MagicMock
from cybersec.domain.llm_adapter import Message
from cybersec.domain.entities import ScanScope
from cybersec.domain.tools import ToolResult
from cybersec.application.agent import SecurityAgent

def _adapter(*responses):
    a = MagicMock()
    a.supports_tools.return_value = True
    a.chat.side_effect = list(responses)
    return a

def _tool(name, content="ok"):
    t = MagicMock()
    t.name = name
    t.execute.return_value = ToolResult(content=content, tool_name=name, success=True)
    return t

def test_agent_returns_text_on_first_response():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert "Sistema seguro" in result
    assert adapter.chat.call_count == 1

def test_agent_calls_tool_then_responds():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {}}]),
        Message(role="assistant", content="2 problemas en SSH encontrados."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool})
    result = agent.run(ScanScope("localhost"))
    assert "2 problemas" in result
    tool.execute.assert_called_once()
    assert adapter.chat.call_count == 2

def test_agent_stops_at_max_iterations():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 10 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3)
    result = agent.run(ScanScope("localhost"))
    assert adapter.chat.call_count <= 5

def test_agent_handles_unknown_tool_gracefully():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "ghost_tool", "args": {}}]),
        Message(role="assistant", content="Análisis completado."),
    )
    result = SecurityAgent(adapter=adapter, tool_registry={}).run(ScanScope("localhost"))
    assert "completado" in result
```

- [ ] **Step 2: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_agent.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Crear `cybersec/application/agent.py`**

```python
import logging
from cybersec.domain.llm_adapter import LLMAdapter, Message
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_tool_schemas

logger = logging.getLogger(__name__)

_PROMPT = """Eres un agente de ciberseguridad. Analiza el sistema con este scope:

Host: {host}
Análisis solicitado: {types}
Archivos de log: {logs}
Directorio de código: {code}
Ventana de tiempo: últimas {hours} horas

Usa las herramientas disponibles para recopilar información real del sistema.
Cuando tengas suficientes hallazgos, genera un diagnóstico con severidad y recomendaciones concretas."""


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

        messages.append(Message(role="user", content="Genera el reporte final con los hallazgos recopilados."))
        final = self._adapter.chat(messages)
        return final.content or "(análisis incompleto)"
```

- [ ] **Step 4: Correr — deben pasar**

```bash
pytest tests/test_agent.py -v
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): SecurityAgent agentic loop with tool execution"
```

---

### Task 12: ReportGenerator + MailgunNotifier

**Files:**
- Create: `cybersec/cybersec/application/report.py`
- Create: `cybersec/cybersec/infrastructure/notifiers/email.py`
- Create: `cybersec/tests/test_report.py`
- Create: `cybersec/tests/test_email.py`

- [ ] **Step 1: Escribir tests de reporte**

```python
# cybersec/tests/test_report.py
from datetime import datetime
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.application.report import ReportGenerator, format_report_text

def test_report_has_required_sections():
    scope = ScanScope(target_host="192.168.1.1")
    report = SecurityReport(
        findings=[Finding("F001", "MySQL expuesto", "Critical", "3306/tcp open", "Restringir con firewall")],
        scope=scope, generated_at=datetime(2026, 6, 9),
        analysis_text="Análisis del agente aquí."
    )
    text = format_report_text(report)
    assert "REPORTE DE SEGURIDAD" in text
    assert "2026" in text
    assert "192.168.1.1" in text
    assert "RESUMEN EJECUTIVO" in text
    assert "Critical: 1" in text
    assert "HALLAZGOS" in text
    assert "F001" in text
    assert "PRÓXIMOS PASOS" in text

def test_report_orders_by_severity():
    scope = ScanScope(target_host="localhost")
    report = SecurityReport(findings=[
        Finding("F001", "Low issue", "Low", "e", "r"),
        Finding("F002", "Critical issue", "Critical", "e", "r"),
    ], scope=scope)
    text = format_report_text(report)
    assert text.index("Critical") < text.index("Low")

def test_report_generator_wraps_agent_output():
    scope = ScanScope(target_host="localhost")
    r = ReportGenerator().from_agent_output("Diagnóstico del agente", scope)
    assert r.scope == scope
    assert r.analysis_text == "Diagnóstico del agente"
    assert r.generated_at is not None
```

- [ ] **Step 2: Escribir test de email**

```python
# cybersec/tests/test_email.py
from unittest.mock import patch, MagicMock
from cybersec.infrastructure.notifiers.email import MailgunNotifier

def test_sends_email_successfully():
    with patch("cybersec.infrastructure.notifiers.email.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        notifier = MailgunNotifier(api_key="key", domain="mg.example.com", sender="sec@example.com")
        result = notifier.send(to="admin@example.com", subject="Reporte", body="Contenido")
        assert result is True
        mock_post.assert_called_once()

def test_returns_false_on_error():
    with patch("cybersec.infrastructure.notifiers.email.requests.post") as mock_post:
        mock_post.side_effect = Exception("network error")
        notifier = MailgunNotifier(api_key="key", domain="mg.example.com", sender="sec@example.com")
        result = notifier.send(to="admin@example.com", subject="Reporte", body="Contenido")
        assert result is False
```

- [ ] **Step 3: Correr — deben fallar**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest tests/test_report.py tests/test_email.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 4: Crear `cybersec/application/report.py`**

```python
from datetime import datetime
from cybersec.domain.entities import ScanScope, Finding, SecurityReport

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def format_report_text(report: SecurityReport) -> str:
    now = report.generated_at or datetime.now()
    host = report.scope.target_host if report.scope else "desconocido"
    s = report.summary()

    lines = [
        "=" * 60,
        f"REPORTE DE SEGURIDAD — {now.strftime('%Y-%m-%d %H:%M')} — {host}",
        "=" * 60,
        "",
        "RESUMEN EJECUTIVO",
        f"  Total hallazgos: {s['total']} (Critical: {s['Critical']}, High: {s['High']}, Medium: {s['Medium']}, Low: {s['Low']})",
        "",
    ]

    sorted_findings = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
    )

    if sorted_findings:
        lines += ["HALLAZGOS", "-" * 40]
        for f in sorted_findings:
            lines += [
                f"  [{f.id}] {f.title}",
                f"  Severidad: {f.severity}",
                f"  Evidencia: {f.evidence}",
                f"  Recomendación: {f.recommendation}",
                "",
            ]
    elif report.analysis_text:
        lines += ["ANÁLISIS DEL AGENTE", "-" * 40, report.analysis_text, ""]

    urgent = [f for f in sorted_findings if f.severity in ("Critical", "High")]
    lines += ["PRÓXIMOS PASOS", "-" * 40]
    if urgent:
        for i, f in enumerate(urgent, 1):
            lines.append(f"  {i}. [{f.severity}] {f.recommendation}")
    else:
        lines.append("  Sin hallazgos críticos o altos que requieran acción inmediata.")

    lines += ["", "=" * 60]
    return "\n".join(lines)


class ReportGenerator:
    def from_agent_output(self, agent_text: str, scope: ScanScope) -> SecurityReport:
        return SecurityReport(
            findings=[],
            scope=scope,
            generated_at=datetime.now(),
            analysis_text=agent_text,
        )
```

- [ ] **Step 5: Crear `cybersec/infrastructure/notifiers/email.py`**

```python
import logging
import requests

logger = logging.getLogger(__name__)


class MailgunNotifier:
    def __init__(self, api_key: str, domain: str, sender: str):
        self._api_key = api_key
        self._domain = domain
        self._sender = sender

    def send(self, to: str, subject: str, body: str) -> bool:
        try:
            resp = requests.post(
                f"https://api.mailgun.net/v3/{self._domain}/messages",
                auth=("api", self._api_key),
                data={"from": self._sender, "to": to, "subject": subject, "text": body},
                timeout=15,
            )
            resp.raise_for_status()
            logger.info(f"Email enviado a {to}")
            return True
        except Exception as e:
            logger.error(f"Error enviando email a {to}: {e}")
            return False
```

- [ ] **Step 6: Correr — deben pasar**

```bash
pytest tests/test_report.py tests/test_email.py -v
```

Expected: `5 passed`

- [ ] **Step 7: Commit**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): ReportGenerator + MailgunNotifier"
```

---

### Task 13: CLI + entry point

**Files:**
- Create: `cybersec/cybersec/cli.py`
- Create: `cybersec/cybersec/__main__.py`

- [ ] **Step 1: Crear `cybersec/__main__.py`**

```python
from cybersec.cli import cli

if __name__ == "__main__":
    cli()
```

- [ ] **Step 2: Crear `cybersec/cli.py`**

```python
import click
from cybersec import config
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_registry
from cybersec.application.agent import SecurityAgent
from cybersec.application.report import ReportGenerator, format_report_text


def _build_adapter(adapter_name: str):
    if adapter_name == "gemini":
        from cybersec.infrastructure.adapters.gemini import GeminiAdapter
        if not config.GEMINI_API_KEY:
            raise click.UsageError("GEMINI_API_KEY no configurada en .env")
        return GeminiAdapter(api_key=config.GEMINI_API_KEY)
    else:
        from cybersec.infrastructure.adapters.openai_compat import OpenAICompatAdapter
        if not config.OPENAI_COMPAT_BASE_URL:
            raise click.UsageError("OPENAI_COMPAT_BASE_URL no configurada en .env")
        return OpenAICompatAdapter(base_url=config.OPENAI_COMPAT_BASE_URL, model=config.OPENAI_COMPAT_MODEL)


@click.group()
def cli():
    """Agente de ciberseguridad — diagnóstico local con IA."""


@cli.command()
@click.option("--host", default="localhost", show_default=True, help="Host a analizar")
@click.option("--log", "logs", multiple=True, help="Archivo de log (repetible). Ej: --log /var/log/auth.log")
@click.option("--code-dir", default=None, help="Directorio de código a analizar")
@click.option("--type", "types", multiple=True,
              type=click.Choice(["network", "logs", "deps", "code", "config"]),
              help="Tipo de análisis (repetible). Default: todos.")
@click.option("--email", default=None, help="Email para recibir el reporte")
@click.option("--adapter", default="gemini", type=click.Choice(["gemini", "openai"]),
              show_default=True, help="Adaptador LLM a usar")
def scan(host, logs, code_dir, types, email, adapter):
    """Ejecuta un análisis de seguridad en el sistema."""
    scope = ScanScope(
        target_host=host,
        log_files=list(logs),
        code_directory=code_dir,
        analysis_types=list(types) or ["network", "logs", "deps", "config"],
        email_report_to=email,
    )

    click.echo(f"\n🔍 Iniciando análisis de seguridad en {host}...")
    click.echo(f"   Análisis: {', '.join(scope.analysis_types)}")
    if logs:
        click.echo(f"   Logs: {', '.join(logs)}")
    click.echo()

    llm = _build_adapter(adapter)
    registry = get_registry()
    agent = SecurityAgent(adapter=llm, tool_registry=registry)

    with click.progressbar(length=1, label="Analizando sistema", show_eta=False) as bar:
        analysis_text = agent.run(scope)
        bar.update(1)

    report = ReportGenerator().from_agent_output(agent_text=analysis_text, scope=scope)
    report_text = format_report_text(report)
    click.echo("\n" + report_text)

    if email:
        from cybersec.infrastructure.notifiers.email import MailgunNotifier
        notifier = MailgunNotifier(
            api_key=config.MAILGUN_API_KEY,
            domain=config.MAILGUN_DOMAIN,
            sender=config.MAILGUN_SENDER_EMAIL,
        )
        if notifier.send(to=email, subject=f"Reporte de Seguridad — {host}", body=report_text):
            click.echo(f"\n✅ Reporte enviado a {email}")
        else:
            click.echo(f"\n⚠️  No se pudo enviar el reporte a {email}")
```

- [ ] **Step 3: Instalar en modo desarrollo y verificar que el CLI arranca**

```bash
cd /home/anuarbarrera/batial/cybersec && pip install -e . -q 2>/dev/null || pip install -r requirements.txt -q
python -m cybersec --help
```

Expected: Ver el menú de ayuda con el comando `scan`.

```bash
python -m cybersec scan --help
```

Expected: Ver las opciones de `scan`.

- [ ] **Step 4: Correr la suite completa**

```bash
cd /home/anuarbarrera/batial/cybersec && pytest -v
```

Expected: Todos los tests en verde (mínimo 30 passed).

- [ ] **Step 5: Commit final**

```bash
cd /home/anuarbarrera/batial && git add cybersec/ && git commit -m "feat(cybersec): CLI entry point with scan command — MVP Fase 1 completo"
```

---

## Self-Review

### Cobertura del PRD

| Requisito PRD | Tarea |
|---|---|
| CLI interactiva | Task 13 — `cli.py` con Click |
| Scope definition (logs, code, tipos) | Task 13 — opciones de `scan` |
| `scan_ports()` | Task 6 |
| `analyze_logs()` | Task 5 |
| `check_dependencies()` | Task 7 |
| `read_code_snippet()` | Task 8 |
| `check_configs()` | Task 9 |
| Reporte estructurado en pantalla | Task 12 — `format_report_text()` |
| Email vía Mailgun | Task 12 — `MailgunNotifier` |
| LLMAdapter base agnóstico | Task 1 — `llm_adapter.py` |
| GeminiAdapter | Task 3 |
| OpenAICompatAdapter (vLLM) | Task 4 |
| Loop agentico | Task 11 — `SecurityAgent` |

### Fuera de alcance (Fase 1)
- Aplicación automática de parches (Fase 2)
- Monitoreo en tiempo real / daemon (Fase 3)
- UI web
- Soporte Windows
