# Trace de diagnóstico por corrida (H2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Instrumentar `SecurityAgent` para que, de forma opcional (`--trace-dir`), cada corrida del CLI genere un archivo JSONL con un evento por respuesta del LLM y por tool call, suficiente para diagnosticar H2 (detección intermitente del hallazgo Critical en `auth_service.py`).

**Architecture:** Nueva clase `RunTracer` (infraestructura) escribe JSONL a un archivo. `SecurityAgent` recibe `tracer: RunTracer = None` opcional y llama a `self._trace(event, **fields)` en 5 puntos de `run()`/`_audit()`. `cli.py` añade `--trace-dir PATH`; si se pasa, abre un `RunTracer` con `contextlib.nullcontext()` como alternativa cuando no se pasa (`tracer=None` uniforme).

**Tech Stack:** Python stdlib (`json`, `pathlib`, `contextlib`, `datetime`), pytest, `unittest.mock.MagicMock`, `click.testing.CliRunner`.

Spec de referencia: `docs/superpowers/specs/2026-06-14-trace-diagnostico-agente-h2-design.md`

---

## File Structure

- Create: `cybersec/infrastructure/tracing.py` — clase `RunTracer` (JSONL writer, context manager).
- Create: `tests/test_tracing.py` — tests de `RunTracer`.
- Modify: `cybersec/application/agent.py` — param `tracer`, helper `_trace`, 5 puntos de instrumentación.
- Modify: `tests/test_agent.py` — tests de los 5 eventos trazados.
- Modify: `cybersec/cli.py` — opción `--trace-dir`, wiring de `RunTracer`.
- Modify: `tests/test_cli.py` — tests del wiring CLI.

**Baseline actual:** 122 tests pasando (verificar con `cd /home/anuarbarrera/batial/cybersec && python -m pytest -q | tail -1` antes de empezar — si el número difiere de 122, usar el real como base para los conteos esperados de cada tarea).

---

### Task 1: `RunTracer` — escritura de eventos JSONL

**Files:**
- Create: `cybersec/infrastructure/tracing.py`
- Test: `tests/test_tracing.py`

- [ ] **Step 1: Escribir los tests (fallarán por `ModuleNotFoundError`)**

Crear `tests/test_tracing.py`:

```python
# cybersec/tests/test_tracing.py
import json
from cybersec.infrastructure.tracing import RunTracer


def test_record_writes_json_line_with_event_and_fields(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("run_start", host="localhost", max_iterations=10)
    tracer.close()

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event"] == "run_start"
    assert entry["host"] == "localhost"
    assert entry["max_iterations"] == 10
    assert "ts" in entry


def test_record_writes_one_line_per_call(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("run_start", host="localhost")
    tracer.record("loop_end", reason="no_tool_calls", iteration=1)
    tracer.close()

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "run_start"
    assert json.loads(lines[1])["event"] == "loop_end"


def test_record_handles_non_serializable_values(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("tool_call", payload=b"\x00\x01")
    tracer.close()

    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    assert entry["event"] == "tool_call"
    assert "payload" in entry


def test_context_manager_closes_file(tmp_path):
    path = tmp_path / "trace.jsonl"
    with RunTracer(path) as tracer:
        tracer.record("run_start", host="localhost")

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "run_start"
```

- [ ] **Step 2: Verificar que fallan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_tracing.py -v`
Expected: 4 errores `ModuleNotFoundError: No module named 'cybersec.infrastructure.tracing'`

- [ ] **Step 3: Implementar `RunTracer`**

Crear `cybersec/infrastructure/tracing.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path


class RunTracer:
    """Escribe un evento JSON por línea a un archivo, para diagnóstico de corridas del agente."""

    def __init__(self, path):
        self._file = open(Path(path), "w", encoding="utf-8")

    def record(self, event: str, **fields) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        self._file.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
```

- [ ] **Step 4: Verificar que pasan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_tracing.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/infrastructure/tracing.py cybersec/tests/test_tracing.py
git commit -m "$(cat <<'EOF'
feat: añadir RunTracer para trace JSONL de diagnóstico

Escribe un evento JSON por línea (timestamp + tipo + campos) a un
archivo, con flush inmediato y soporte de context manager. Base para
instrumentar SecurityAgent.run() y diagnosticar H2.
EOF
)"
```

---

### Task 2: Inyectar `tracer` en `SecurityAgent` y trazar `run_start`

**Files:**
- Modify: `cybersec/application/agent.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Escribir el test (fallará)**

Añadir al final de `tests/test_agent.py`:

```python
def test_agent_traces_run_start_with_scope_info():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(
        ScanScope("localhost", code_directory="/tmp/proyecto",
                  analysis_types=["code"], log_files=["/var/log/auth.log"])
    )
    tracer.record.assert_any_call(
        "run_start",
        host="localhost",
        code_directory="/tmp/proyecto",
        analysis_types=["code"],
        log_files=["/var/log/auth.log"],
        max_iterations=10,
    )
```

- [ ] **Step 2: Verificar que falla**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py::test_agent_traces_run_start_with_scope_info -v`
Expected: FAIL con `TypeError: __init__() got an unexpected keyword argument 'tracer'`

- [ ] **Step 3: Implementar**

En `cybersec/application/agent.py`, modificar la clase `SecurityAgent` (líneas 111-117 originalmente):

```python
class SecurityAgent:
    def __init__(self, adapter: LLMAdapter, tool_registry: dict, max_iterations: int = 10,
                 audit_adapter: LLMAdapter = None, tracer=None):
        self._adapter = adapter
        self._registry = tool_registry
        self._max_iterations = max_iterations
        self._audit_adapter = audit_adapter
        self._tracer = tracer

    def _trace(self, event: str, **fields) -> None:
        if self._tracer is not None:
            self._tracer.record(event, **fields)
```

Y en `run()`, justo después de `tools = get_tool_schemas()` (línea 132 originalmente), antes del `for i in range(self._max_iterations):`:

```python
        tools = get_tool_schemas()

        self._trace(
            "run_start",
            host=scope.target_host,
            code_directory=scope.code_directory,
            analysis_types=scope.analysis_types,
            log_files=scope.log_files,
            max_iterations=self._max_iterations,
        )

        for i in range(self._max_iterations):
```

- [ ] **Step 4: Verificar que pasa (y que nada se rompe)**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py -v`
Expected: todos los tests de `test_agent.py` pasan (22 anteriores + 1 nuevo = 23), sin fallos.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "$(cat <<'EOF'
feat: inyectar tracer opcional en SecurityAgent y trazar run_start

SecurityAgent acepta tracer: RunTracer = None (igual patrón que
audit_adapter). _trace() no hace nada si tracer es None, por lo que
los tests existentes no requieren cambios. Primer evento: run_start
con el scope completo de la corrida.
EOF
)"
```

---

### Task 3: Trazar `llm_response` por iteración

**Files:**
- Modify: `cybersec/application/agent.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Escribir el test (fallará)**

Añadir al final de `tests/test_agent.py`:

```python
def test_agent_traces_llm_response_with_tool_calls():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "check_configs", "args": {"path": "/etc/ssh"}}]),
        Message(role="assistant", content="2 problemas en SSH encontrados."),
    )
    tool = _tool("check_configs", "PermitRootLogin yes")
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"check_configs": tool}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    tracer.record.assert_any_call(
        "llm_response",
        iteration=1,
        has_tool_calls=True,
        tool_calls=[{"name": "check_configs", "args": {"path": "/etc/ssh"}}],
        content_preview="",
    )
    tracer.record.assert_any_call(
        "llm_response",
        iteration=2,
        has_tool_calls=False,
        tool_calls=[],
        content_preview="2 problemas en SSH encontrados.",
    )
```

- [ ] **Step 2: Verificar que falla**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py::test_agent_traces_llm_response_with_tool_calls -v`
Expected: FAIL — `tracer.record` no fue llamado con `"llm_response"` (AssertionError de `assert_any_call`).

- [ ] **Step 3: Implementar**

En `run()`, justo después de `response = self._adapter.chat(messages, tools=tools)` y antes de `if not response.tool_calls:`:

```python
            response = self._adapter.chat(messages, tools=tools)

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
```

- [ ] **Step 4: Verificar que pasa**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py -v`
Expected: 23 anteriores + 1 nuevo = 24 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "$(cat <<'EOF'
feat: trazar llm_response por iteración del agente

Cada respuesta del LLM se registra con su número de iteración,
si trae tool_calls (nombre+args, sin thought_signature) y un
preview de 200 chars del content. Permite ver, por corrida, en
qué iteración se decidió leer cada archivo.
EOF
)"
```

---

### Task 4: Trazar `tool_result` por cada tool ejecutada

**Files:**
- Modify: `cybersec/application/agent.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Escribir los tests (fallarán)**

Añadir al final de `tests/test_agent.py`:

```python
def test_agent_traces_tool_result_with_metadata():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[
            {"name": "read_code_snippet", "args": {"file_path": "/tmp/auth_service.py"}}
        ]),
        Message(role="assistant", content="Listo."),
    )
    content = "# /tmp/auth_service.py\n```python\npassword = 'x'\n```"
    tool = MagicMock()
    tool.name = "read_code_snippet"
    tool.execute.return_value = ToolResult(
        content=content, tool_name="read_code_snippet", success=True,
        metadata={"file_path": "/tmp/auth_service.py", "lines": 3, "truncated": False},
    )
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"read_code_snippet": tool}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    tracer.record.assert_any_call(
        "tool_result",
        iteration=1,
        name="read_code_snippet",
        args={"file_path": "/tmp/auth_service.py"},
        success=True,
        metadata={"file_path": "/tmp/auth_service.py", "lines": 3, "truncated": False},
        content_length=len(content),
    )


def test_agent_traces_tool_result_for_unknown_tool():
    adapter = _adapter(
        Message(role="assistant", content="", tool_calls=[{"name": "ghost_tool", "args": {}}]),
        Message(role="assistant", content="Listo."),
    )
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer)
    agent.run(ScanScope("localhost"))

    expected_content = "Herramienta 'ghost_tool' no disponible."
    tracer.record.assert_any_call(
        "tool_result",
        iteration=1,
        name="ghost_tool",
        args={},
        success=False,
        metadata={},
        content_length=len(expected_content),
    )
```

- [ ] **Step 2: Verificar que fallan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py::test_agent_traces_tool_result_with_metadata tests/test_agent.py::test_agent_traces_tool_result_for_unknown_tool -v`
Expected: ambos FAIL — `tracer.record` no fue llamado con `"tool_result"`.

- [ ] **Step 3: Implementar**

En `run()`, reemplazar el bloque del loop de tool calls (que actualmente es):

```python
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
```

por:

```python
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
```

- [ ] **Step 4: Verificar que pasan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py -v`
Expected: 24 anteriores + 2 nuevos = 26 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "$(cat <<'EOF'
feat: trazar tool_result con metadata por cada tool call

Cada ejecución de tool registra nombre, args, success, el metadata
del ToolResult (ej. file_path/lines/truncated de read_code_snippet,
directory/count de list_code_files) y la longitud del contenido.
Herramientas desconocidas o que lanzan excepción trazan
success=False, metadata={}.
EOF
)"
```

---

### Task 5: Trazar `loop_end` (motivo de fin del loop)

**Files:**
- Modify: `cybersec/application/agent.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Escribir los tests (fallarán)**

Añadir al final de `tests/test_agent.py`:

```python
def test_agent_traces_loop_end_reason_no_tool_calls():
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    tracer.record.assert_any_call("loop_end", reason="no_tool_calls", iteration=1)


def test_agent_traces_loop_end_reason_max_iterations():
    loop_msg = Message(role="assistant", content="", tool_calls=[{"name": "scan_ports", "args": {"host": "localhost"}}])
    final_msg = Message(role="assistant", content="Análisis parcial.")
    adapter = _adapter(*([loop_msg] * 3 + [final_msg]))
    tool = _tool("scan_ports", "22/tcp open")
    tracer = MagicMock()
    agent = SecurityAgent(adapter=adapter, tool_registry={"scan_ports": tool}, max_iterations=3, tracer=tracer)
    agent.run(ScanScope("localhost"))
    tracer.record.assert_any_call("loop_end", reason="max_iterations", iteration=3)
```

- [ ] **Step 2: Verificar que fallan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py::test_agent_traces_loop_end_reason_no_tool_calls tests/test_agent.py::test_agent_traces_loop_end_reason_max_iterations -v`
Expected: ambos FAIL — `tracer.record` no fue llamado con `"loop_end"`.

- [ ] **Step 3: Implementar**

Dos puntos en `run()`. Primero, dentro de `if not response.tool_calls:` (actualmente):

```python
            if not response.tool_calls:
                report = response.content or "(sin respuesta)"
                return self._audit(messages, response, report, notify)
```

cambia a:

```python
            if not response.tool_calls:
                report = response.content or "(sin respuesta)"
                self._trace("loop_end", reason="no_tool_calls", iteration=i + 1)
                return self._audit(messages, response, report, notify)
```

Segundo, justo después de que termina el `for i in range(self._max_iterations):` (actualmente):

```python
        notify("Generando reporte final...")
        messages.append(Message(role="user", content=_FINAL_REPORT_PROMPT))
```

cambia a:

```python
        self._trace("loop_end", reason="max_iterations", iteration=self._max_iterations)
        notify("Generando reporte final...")
        messages.append(Message(role="user", content=_FINAL_REPORT_PROMPT))
```

- [ ] **Step 4: Verificar que pasan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py -v`
Expected: 26 anteriores + 2 nuevos = 28 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "$(cat <<'EOF'
feat: trazar loop_end con el motivo de fin del loop del agente

Distingue si el agente terminó porque el LLM dejó de pedir tool
calls (no_tool_calls, caso normal) o porque se agotó
max_iterations — clave para descartar la hipótesis de presupuesto
de iteraciones en H2.
EOF
)"
```

---

### Task 6: Trazar `audit_result`

**Files:**
- Modify: `cybersec/application/agent.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Escribir los tests (fallarán)**

Añadir al final de `tests/test_agent.py`:

```python
def test_agent_traces_audit_result_on_success():
    first_response = Message(role="assistant", content="Reporte inicial.")
    audit_response = Message(role="assistant", content="Reporte auditado.")
    adapter = _adapter(first_response, audit_response)
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    tracer.record.assert_any_call("audit_result", success=True, report="Reporte auditado.")


def test_agent_traces_audit_result_on_failure():
    first_response = Message(role="assistant", content="Reporte inicial.")
    adapter = _adapter(first_response, RuntimeError("auditor no disponible"))
    tracer = MagicMock()
    SecurityAgent(adapter=adapter, tool_registry={}, tracer=tracer).run(ScanScope("localhost"))
    tracer.record.assert_any_call("audit_result", success=False, report="Reporte inicial.")
```

- [ ] **Step 2: Verificar que fallan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py::test_agent_traces_audit_result_on_success tests/test_agent.py::test_agent_traces_audit_result_on_failure -v`
Expected: ambos FAIL — `tracer.record` no fue llamado con `"audit_result"`.

- [ ] **Step 3: Implementar**

En `_audit()`, el bloque actual:

```python
        adapter = self._audit_adapter or self._adapter
        try:
            audit_response = adapter.chat(audit_messages)
            return audit_response.content or report
        except Exception:
            logger.exception("Error en la auditoría del reporte, se conserva el original")
            return report
```

cambia a:

```python
        adapter = self._audit_adapter or self._adapter
        try:
            audit_response = adapter.chat(audit_messages)
            result = audit_response.content or report
            self._trace("audit_result", success=True, report=result)
            return result
        except Exception:
            logger.exception("Error en la auditoría del reporte, se conserva el original")
            self._trace("audit_result", success=False, report=report)
            return report
```

- [ ] **Step 4: Verificar que pasan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_agent.py -v`
Expected: 28 anteriores + 2 nuevos = 30 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "$(cat <<'EOF'
feat: trazar audit_result al cerrar el paso de auditoría

Registra si la auditoría tuvo éxito y el reporte final resultante
(el mismo texto que ya se imprime por stdout, sin exposición
adicional). Permite correlacionar, por corrida, si el hallazgo de
auth_service.py terminó mencionado en el reporte final.
EOF
)"
```

---

### Task 7: `--trace-dir` en el CLI

**Files:**
- Modify: `cybersec/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Escribir los tests (fallarán)**

Añadir al final de `tests/test_cli.py`:

```python
from click.testing import CliRunner


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
def test_scan_creates_trace_file_when_trace_dir_given(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada."
    )
    mock_agent_cls.return_value = mock_agent

    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--trace-dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    trace_files = list(tmp_path.glob("run-*.jsonl"))
    assert len(trace_files) == 1
    _, kwargs = mock_agent_cls.call_args
    assert kwargs["tracer"] is not None


@patch("cybersec.cli.check_preconditions", return_value=[])
@patch("cybersec.cli.get_registry", return_value={})
@patch("cybersec.cli._build_adapter")
@patch("cybersec.cli.SecurityAgent")
def test_scan_does_not_create_trace_file_by_default(
    mock_agent_cls, mock_build_adapter, mock_get_registry, mock_check, tmp_path
):
    mock_agent = MagicMock()
    mock_agent.run.return_value = (
        "Reporte.\nHALLAZGOS_JSON:\n```json\n[]\n```\nPRÓXIMOS PASOS:\n1. Nada."
    )
    mock_agent_cls.return_value = mock_agent

    from cybersec.cli import cli
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])

    assert result.exit_code == 0, result.output
    _, kwargs = mock_agent_cls.call_args
    assert kwargs["tracer"] is None
```

Nota: `tests/test_cli.py` ya importa `from unittest.mock import patch` — añadir también `MagicMock` a ese import (`from unittest.mock import patch, MagicMock`).

- [ ] **Step 2: Verificar que fallan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest tests/test_cli.py -v`
Expected: los 2 tests nuevos fallan — `Error: No such option: --trace-dir` (exit_code != 0) y/o `KeyError: 'tracer'` al inspeccionar `kwargs`.

- [ ] **Step 3: Implementar**

En `cybersec/cli.py`, añadir imports al inicio del archivo (antes de `import click`):

```python
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

import click
from cybersec import config
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.preconditions import check_preconditions
from cybersec.infrastructure.tools.registry import get_registry
from cybersec.infrastructure.tracing import RunTracer
from cybersec.application.agent import SecurityAgent
from cybersec.application.report import ReportGenerator, format_report_text
```

Añadir la opción `--trace-dir` al decorador de `scan` (después de `--adapter`):

```python
@click.option("--adapter", default="gemini", type=click.Choice(["gemini", "openai"]),
              show_default=True, help="Adaptador LLM a usar")
@click.option("--trace-dir", default=None,
              help="Directorio donde guardar un trace JSONL de la corrida (diagnóstico)")
def scan(host, logs, code_dir, types, email, adapter, trace_dir):
```

Reemplazar el bloque de construcción/ejecución del agente (actualmente):

```python
    llm = _build_adapter(adapter)
    audit_llm = _build_adapter(adapter, model=config.GEMINI_AUDIT_MODEL, temperature=0.0) if adapter == "gemini" else None
    registry = get_registry()
    agent = SecurityAgent(adapter=llm, tool_registry=registry, audit_adapter=audit_llm)

    # Estimación de pasos: hasta max_iterations del loop + 1 paso de auditoría final.
    # Si el agente termina antes, la barra se completa al 100% al finalizar.
    total_steps = 11
    with click.progressbar(length=total_steps, label="Analizando sistema",
                            item_show_func=lambda step: step or "", show_eta=False) as bar:
        analysis_text = agent.run(scope, on_progress=lambda step: bar.update(1, current_item=step))
        bar.update(max(0, bar.length - bar.pos), current_item="Completado")
```

por:

```python
    llm = _build_adapter(adapter)
    audit_llm = _build_adapter(adapter, model=config.GEMINI_AUDIT_MODEL, temperature=0.0) if adapter == "gemini" else None
    registry = get_registry()

    trace_cm = nullcontext()
    if trace_dir:
        Path(trace_dir).mkdir(parents=True, exist_ok=True)
        trace_path = Path(trace_dir) / f"run-{datetime.now().strftime('%Y%m%dT%H%M%S')}.jsonl"
        trace_cm = RunTracer(trace_path)

    with trace_cm as tracer:
        agent = SecurityAgent(adapter=llm, tool_registry=registry, audit_adapter=audit_llm, tracer=tracer)

        # Estimación de pasos: hasta max_iterations del loop + 1 paso de auditoría final.
        # Si el agente termina antes, la barra se completa al 100% al finalizar.
        total_steps = 11
        with click.progressbar(length=total_steps, label="Analizando sistema",
                                item_show_func=lambda step: step or "", show_eta=False) as bar:
            analysis_text = agent.run(scope, on_progress=lambda step: bar.update(1, current_item=step))
            bar.update(max(0, bar.length - bar.pos), current_item="Completado")
```

El resto de la función (`report = ReportGenerator()...` en adelante) queda igual, fuera del bloque `with trace_cm as tracer:`.

- [ ] **Step 4: Verificar que pasan**

Run: `cd /home/anuarbarrera/batial/cybersec && python -m pytest -v`
Expected: 30 anteriores + 2 nuevos = 32 nuevos desde el baseline de esta plan → total = baseline_inicial + 14. Si el baseline era 122, esperar **136 passed**.

- [ ] **Step 5: Commit**

```bash
cd /home/anuarbarrera/batial
git add cybersec/cybersec/cli.py cybersec/tests/test_cli.py
git commit -m "$(cat <<'EOF'
feat: añadir --trace-dir al comando scan

Opción opcional que, si se pasa, escribe un run-<timestamp>.jsonl
con el trace de la corrida (RunTracer) en el directorio indicado.
Sin la opción, tracer=None y no se genera ningún archivo (cero
overhead). Cierra la instrumentación de H2: ya es posible correr
el CLI varias veces con --trace-dir y comparar los .jsonl.
EOF
)"
```

---

## Validación final (no es un task de código)

Tras el Task 7, para empezar a recolectar datos de H2:

```bash
cd /home/anuarbarrera/batial/cybersec
python -m cybersec.cli scan --code-dir /home/anuarbarrera/agente-cosmic \
  --trace-dir ./traces --type code
```

Repetir 2-3 veces y luego inspeccionar, por ejemplo:

```bash
grep -h '"name": "read_code_snippet"' traces/*.jsonl | grep -o '"file_path"[^,}]*' 
grep -h '"event": "loop_end"' traces/*.jsonl
grep -h '"event": "audit_result"' traces/*.jsonl | python -c "import sys,json; [print(json.loads(l)['success']) for l in sys.stdin]"
```

Esto es trabajo de diagnóstico de seguimiento (fuera de esta plan), descrito en la sección "Seguimiento" de la spec.
