# Pre-fetch determinista de archivos de seguridad obligatorios — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Antes de que el LLM tenga su primer turno en `SecurityAgent.run()`, leer determinísticamente (vía `list_code_files` + `read_code_snippet`) todos los archivos del proyecto que matchean `MANDATORY_FILE_PATTERNS` (settings, config, auth, login, password, credential, docker-compose, Dockerfile, .env*, middleware) e inyectar su contenido como texto en el prompt inicial, eliminando la discrecionalidad del LLM sobre si los lee o no.

**Architecture:** Nuevo método `SecurityAgent._prefetch_mandatory_files(code_directory)` que usa el `tool_registry` existente (mismas tools `list_code_files`/`read_code_snippet` que ya usa el loop agéntico) para producir un bloque de texto con el contenido de esos archivos, trazado con `iteration=0` reutilizando el evento `tool_result` existente. `run()` llama a este método y agrega su resultado al `initial` antes de construir `messages`. Se reescribe la instrucción #2 de `_PROMPT` para reflejar que esos archivos ya vienen incluidos.

**Tech Stack:** Python 3.12, `fnmatch` (stdlib) para el matching de patrones, pytest + `unittest.mock.MagicMock` para tests (mismos patrones que `tests/test_agent.py`).

**Spec de referencia:** `docs/superpowers/specs/2026-06-15-prefetch-archivos-obligatorios-design.md`

**Baseline:** 137/137 tests pasan actualmente (`venv/bin/pytest -q` desde `/home/anuarbarrera/batial/cybersec`).

---

## Task 1: `_prefetch_mandatory_files` — lógica completa con tests

**Files:**
- Modify: `cybersec/cybersec/application/agent.py`
- Test: `cybersec/tests/test_agent.py` (agregar al final del archivo, después de la línea 381)

Todos los comandos de este plan se ejecutan desde `/home/anuarbarrera/batial/cybersec`.

### Ciclo 1 — casos extremos triviales: sin `code_directory`, sin tool `list_code_files`

- [ ] **Step 1: Escribir los tests que fallan**

Agregar al final de `tests/test_agent.py`:

```python
def test_prefetch_returns_empty_when_no_code_directory():
    agent = SecurityAgent(adapter=_adapter(), tool_registry={})
    assert agent._prefetch_mandatory_files(None) == ""


def test_prefetch_returns_empty_when_list_code_files_tool_missing():
    agent = SecurityAgent(adapter=_adapter(), tool_registry={})
    assert agent._prefetch_mandatory_files("/tmp/proyecto") == ""
```

- [ ] **Step 2: Verificar que fallan**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_returns_empty_when_no_code_directory tests/test_agent.py::test_prefetch_returns_empty_when_list_code_files_tool_missing -v`

Expected: ambos tests fallan con `AttributeError: 'SecurityAgent' object has no attribute '_prefetch_mandatory_files'`.

- [ ] **Step 3: Implementación mínima**

En `cybersec/cybersec/application/agent.py`, agregar el método `_prefetch_mandatory_files` a la clase `SecurityAgent`, justo después del método `_trace` (líneas 120-122):

```python
    def _trace(self, event: str, **fields) -> None:
        if self._tracer is not None:
            self._tracer.record(event, **fields)

    def _prefetch_mandatory_files(self, code_directory: Optional[str]) -> str:
        if code_directory is None:
            return ""

        list_tool = self._registry.get("list_code_files")
        if list_tool is None:
            return ""

        return ""
```

- [ ] **Step 4: Verificar que pasan**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_returns_empty_when_no_code_directory tests/test_agent.py::test_prefetch_returns_empty_when_list_code_files_tool_missing -v`

Expected: 2 passed.

### Ciclo 2 — filtra por `MANDATORY_FILE_PATTERNS`, lee cada match y traza ambos pasos

- [ ] **Step 5: Escribir el test que falla**

Agregar al final de `tests/test_agent.py`:

```python
def test_prefetch_filters_reads_and_traces_mandatory_files():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="\n".join([
            "/tmp/proyecto/saas_chatbot/settings.py",
            "/tmp/proyecto/core/tenant_management/services/auth_service.py",
            "/tmp/proyecto/core/auth_config.py",
            "/tmp/proyecto/docker-compose.yml",
            "/tmp/proyecto/core/views.py",
        ]),
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 5},
    )

    def fake_read(file_path="", **kwargs):
        content = f"# {file_path}\n```python\n# contenido de {file_path}\n```"
        return ToolResult(
            content=content, tool_name="read_code_snippet", success=True,
            metadata={"file_path": file_path, "lines": 1, "truncated": False},
        )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.side_effect = fake_read

    tracer = MagicMock()
    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    }, tracer=tracer)
    result = agent._prefetch_mandatory_files("/tmp/proyecto")

    assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in result
    assert "settings.py" in result
    assert "auth_service.py" in result
    assert "auth_config.py" in result
    assert "docker-compose.yml" in result
    assert "core/views.py" not in result
    assert read_tool.execute.call_count == 4

    list_tool.execute.assert_called_once_with(directory="/tmp/proyecto")
    list_content_length = len(list_tool.execute.return_value.content)
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="list_code_files",
        args={"directory": "/tmp/proyecto"}, success=True,
        metadata={"directory": "/tmp/proyecto", "count": 5},
        content_length=list_content_length,
    )
    settings_content = (
        "# /tmp/proyecto/saas_chatbot/settings.py\n"
        "```python\n# contenido de /tmp/proyecto/saas_chatbot/settings.py\n```"
    )
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="read_code_snippet",
        args={"file_path": "/tmp/proyecto/saas_chatbot/settings.py"}, success=True,
        metadata={"file_path": "/tmp/proyecto/saas_chatbot/settings.py", "lines": 1, "truncated": False},
        content_length=len(settings_content),
    )
```

- [ ] **Step 6: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_filters_reads_and_traces_mandatory_files -v`

Expected: FAIL — `assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in ""` (la implementación actual retorna `""` siempre que `list_tool` exista).

- [ ] **Step 7: Implementación**

Agregar los imports `fnmatch` y `os` al inicio de `cybersec/cybersec/application/agent.py` (línea 1):

```python
import fnmatch
import logging
import os
from typing import Callable, Optional
```

Agregar la constante `MANDATORY_FILE_PATTERNS` después de `logger = logging.getLogger(__name__)` (línea 7), antes de `_SEVERITY_CRITERIA`:

```python
logger = logging.getLogger(__name__)

MANDATORY_FILE_PATTERNS = [
    "*settings*", "*config*",
    "*auth*", "*login*", "*password*", "*credential*",
    "docker-compose*", "Dockerfile*", "*.env*",
    "*middleware*",
]
```

Reemplazar el `return ""` final de `_prefetch_mandatory_files` (el del Step 3) por:

```python
        list_result = list_tool.execute(directory=code_directory)
        self._trace(
            "tool_result", iteration=0, name="list_code_files",
            args={"directory": code_directory}, success=list_result.success,
            metadata=list_result.metadata, content_length=len(list_result.content),
        )

        paths = []
        for line in list_result.content.splitlines():
            if not line.startswith("/"):
                continue
            basename = os.path.basename(line).lower()
            if any(fnmatch.fnmatch(basename, pattern.lower()) for pattern in MANDATORY_FILE_PATTERNS):
                paths.append(line)

        read_tool = self._registry.get("read_code_snippet")
        sections = []
        for path in paths:
            result = read_tool.execute(file_path=path)
            self._trace(
                "tool_result", iteration=0, name="read_code_snippet",
                args={"file_path": path}, success=result.success,
                metadata=result.metadata, content_length=len(result.content),
            )
            sections.append(result.content)

        return "ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático, ya leídos):\n\n" + "\n\n".join(sections)
```

- [ ] **Step 8: Verificar que pasa (y que el ciclo 1 sigue pasando)**

Run: `venv/bin/pytest tests/test_agent.py -k prefetch -v`

Expected: 3 passed (los 2 del ciclo 1 + el de este ciclo).

### Ciclo 3 — `list_code_files` falla (`success=False`) → `""`

- [ ] **Step 9: Escribir el test que falla**

```python
def test_prefetch_returns_empty_when_list_code_files_fails():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="Directorio no existe: /tmp/proyecto",
        tool_name="list_code_files", success=False,
        error="Directorio no existe: /tmp/proyecto",
    )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    tracer = MagicMock()
    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    }, tracer=tracer)
    assert agent._prefetch_mandatory_files("/tmp/proyecto") == ""
    read_tool.execute.assert_not_called()
    tracer.record.assert_any_call(
        "tool_result", iteration=0, name="list_code_files",
        args={"directory": "/tmp/proyecto"}, success=False,
        metadata={}, content_length=len("Directorio no existe: /tmp/proyecto"),
    )
```

- [ ] **Step 10: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_returns_empty_when_list_code_files_fails -v`

Expected: FAIL — `assert 'ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático, ya leídos):\n\n' == ''` (sin chequeo de `success`, `paths` queda vacío pero el método igual retorna el encabezado).

- [ ] **Step 11: Implementación**

En `_prefetch_mandatory_files`, justo después del bloque `self._trace("tool_result", iteration=0, name="list_code_files", ...)` agregado en el Ciclo 2, insertar:

```python
        if not list_result.success:
            return ""
```

- [ ] **Step 12: Verificar que pasa**

Run: `venv/bin/pytest tests/test_agent.py -k prefetch -v`

Expected: 4 passed.

### Ciclo 4 — cero archivos matchean los patrones → mensaje explícito

- [ ] **Step 13: Escribir el test que falla**

```python
def test_prefetch_returns_message_when_no_files_match():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/core/views.py\n/tmp/proyecto/core/models.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 2},
    )
    agent = SecurityAgent(adapter=_adapter(), tool_registry={"list_code_files": list_tool})
    result = agent._prefetch_mandatory_files("/tmp/proyecto")
    assert "No se encontraron archivos" in result
```

- [ ] **Step 14: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_returns_message_when_no_files_match -v`

Expected: FAIL — `assert 'No se encontraron archivos' in 'ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático, ya leídos):\n\n'` es `False` (con `paths` vacío, `"\n\n".join([])` es `""`, no contiene ese mensaje).

- [ ] **Step 15: Implementación**

En `_prefetch_mandatory_files`, justo después de construir `paths` (el `for line in list_result.content.splitlines(): ...` del Ciclo 2) y antes de `read_tool = self._registry.get("read_code_snippet")`, insertar:

```python
        if not paths:
            return (
                "ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático):\n\n"
                "No se encontraron archivos que coincidan con los patrones de "
                "seguridad obligatorios en este proyecto."
            )
```

- [ ] **Step 16: Verificar que pasa**

Run: `venv/bin/pytest tests/test_agent.py -k prefetch -v`

Expected: 5 passed.

### Ciclo 5 — `read_code_snippet` falla para un archivo puntual → línea de error, el resto continúa

- [ ] **Step 17: Escribir el test que falla**

```python
def test_prefetch_includes_error_line_when_read_code_snippet_fails():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="\n".join([
            "/tmp/proyecto/saas_chatbot/settings.py",
            "/tmp/proyecto/core/tenant_management/services/auth_service.py",
        ]),
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 2},
    )

    def fake_read(file_path="", **kwargs):
        if "auth_service" in file_path:
            return ToolResult(
                content=f"Archivo no existe: {file_path}",
                tool_name="read_code_snippet", success=False,
                error=f"Archivo no existe: {file_path}",
            )
        return ToolResult(
            content=f"# {file_path}\n```python\nDEBUG = True\n```",
            tool_name="read_code_snippet", success=True,
            metadata={"file_path": file_path, "lines": 1, "truncated": False},
        )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.side_effect = fake_read

    agent = SecurityAgent(adapter=_adapter(), tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    })
    result = agent._prefetch_mandatory_files("/tmp/proyecto")

    assert "settings.py" in result
    assert "DEBUG = True" in result
    assert "error al leer este archivo" in result
    assert "auth_service.py" in result
```

- [ ] **Step 18: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_includes_error_line_when_read_code_snippet_fails -v`

Expected: FAIL — `assert "error al leer este archivo" in result` es `False` (el contenido del archivo fallido se agrega tal cual: `"Archivo no existe: ..."`, sin esa frase).

- [ ] **Step 19: Implementación**

En `_prefetch_mandatory_files`, dentro del `for path in paths:` del Ciclo 2, reemplazar:

```python
            sections.append(result.content)
```

por:

```python
            if result.success:
                sections.append(result.content)
            else:
                sections.append(f"# {path}\n(error al leer este archivo: {result.content})")
```

- [ ] **Step 20: Verificar que pasa**

Run: `venv/bin/pytest tests/test_agent.py -k prefetch -v`

Expected: 6 passed.

### Ciclo 6 — `read_code_snippet` no está en el registry (registry parcial)

- [ ] **Step 21: Escribir el test que falla**

```python
def test_prefetch_handles_missing_read_code_snippet_tool():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/saas_chatbot/settings.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 1},
    )
    agent = SecurityAgent(adapter=_adapter(), tool_registry={"list_code_files": list_tool})
    result = agent._prefetch_mandatory_files("/tmp/proyecto")
    assert "settings.py" in result
    assert "error al leer este archivo" in result
```

- [ ] **Step 22: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_prefetch_handles_missing_read_code_snippet_tool -v`

Expected: ERROR — `AttributeError: 'NoneType' object has no attribute 'execute'` (`read_tool` es `None` porque el registry no tiene `read_code_snippet`, y el código llama `read_tool.execute(...)` sin verificar).

- [ ] **Step 23: Implementación**

En `_prefetch_mandatory_files`, dentro del `for path in paths:`, justo antes de `result = read_tool.execute(file_path=path)`, insertar:

```python
            if read_tool is None:
                sections.append(f"# {path}\n(error al leer este archivo: herramienta read_code_snippet no disponible)")
                continue
```

- [ ] **Step 24: Verificar que pasa**

Run: `venv/bin/pytest tests/test_agent.py -k prefetch -v`

Expected: 7 passed.

### Cierre de Task 1

- [ ] **Step 25: Correr toda la suite**

Run: `venv/bin/pytest -q`

Expected: `144 passed` (137 existentes + 7 nuevos de `_prefetch_mandatory_files`).

- [ ] **Step 26: Commit**

```bash
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "feat: agregar _prefetch_mandatory_files para leer archivos de seguridad obligatorios"
```

---

## Task 2: Integrar el pre-fetch en `run()`

**Files:**
- Modify: `cybersec/cybersec/application/agent.py:129-136`
- Test: `cybersec/tests/test_agent.py` (agregar al final del archivo)

- [ ] **Step 1: Escribir el test que falla**

Agregar al final de `tests/test_agent.py`:

```python
def test_run_includes_prefetched_mandatory_files_in_initial_prompt():
    list_tool = MagicMock()
    list_tool.name = "list_code_files"
    list_tool.execute.return_value = ToolResult(
        content="/tmp/proyecto/core/tenant_management/services/auth_service.py",
        tool_name="list_code_files", success=True,
        metadata={"directory": "/tmp/proyecto", "count": 1},
    )
    read_tool = MagicMock()
    read_tool.name = "read_code_snippet"
    read_tool.execute.return_value = ToolResult(
        content=(
            "# /tmp/proyecto/core/tenant_management/services/auth_service.py\n"
            "```python\n'password': password,\n```"
        ),
        tool_name="read_code_snippet", success=True,
        metadata={
            "file_path": "/tmp/proyecto/core/tenant_management/services/auth_service.py",
            "lines": 1, "truncated": False,
        },
    )
    adapter = _adapter(Message(role="assistant", content="Sistema seguro."))
    agent = SecurityAgent(adapter=adapter, tool_registry={
        "list_code_files": list_tool, "read_code_snippet": read_tool,
    })
    agent.run(ScanScope("localhost", code_directory="/tmp/proyecto"))

    sent_messages = adapter.chat.call_args_list[0][0][0]
    assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in sent_messages[0].content
    assert "auth_service.py" in sent_messages[0].content
    assert "'password': password," in sent_messages[0].content
```

- [ ] **Step 2: Verificar que falla**

Run: `venv/bin/pytest tests/test_agent.py::test_run_includes_prefetched_mandatory_files_in_initial_prompt -v`

Expected: FAIL — `assert "ARCHIVOS DE SEGURIDAD OBLIGATORIOS" in sent_messages[0].content` es `False` (`run()` todavía no llama a `_prefetch_mandatory_files`).

- [ ] **Step 3: Implementación**

En `cybersec/cybersec/application/agent.py`, dentro de `run()`, reemplazar (líneas 129-136):

```python
        initial = _PROMPT.format(
            host=scope.target_host,
            types=", ".join(scope.analysis_types) or "general",
            logs=", ".join(scope.log_files) or "ninguno",
            code=scope.code_directory or "ninguno",
            hours=scope.time_range_hours,
        )
        messages: list[Message] = [Message(role="user", content=initial)]
        tools = get_tool_schemas()
```

por:

```python
        initial = _PROMPT.format(
            host=scope.target_host,
            types=", ".join(scope.analysis_types) or "general",
            logs=", ".join(scope.log_files) or "ninguno",
            code=scope.code_directory or "ninguno",
            hours=scope.time_range_hours,
        )
        prefetch_text = self._prefetch_mandatory_files(scope.code_directory)
        if prefetch_text:
            initial += "\n\n" + prefetch_text
        messages: list[Message] = [Message(role="user", content=initial)]
        tools = get_tool_schemas()
```

- [ ] **Step 4: Verificar que pasa**

Run: `venv/bin/pytest tests/test_agent.py::test_run_includes_prefetched_mandatory_files_in_initial_prompt -v`

Expected: 1 passed.

- [ ] **Step 5: Correr toda la suite (no-regresión)**

Run: `venv/bin/pytest -q`

Expected: `145 passed`. En particular, confirmar que pasan los tests que usan `code_directory="/tmp/proyecto"` con `tool_registry={}` (`test_initial_prompt_mentions_list_code_files_tool`, `test_initial_prompt_mentions_scan_code_security_tool`, `test_initial_prompt_lists_mandatory_security_file_patterns`, `test_agent_traces_run_start_with_scope_info`) — deben seguir pasando sin cambios, porque `_prefetch_mandatory_files` retorna `""` cuando `tool_registry` no tiene `list_code_files`.

- [ ] **Step 6: Commit**

```bash
git add cybersec/cybersec/application/agent.py cybersec/tests/test_agent.py
git commit -m "feat: inyectar el pre-fetch de archivos obligatorios en el prompt inicial"
```

---

## Task 3: Reescribir la instrucción #2 de `_PROMPT`

**Files:**
- Modify: `cybersec/cybersec/application/agent.py:59-68`

No se agregan tests nuevos: los tests existentes `test_initial_prompt_mentions_list_code_files_tool`,
`test_initial_prompt_mentions_scan_code_security_tool` y
`test_initial_prompt_lists_mandatory_security_file_patterns` (en `tests/test_agent.py`,
líneas 90-110) ya verifican el contenido textual requerido y sirven como
especificación de esta reescritura.

- [ ] **Step 1: Reescribir la instrucción #2**

En `cybersec/cybersec/application/agent.py`, dentro de `_PROMPT`, reemplazar las líneas 59-68:

```python
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
```

por:

```python
2. A continuación se incluye el contenido de los archivos de seguridad
   obligatorios del proyecto (settings, config, auth, login, password,
   credential, docker-compose, Dockerfile, .env*, middleware), ya leídos
   automáticamente — no necesitas volver a llamar a read_code_snippet sobre
   ellos. Analiza su contenido como parte de tu evaluación de seguridad.
   Además, usa list_code_files y read_code_snippet para revisar cualquier
   otro archivo que consideres relevante desde el punto de vista de
   seguridad (manejo de inputs, sesiones, permisos, lógica de negocio).
```

- [ ] **Step 2: Verificar que los tests existentes y nuevos siguen pasando**

Run: `venv/bin/pytest tests/test_agent.py -v -k "prompt or prefetch"`

Expected: todos los tests con "prompt" o "prefetch" en el nombre pasan, incluyendo
`test_initial_prompt_mentions_list_code_files_tool`,
`test_initial_prompt_mentions_scan_code_security_tool` y
`test_initial_prompt_lists_mandatory_security_file_patterns`.

- [ ] **Step 3: Correr toda la suite**

Run: `venv/bin/pytest -q`

Expected: `145 passed`.

- [ ] **Step 4: Commit**

```bash
git add cybersec/cybersec/application/agent.py
git commit -m "docs: reescribir instruccion de archivos obligatorios para reflejar el pre-fetch"
```

---

## Validación final (manual, post-merge — no es una tarea de subagente)

Esta sección requiere credenciales reales de Gemini (`.env`) y hace llamadas a
la API real, por lo que la ejecuta el usuario/orquestador directamente, no un
subagente en un worktree aislado.

1. Activar el entorno y correr un scan real con trace:

```bash
cd /home/anuarbarrera/batial/cybersec
source venv/bin/activate
python3 -m cybersec scan --code-dir /home/anuarbarrera/agente-cosmic --trace-dir /tmp/cybersec-traces
```

2. Analizar el trace más reciente:

```bash
./analiza_traces.sh /tmp/cybersec-traces
```

3. Confirmar en la salida:
   - Bajo "Archivos leídos con read_code_snippet" aparece una entrada con
     `"iteration":0` y `"file"` conteniendo `auth_service.py` (el pre-fetch
     determinista lo garantiza, independientemente de lo que decida el LLM
     en el loop).
   - "H1: ¿se leyó auth_service.py?" muestra esa entrada (ya no "No se leyó
     ningún archivo *auth_service*").
   - "H2: ¿el reporte final menciona el hallazgo?" encuentra coincidencias
     (`auth_service`, `password` o `Critical`) en `audit_result.report`.

Si el paso 3 (H2) sigue sin match pese a que el pre-fetch funcionó (H1 OK),
el problema pasa de "cobertura de archivos" a "razonamiento del LLM sobre
contenido ya presente" — un problema distinto, fuera del alcance de este plan,
que requeriría una nueva sesión de diagnóstico.
