# Trace de diagnóstico por corrida (H2) — Spec

## Contexto

El agente de ciberseguridad (`cybersec/`) tiene un hallazgo Critical conocido en
`agente-cosmic/.../auth_service.py` (password en texto plano persistido) que
detecta de forma **intermitente** entre corridas, sin cambios de código
relevantes. El plan `2026-06-14-criterios-severidad-y-auditoria-deterministica.md`
ya resolvió el problema de severidad/determinismo (122/122 tests, validado),
pero la validación en vivo (3 corridas) mostró 0/3 detecciones — y el usuario
reporta que, en corridas posteriores a distintas horas, una sí detectó el
hallazgo y otra no.

Sin datos, no se puede distinguir entre tres hipótesis:

1. El agente **nunca llama** a `read_code_snippet` sobre `auth_service.py` en
   esa corrida (problema de cobertura de archivos / tools).
2. El agente **lee el archivo pero el LLM no lo considera** relevante al
   generar `HALLAZGOS_JSON` (problema de razonamiento del modelo).
3. El loop **agota `max_iterations`** antes de llegar a leer ese archivo
   (problema de presupuesto de iteraciones).

**Objetivo de esta spec:** instrumentar `SecurityAgent` para que cada corrida
del CLI pueda, opcionalmente, generar un archivo de traza estructurado que
permita responder estas tres preguntas inspeccionando varias corridas. El
diagnóstico/arreglo de H2 en sí mismo es un trabajo de seguimiento que
depende de los datos que produzca esta instrumentación — **no** es parte de
esta spec.

## No-objetivos

- No se intenta arreglar H2 en esta spec (eso depende de los datos
  recolectados).
- No se cambia el comportamiento del CLI cuando no se pasa `--trace-dir`
  (cero overhead, sin archivos nuevos).
- No se añade manejo de errores para fallos de E/S del propio trace (disco
  lleno, permisos) más allá de dejar que la excepción se propague — ver
  "Manejo de errores".

## Arquitectura

```
cli.py (scan)
  --trace-dir PATH (opcional)
       │
       ▼
  RunTracer(trace_dir/run-<timestamp>.jsonl)   [infrastructure/tracing.py]
       │  (inyectado)
       ▼
  SecurityAgent(tracer=...)                     [application/agent.py]
       │  self._trace(event, **fields) en puntos clave de run()/_audit()
       ▼
  run-<timestamp>.jsonl  (1 evento JSON por línea)
```

### `cybersec/infrastructure/tracing.py` (nuevo)

```python
import json
from datetime import datetime, timezone
from pathlib import Path


class RunTracer:
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

- `flush()` tras cada escritura: si el proceso se cuelga o tarda mucho, el
  trace parcial queda en disco igual.
- `default=str` en `json.dumps`: red de seguridad por si algún campo no
  serializable se filtra (ej. `bytes` de `thought_signature` de Gemini 3.x),
  aunque el esquema de eventos los excluye explícitamente (ver abajo).

### `cybersec/application/agent.py` (modificado)

- `SecurityAgent.__init__` recibe un nuevo parámetro opcional
  `tracer: RunTracer = None` (mismo patrón que `audit_adapter`).
- Nuevo helper:

```python
def _trace(self, event: str, **fields) -> None:
    if self._tracer is not None:
        self._tracer.record(event, **fields)
```

- `run()` y `_audit()` llaman a `self._trace(...)` en los puntos descritos en
  "Esquema de eventos".
- Con `tracer=None` (default), `_trace` no hace nada — los 122 tests
  existentes no necesitan cambios.

### `cybersec/cli.py` (modificado)

- Nueva opción `--trace-dir PATH` en el comando `scan`.
- Si se pasa: crea el directorio (si no existe) y abre
  `RunTracer(trace_dir/run-<timestamp>.jsonl)` como context manager.
- Si no se pasa: usa `contextlib.nullcontext()`, de modo que `tracer` sea
  `None` de forma uniforme.

```python
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

trace_cm = nullcontext()
if trace_dir:
    from cybersec.infrastructure.tracing import RunTracer
    Path(trace_dir).mkdir(parents=True, exist_ok=True)
    trace_path = Path(trace_dir) / f"run-{datetime.now().strftime('%Y%m%dT%H%M%S')}.jsonl"
    trace_cm = RunTracer(trace_path)

with trace_cm as tracer:
    agent = SecurityAgent(adapter=llm, tool_registry=registry, audit_adapter=audit_llm, tracer=tracer)
    ...
```

## Esquema de eventos (JSONL)

Cada línea es un objeto JSON con `ts` (timestamp ISO UTC) + `event` + campos
específicos:

| Evento | Cuándo se emite | Campos |
|---|---|---|
| `run_start` | al inicio de `run()` | `host`, `code_directory`, `analysis_types`, `log_files`, `max_iterations` |
| `llm_response` | cada iteración, tras `adapter.chat(...)` | `iteration` (1-based), `has_tool_calls` (bool), `tool_calls` (`[{"name", "args"}]`, **sin** `thought_signature`), `content_preview` (primeros 200 chars de `response.content`) |
| `tool_result` | por cada tool call ejecutado en la iteración | `iteration`, `name`, `args`, `success` (bool), `metadata` (el `metadata` del `ToolResult`, ej. `{"file_path":..., "lines":..., "truncated":...}` para `read_code_snippet` o `{"directory":..., "count":...}` para `list_code_files`; `{}` si la tool no existe o lanzó excepción), `content_length` (long del `content` resultante) |
| `loop_end` | al salir del loop principal | `reason` (`"no_tool_calls"` o `"max_iterations"`), `iteration` |
| `audit_result` | al terminar `_audit()` | `success` (bool), `report` (texto completo del reporte final — ya es lo que se imprime por stdout, no añade exposición nueva) |

Para `loop_end.iteration`: si `reason="no_tool_calls"`, es el número de
iteración 1-based en el que el LLM devolvió una respuesta sin `tool_calls`
(la misma `i+1` del `llm_response` correspondiente). Si
`reason="max_iterations"`, es `self._max_iterations` (el loop se agotó por
completo).

Este esquema responde directamente a las tres hipótesis de H2:

1. **Cobertura de archivos**: buscar `tool_result` con `name="read_code_snippet"`
   y `args.file_path` que contenga `auth_service` — ¿aparece en la corrida?
2. **Razonamiento del LLM**: si el archivo se leyó, ¿el `audit_result.report`
   final menciona el hallazgo (`auth_service`, `password`, severidad
   `Critical`)?
3. **Presupuesto de iteraciones**: ¿`loop_end.reason == "max_iterations"`
   ocurre antes de que aparezca el `tool_result` de `auth_service.py`?

## Detalle de instrumentación (nivel "resumido")

Decisión de diseño (ya validada): los eventos NO incluyen el contenido íntegro
de las respuestas del LLM ni de los `tool_result` (que podrían contener el
propio secreto en texto plano que se busca detectar). Solo:

- `content_preview`: primeros 200 caracteres de `response.content`.
- `metadata` + `content_length`: ya provistos por `ToolResult`, sin volcar el
  contenido del archivo.
- Excepción: `audit_result.report` SÍ incluye el texto completo, porque es
  exactamente el reporte final que el CLI ya imprime por stdout — no es
  información nueva expuesta por el trace.

## Manejo de errores

- **Apertura del archivo** (`RunTracer.__init__`): si `--trace-dir` no es
  escribible, `open()` lanza de forma natural y el comando falla con
  traceback. Sin manejo especial — es un flag de diagnóstico explícito.
- **Escrituras durante la corrida** (`record()`): no se envuelven en
  try/except. Un fallo de E/S aquí (disco lleno) se propagaría y abortaría la
  corrida. Aceptado como caso extremo de un flag opt-in de diagnóstico — no se
  añade resiliencia adicional.
- **`tool_result` para tool desconocida o que lanza excepción**: reusa las
  ramas ya existentes en `run()` (`tool is None` / `except Exception`),
  trazando `success=False, metadata={}`.
- **`audit_result`**: refleja el `try/except` ya existente en `_audit()`
  (`success=True` con el reporte auditado, o `success=False` con el reporte
  original si la auditoría falla).
- **Cierre garantizado**: `with trace_cm as tracer:` asegura `close()`/flush
  incluso si `agent.run()` propaga una excepción no capturada.

## Testing

**`tests/test_tracing.py`** (nuevo):
- `record()` escribe una línea JSON por llamada, con `event`, `ts` y los
  campos dados.
- múltiples `record()` → múltiples líneas, cada una JSON válida.
- valores no serializables (ej. `bytes`) no rompen `record()` (gracias a
  `default=str`).
- el context manager cierra el archivo (contenido legible tras el `with`).

**`tests/test_agent.py`** (nuevos, con `tracer=MagicMock()`):
- `run_start` incluye `host`, `code_directory`, `analysis_types`, `log_files`,
  `max_iterations`.
- `llm_response` por iteración incluye `iteration`, `has_tool_calls`,
  `tool_calls=[{"name","args"}]` (sin `thought_signature`), `content_preview`.
- `tool_result` incluye el `metadata` real del `ToolResult` y
  `content_length`.
- `tool_result` para tool desconocida (`ghost_tool`) → `success=False,
  metadata={}`.
- `loop_end` con `reason="no_tool_calls"` (caso normal) y
  `reason="max_iterations"` (loop agotado).
- `audit_result` con `success=True` (auditoría ok) y `success=False`
  (auditoría falla, fallback).
- con `tracer=None` (default), nada de esto se llama y no hay error.

**`tests/test_cli.py`** (nuevos, vía `click.testing.CliRunner` + mocks de
`SecurityAgent`/`_build_adapter`/`get_registry`):
- `--trace-dir <tmp_path>` → se crea un archivo `run-*.jsonl` en ese
  directorio y `SecurityAgent(...)` se construye con `tracer` no-`None`.
- sin `--trace-dir` → no se crea ningún archivo y `SecurityAgent(...)` se
  construye con `tracer=None`.

## Seguimiento (fuera de alcance de esta spec)

Una vez implementado y validado, el siguiente paso (sesión aparte) es:

1. Correr el CLI varias veces con `--trace-dir` contra `agente-cosmic`.
2. Inspeccionar los `.jsonl` para confirmar/descartar cada una de las tres
   hipótesis de H2 listadas en "Contexto".
3. Diseñar el fix correspondiente (ej. ajustar el prompt, aumentar
   `max_iterations`, forzar lectura de archivos obligatorios antes de
   permitir que el agente termine, etc.) en una nueva spec/plan.
