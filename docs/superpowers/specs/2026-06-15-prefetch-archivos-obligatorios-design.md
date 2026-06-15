# Pre-fetch determinista de archivos de seguridad obligatorios — Diseño

## Contexto

La instrumentación de trace (`docs/superpowers/specs/2026-06-14-trace-diagnostico-agente-h2-design.md`)
permitió diagnosticar por qué el reporte del agente nunca menciona el
hallazgo Critical de `auth_service.py` (password en texto plano persistido)
en `agente-cosmic`.

Se ejecutaron 3 corridas reales (`cybersec scan --code-dir agente-cosmic
--trace-dir ...`) y se analizaron los `.jsonl` con `analiza_traces.sh`. En
las 3 corridas:

- `scan_code_security` y `list_code_files` se ejecutan siempre de forma
  confiable.
- `read_code_snippet` se ejecuta **exactamente una vez por corrida**, siempre
  sobre `settings.py`.
- `auth_service.py` está visible en la salida de `list_code_files` (entre los
  9 archivos del proyecto que matchean `MANDATORY_FILE_PATTERNS`), pero nunca
  se lee.
- El loop termina voluntariamente con `loop_end reason="no_tool_calls"`, con
  3-7 de 10 iteraciones sin usar (descarta H3 — no es un problema de
  presupuesto de iteraciones).

**Conclusión (H1 confirmado):** el LLM, dentro del loop agéntico, decide no
leer los archivos obligatorios pese a que la instrucción del prompt lo pide
explícitamente ("usa read_code_snippet para leer SIEMPRE, sin excepción...").
El problema es de cobertura de archivos, no de razonamiento sobre contenido ya
visto ni de presupuesto de iteraciones.

## Objetivo

Eliminar la discrecionalidad del LLM sobre si lee o no los archivos de
seguridad obligatorios: Python los lee de forma determinista **antes** de que
el LLM tenga su primer turno, y los entrega ya como contexto disponible.

Fuera de alcance de este diseño ("Forma 2", no incluida): reescribir las
instrucciones sobre "cuándo tienes suficientes hallazgos" para el resto del
análisis discrecional. Esta iteración se limita al pre-fetch determinista +
el ajuste mínimo de prompt necesario para que ese pre-fetch tenga sentido.

## Arquitectura

Antes de construir el primer mensaje (`messages`) y entrar al loop de
`SecurityAgent.run()`, cuando `scope.code_directory` no es `None`:

1. Se llama a `list_code_files(directory=code_directory)` vía el
   `tool_registry`.
2. Se filtran las rutas devueltas contra `MANDATORY_FILE_PATTERNS`.
3. Para cada archivo que matchea, se llama a
   `read_code_snippet(file_path=...)`.
4. El contenido devuelto por cada `read_code_snippet` (mismo formato que ya
   produce `CodeReaderTool`: `# {path}\n\`\`\`{ext}\n{snippet}\n\`\`\``) se
   concatena en un bloque de texto, con un encabezado explicativo.
5. Ese bloque se agrega como texto plano al final del prompt inicial
   (`initial`), **antes** de crear `messages = [Message(role="user",
   content=initial)]`.

### Decisión clave: inyección como texto, no como `Message(role="tool", ...)`

En `cybersec/infrastructure/adapters/gemini.py`, un `Message(role="tool",
tool_results=[...])` se convierte en `types.Content(role="user",
parts=[FunctionResponse(...)])`. La API de Gemini exige que un
`FunctionResponse` siga a un `function_call` previo del modelo (con su
`thought_signature` correspondiente). El pre-fetch ocurre antes de cualquier
turno del LLM, por lo que no existe ese `function_call` previo — un mensaje
`tool`-role sintético rompería esa validación (`400 INVALID_ARGUMENT`).

Por eso el contenido pre-leído se agrega como **texto** dentro del prompt
inicial. Esto funciona igual para `GeminiAdapter` y `OpenAICompatAdapter`, sin
tocar ninguno de los dos adaptadores.

## Componentes

### `MANDATORY_FILE_PATTERNS`

Constante de módulo en `cybersec/application/agent.py`, lista de patrones
estilo `fnmatch`, extraída de la instrucción #2 actual de `_PROMPT`:

```python
MANDATORY_FILE_PATTERNS = [
    "*settings*", "*config*",
    "*auth*", "*login*", "*password*", "*credential*",
    "docker-compose*", "Dockerfile*", "*.env*",
    "*middleware*",
]
```

Nota: se omite `.env.example` del listado original porque ya matchea con
`*.env*` (era redundante).

### `SecurityAgent._prefetch_mandatory_files(code_directory: str | None) -> str`

Comportamiento, en orden:

1. Si `code_directory is None` → retorna `""`. Sin llamadas a tools, sin
   trazas.
2. `tool = self._registry.get("list_code_files")`. Si `tool is None` →
   retorna `""`. Sin trazas. (Cubre los tests existentes que usan
   `tool_registry={}`.)
3. Ejecuta `result = tool.execute(directory=code_directory)`. Se traza un
   `tool_result` con `iteration=0`, `name="list_code_files"`,
   `args={"directory": code_directory}`, `success=result.success`,
   `metadata=result.metadata`, `content_length=len(result.content)`.
   Si `result.success` es `False` → retorna `""` (no se intenta filtrar ni
   leer nada más).
4. Parsea `result.content` línea por línea: conserva solo las líneas que
   empiezan con `/` (rutas absolutas; descarta la línea
   `[lista truncada a 200 archivos]` si está presente).
5. Filtra esas rutas: una ruta se incluye si
   `fnmatch.fnmatch(os.path.basename(path).lower(), pattern.lower())` es
   verdadero para algún `pattern` en `MANDATORY_FILE_PATTERNS`. Deduplica
   preservando el orden de aparición (un archivo puede matchear más de un
   patrón).
6. Si la lista filtrada queda vacía → retorna un bloque corto:
   ```
   ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático):

   No se encontraron archivos que coincidan con los patrones de seguridad
   obligatorios en este proyecto.
   ```
7. Si no está vacía: para cada ruta, ejecuta
   `read_tool.execute(file_path=path)` donde `read_tool =
   self._registry.get("read_code_snippet")`. Para cada llamada se traza un
   `tool_result` con `iteration=0`, `name="read_code_snippet"`,
   `args={"file_path": path}`, `success`, `metadata`, `content_length`.
   - Si `success` es `True`, se usa `result.content` tal cual (ya viene en
     formato `# {path}\n\`\`\`{ext}\n...\n\`\`\``).
   - Si `success` es `False`, se agrega en su lugar una línea:
     `# {path}\n(error al leer este archivo: {result.content})` — y se
     continúa con el resto de los archivos (un fallo puntual no aborta el
     pre-fetch completo).

   Nota: si `read_tool is None` (no debería ocurrir si `list_code_files`
   existe, pero por robustez ante registries parciales en tests), se trata
   igual que un fallo puntual por archivo: línea de error, sin trazar
   `tool_result` (no hay tool que ejecutar).

8. Retorna el bloque final:
   ```
   ARCHIVOS DE SEGURIDAD OBLIGATORIOS (pre-fetch automático, ya leídos):

   {contenido de cada archivo, separados por "\n\n"}
   ```

### Integración en `run()`

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
```

`_prefetch_mandatory_files` se llama **antes** del `self._trace("run_start",
...)` existente (que no cambia de posición). Por lo tanto, en el `.jsonl` los
eventos `tool_result` con `iteration=0` del pre-fetch aparecen **antes** de
`run_start`, seguidos de `llm_response` de la iteración 1 en adelante. Esto
no afecta a `analiza_traces.sh`, cuyas queries filtran por `name`/`event`, no
por orden.

## Reescritura mínima del prompt (`_PROMPT`, instrucción #2)

El bloque actual:

```
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

se reemplaza por:

```
2. A continuación se incluye el contenido de los archivos de seguridad
   obligatorios del proyecto (settings, config, auth, login, password,
   credential, docker-compose, Dockerfile, .env*, middleware), ya leídos
   automáticamente — no necesitas volver a llamar a read_code_snippet sobre
   ellos. Analiza su contenido como parte de tu evaluación de seguridad.
   Además, usa list_code_files y read_code_snippet para revisar cualquier
   otro archivo que consideres relevante desde el punto de vista de
   seguridad (manejo de inputs, sesiones, permisos, lógica de negocio).
```

Esta instrucción sigue dentro del bloque condicional existente ("Si se
especifica un directorio de código (distinto de 'ninguno')..."), por lo que
solo aplica cuando `code_directory` no es `None` — caso en el que
`prefetch_text` siempre es no-vacío (incluye al menos el bloque "no se
encontraron..." si no hubo matches), así que "a continuación se incluye" es
siempre veraz cuando esta instrucción es relevante.

## Trazas

El pre-fetch reutiliza el evento `tool_result` existente (mismo schema:
`iteration`, `name`, `args`, `success`, `metadata`, `content_length`), con
`iteration=0` para distinguirlo de las iteraciones del loop principal (1..N).
No se introduce ningún evento nuevo. `analiza_traces.sh` no requiere cambios:
sus queries filtran por `name`, no por `iteration`.

Eventos emitidos por pre-fetch (en orden):
- Un `tool_result` para `list_code_files` (siempre, salvo que
  `code_directory is None` o la tool no esté en el registry).
- Un `tool_result` por cada `read_code_snippet` de un archivo que matcheó
  (solo si la tool existe en el registry).

## Manejo de errores / edge cases

| Caso | Comportamiento | Trazas |
|---|---|---|
| `code_directory is None` | `_prefetch_mandatory_files` retorna `""`, `initial` sin cambios | ninguna |
| `list_code_files` no está en el registry | retorna `""` | ninguna |
| `list_code_files` falla (`success=False`) | retorna `""` | 1 `tool_result` con `success=False` |
| Cero archivos matchean los patrones | retorna bloque "no se encontraron..." | 1 `tool_result` de `list_code_files` |
| `read_code_snippet` falla para un archivo puntual | línea de error para ese archivo, el resto continúa normalmente | `tool_result` con `success=False` para ese archivo |
| `read_code_snippet` no está en el registry pero `list_code_files` sí (registries parciales en tests) | línea de error por archivo, pre-fetch no falla | solo el `tool_result` de `list_code_files` |

En todos los casos donde `_prefetch_mandatory_files` retorna `""`, el
comportamiento de `run()` es exactamente el actual (sin el bloque pre-fetch
en `initial`) — los ~5 tests existentes que usan `code_directory="/tmp/proyecto"`
con `tool_registry={}` no requieren cambios.

## Testing

Nuevos tests en `tests/test_agent.py` para `_prefetch_mandatory_files`
(registry mockeado con `MagicMock`/fakes simples, sin tocar adapters reales):

1. `code_directory=None` → retorna `""`, no se llama a ninguna tool.
2. `tool_registry={}` (sin `list_code_files`) → retorna `""`, no se llama a
   ninguna tool, no se traza nada.
3. `list_code_files` devuelve `success=False` → retorna `""`, se traza 1
   `tool_result` con `success=False`, no se llama `read_code_snippet`.
4. `list_code_files` devuelve una lista con archivos que matchean varios
   patrones distintos (incluye `auth_service.py`, `settings.py`,
   `docker-compose.yml`, y al menos un archivo que NO matchea ninguno) →
   verifica que solo los archivos que matchean se pasan a
   `read_code_snippet`, que el resultado incluye el contenido de cada uno, y
   que no hay duplicados si un archivo matchea dos patrones.
5. `list_code_files` devuelve solo archivos que no matchean ningún patrón →
   retorna el bloque "no se encontraron...".
6. Uno de los `read_code_snippet` devuelve `success=False` → la salida
   incluye una línea de error para ese archivo, pero el contenido de los
   demás archivos sigue presente.
7. Con `tracer` no `None`: verificar que se registran los eventos
   `tool_result` con `iteration=0` esperados (cantidad y campos).
8. Con `tracer=None`: verificar que no se levanta ninguna excepción
   (`_trace` ya es no-op).

Test de integración en `run()`:

9. `code_directory` configurado + registry con `list_code_files` y
   `read_code_snippet` mockeados (devolviendo un archivo `auth_service.py`
   con contenido conocido) + adapter mockeado que devuelve `tool_calls=[]`
   inmediatamente → verificar que el primer `Message` pasado a
   `adapter.chat()` (`messages[0].content`) contiene el contenido
   pre-fetcheado de `auth_service.py`.

No-regresión:

10. Ejecutar la suite completa (137 tests actuales) — deben seguir pasando
    sin modificaciones, en particular los tests que usan
    `code_directory="/tmp/proyecto"` con `tool_registry={}`.

## Validación final

Tras implementar, correr `cybersec scan --code-dir agente-cosmic --trace-dir
/tmp/cybersec-traces` (al menos 1 vez, idealmente 2-3 dado que el problema
original era intermitente en el razonamiento del LLM aunque el pre-fetch en
sí es determinista) y confirmar con `analiza_traces.sh`:

- El `tool_result` de `read_code_snippet` sobre `auth_service.py` aparece con
  `iteration=0` (pre-fetch), independientemente de lo que el LLM decida hacer
  después.
- `audit_result.report` menciona `auth_service`/`password`/`Critical`.
