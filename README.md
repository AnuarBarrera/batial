# Agente de Ciberseguridad con IA

CLI standalone en Python que analiza el estado de seguridad de un servidor Linux, orquesta un loop agéntico con LLM y genera un reporte estructurado de vulnerabilidades — enviado por email al terminar.

---

## Qué hace

El agente recibe un scope de análisis (host, logs, directorio de código), lanza un loop agéntico donde el LLM decide qué herramientas usar y en qué orden, ejecuta cada herramienta localmente y produce un reporte con hallazgos, severidad y recomendaciones concretas.

```
Usuario define scope → LLM decide tools → Tools corren en local → LLM genera diagnóstico → LLM auditor revisa el reporte → Reporte en pantalla + email
```

### Herramientas disponibles

| Tool | Qué hace |
|---|---|
| `scan_ports` | Wrapper de nmap — top 1000 puertos TCP, detecta servicios sensibles expuestos (MySQL, Redis, VNC, etc.) |
| `analyze_logs` | Parsea auth.log, syslog, nginx/apache — detecta brute force SSH, IPs repetidas, errores 5xx |
| `check_dependencies` | Verifica paquetes pip/npm contra CVEs conocidos con `pip-audit` y `npm audit` |
| `list_code_files` | Lista archivos de código en un directorio (recursivo, excluye .git/node_modules/venv/etc.) |
| `read_code_snippet` | Lee archivos de código fuente (.py, .js, .ts, .go, .sh, .env, .yaml…) para análisis estático |
| `check_configs` | Revisa sshd_config, permisos de /etc/passwd y /etc/shadow, estado del firewall (ufw/iptables) |
| `scan_code_security` | Análisis estático determinista con `bandit` — secretos hardcodeados, funciones peligrosas (eval/exec, shell=True), criptografía débil, SQL injection, etc. |

---

## Arquitectura

```
cybersec/
├── cybersec/
│   ├── domain/               # Entidades y contratos (LLMAdapter, BaseTool)
│   ├── application/          # Loop agéntico (SecurityAgent), generador de reportes
│   │                         # y PatchProposer (Fase 2a — propuesta de parche)
│   └── infrastructure/
│       ├── adapters/         # GeminiAdapter, OpenAICompatAdapter, AnthropicVertexAdapter
│       ├── tools/            # Las 7 herramientas de análisis
│       └── notifiers/        # MailgunNotifier (email)
├── tests/                    # 223 tests con pytest
├── .env.example
├── requirements.txt
└── pytest.ini
```

**Principio clave:** el agente no conoce el proveedor de LLM — solo habla con `LLMAdapter`. Cambiar de Gemini a Claude o a vLLM propio es cambiar una variable de entorno.

---

## Pre-fetch determinista de archivos de seguridad obligatorios

El loop agéntico le da al LLM control sobre qué herramientas usa y en qué orden — pero eso introduce no-determinismo. En pruebas reales, el modelo ocasionalmente decidía **no** llamar a `read_code_snippet` sobre archivos críticos (autenticación, configuración, credenciales) aunque el prompt lo pidiera explícitamente.

Para eliminar esa discrecionalidad, **antes** de que el LLM reciba su primer turno, `SecurityAgent._prefetch_mandatory_files()` ejecuta determinísticamente `list_code_files` + `read_code_snippet` sobre cualquier archivo del proyecto cuyo nombre coincida con estos patrones:

```python
MANDATORY_FILE_PATTERNS = [
    "*settings*", "*config*",
    "*auth*", "*login*", "*password*", "*credential*",
    "docker-compose*", "Dockerfile*", "*.env*",
    "*middleware*",
]
```

El contenido de esos archivos se inyecta como texto plano al final del prompt inicial: el LLM lo recibe ya leído, sin depender de que decida pedirlo.

---

## Confinamiento de herramientas al scope analizado

El LLM decide los argumentos de cada tool call de forma autónoma dentro del loop agéntico — eso significa que un archivo hostil dentro del código analizado (prompt injection indirecto) podría, en teoría, instruir al modelo a leer archivos fuera de scope o manipular el escaneo de red. El prompt no es un límite de seguridad; estas dos validaciones sí lo son:

- **`read_code_snippet` / `list_code_files`** solo pueden leer/listar rutas dentro de `--code-dir`. `SecurityAgent` inyecta el directorio de scope en cada llamada — sobrescribiendo cualquier valor que el propio LLM intente pasar — y ambas tools rechazan cualquier ruta que no resuelva dentro de ese directorio.
- **`scan_ports`** valida que `host` sea un hostname/IP/CIDR/IPv6 válido antes de construir el comando de nmap, evitando argument injection (`--script=vuln`, `-oN /ruta/archivo`) si el valor llega manipulado.

---

## Requisitos

- Python 3.10+
- `nmap` instalado en el sistema (`sudo apt install nmap`)
- `pip-audit` para análisis de dependencias Python (`pip install pip-audit`)
- `bandit` para análisis estático de código Python (incluido en `requirements.txt`)

---

## Instalación

```bash
cd cybersec
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Editar .env con tus claves
```

---

## Configuración

Copia `.env.example` a `.env` y completa los valores según el adaptador que quieras usar:

```env
# LLM — Gemini (API directa)
GEMINI_API_KEY=tu_api_key
GEMINI_MODEL=gemini-2.5-flash
GEMINI_AUDIT_MODEL=gemini-2.5-pro

# LLM — Vertex AI (GCP, Gemini o Claude)
GOOGLE_CLOUD_PROJECT=tu-proyecto-gcp
GOOGLE_CLOUD_LOCATION=us-central1
GEMINI_VERTEX_MODEL=gemini-2.5-pro
GEMINI_VERTEX_AUDIT_MODEL=gemini-2.5-pro

# LLM — Claude vía Vertex AI
ANTHROPIC_VERTEX_PROJECT=tu-proyecto-gcp
ANTHROPIC_VERTEX_REGION=us-east5
ANTHROPIC_VERTEX_MODEL=claude-sonnet-4-5

# LLM — OpenAI-compatible (vLLM propio, Ollama, Groq, Together…)
OPENAI_COMPAT_BASE_URL=http://tu-servidor:8000
OPENAI_COMPAT_MODEL=Qwen/Qwen2.5-Coder-14B-Instruct

# Email — Mailgun
MAILGUN_API_KEY=tu_api_key
MAILGUN_DOMAIN=mg.tudominio.com
MAILGUN_SENDER_EMAIL=seguridad@tudominio.com
```

---

## Uso

```bash
# Análisis básico en localhost con Gemini
python3 -m cybersec scan

# Análisis completo con logs y email
python3 -m cybersec scan \
  --host 192.168.1.10 \
  --log /var/log/auth.log \
  --log /var/log/nginx/access.log \
  --type network --type logs --type config --type deps --type code \
  --code-dir /ruta/a/tu/proyecto \
  --email tu@email.com

# Usar Vertex AI (Gemini en GCP)
python3 -m cybersec scan --adapter vertex --model gemini-2.5-pro --location global --host 10.0.0.5

# Usar Claude vía Vertex AI
python3 -m cybersec scan --adapter anthropic-vertex --model claude-sonnet-4-6 --host 10.0.0.5

# Modo verbose: ver qué archivos explora el agente en cada iteración
python3 -m cybersec scan --verbose --adapter vertex --model gemini-2.5-pro \
  --host 192.168.1.10 --code-dir /ruta/proyecto

# Guardar trace JSONL para diagnóstico
python3 -m cybersec scan --trace-dir /tmp/cybersec-traces --host 192.168.1.10

# Fase 2a: generar propuestas de parche además del diagnóstico
python3 -m cybersec scan --code-dir /ruta/proyecto --propose-patches --patch-dir ./patches
```

### Opciones del comando `scan`

| Opción | Default | Descripción |
|---|---|---|
| `--host` | `localhost` | IP o hostname a analizar |
| `--log` | — | Ruta a archivo de log (repetible) |
| `--code-dir` | — | Directorio de código para análisis estático |
| `--type` | todos | `network`, `logs`, `deps`, `code`, `config` (repetible) |
| `--email` | — | Email para recibir el reporte por Mailgun |
| `--adapter` | `gemini` | `gemini`, `vertex`, `anthropic-vertex`, `openai` |
| `--model` | según adapter | Override del modelo configurado en `.env` |
| `--audit-model` | según adapter | Modelo para el paso de auditoría |
| `--location` | según adapter | Región de Vertex AI (`us-central1`, `global`, etc.) |
| `--max-iterations` | `15` | Límite de iteraciones del loop agéntico |
| `--verbose` | off | Muestra herramientas por iteración en lugar de barra de progreso |
| `--trace-dir` | — | Directorio donde guardar un trace JSONL de la corrida |
| `--exceptions-file` | — | Archivo `.md` con hallazgos aceptados a nivel de host (puertos, infra) |
| `--propose-patches` | off | Genera propuestas de parche (Fase 2a) para hallazgos con archivo identificado. Requiere `--code-dir` |
| `--patch-dir` | `./patches` | Directorio donde guardar los `.patch` generados (solo con `--propose-patches`) |

### Modo verbose

Con `--verbose` se muestra en tiempo real qué explora el agente en cada iteración:

```
[1/15] scan_code_security, check_dependencies, list_code_files
[2/15] read_code_snippet(settings.py), read_code_snippet(auth_service.py)
[3/15] read_code_snippet(views.py), read_code_snippet(web_scraper.py)
[4/15] read_code_snippet(pii_handler.py)
[5/15] → sin herramientas — generando reporte
  Auditando el reporte...
```

Útil para entender qué rutas de exploración tomó el agente y en qué punto decidió que tenía suficiente información.

### Hallazgos aceptados formalmente

El agente distingue entre hallazgos que requieren acción y hallazgos que han sido revisados y aceptados conscientemente (deuda técnica, decisiones de arquitectura, limitaciones del MVP). Los aceptados aparecen en el reporte en una sección separada, excluidos de PRÓXIMOS PASOS, y no cuentan en el resumen ejecutivo.

Se soportan dos fuentes que se fusionan en cada scan:

**1. Excepciones del proyecto** — viven en el repositorio analizado:

```bash
# {code-dir}/.cybersec-exceptions.md
## CSP con unsafe-inline y unsafe-eval
**Razón:** Los templates Django usan scripts inline — refactorización pendiente Fase 2.

## DNS Rebinding TOCTOU en WebScraper
**Razón:** Requiere DNS malicioso con TTL bajo + timing exacto. Complejidad alta, aceptado para MVP.
```

Se detectan automáticamente si el archivo existe en `--code-dir`. No requieren ningún flag adicional.

**2. Excepciones de host** — independientes del código analizado, para puertos o configuración de infraestructura que aplica al servidor:

```bash
# ~/.cybersec-host.md  (o cualquier ruta)
## Puerto 8000 expuesto
**Razón:** Servicio de desarrollo interno en red LAN — no accesible desde internet.

## Puerto 5678 (n8n)
**Razón:** Herramienta interna de automatización, acceso restringido a la red local.
```

```bash
python3 -m cybersec scan --exceptions-file ~/.cybersec-host.md ...
```

El formato es Markdown libre — el agente hace el matching semántico, no por cadena exacta.

En el reporte los hallazgos aceptados aparecen así:

```
HALLAZGOS ACEPTADOS
----------------------------------------
  (Revisados y aprobados formalmente — excluidos de próximos pasos)

  [F003] Puerto 8000 expuesto  [Medium]
  Razón: Servicio de desarrollo en red LAN — no accesible desde internet

  [F004] DNS Rebinding TOCTOU  [Medium]
  Razón: Requiere DNS malicioso con TTL bajo. Aceptado para MVP.
```

### Contexto del proyecto (CLAUDE.md, GEMINI.md, AGENTS.md)

Si el directorio analizado contiene archivos de contexto para agentes de IA (`CLAUDE.md`, `GEMINI.md`, `AGENTS.md`, `memory.md`), el agente los lee durante el análisis para entender la arquitectura del proyecto, decisiones de diseño y deuda técnica conocida. Esto reduce falsos positivos sin configuración adicional — el agente llega informado sobre por qué ciertas cosas son como son.

No requiere ninguna acción: si el archivo existe en `--code-dir`, el agente lo encontrará y lo leerá. También puedes añadir una sección `## Vulnerabilidades de Seguridad Aceptadas` directamente en tu `CLAUDE.md` para combinar contexto y excepciones en un solo archivo.

### Resumen de tokens y costo

Al finalizar cada scan se muestra un resumen de tokens consumidos y el costo estimado. Si se especificó `--model`, muestra solo ese modelo; si no, compara todos los modelos soportados:

```
────────────────────────────────────────────────────────────
Tokens utilizados: 258,227 entrada / 5,183 salida (total: 263,410)
Costo estimado por modelo:
  gemini-2.5-flash: $0.0209
  gemini-2.5-pro:   $0.3746
  claude-haiku-4-5: $0.2273
  claude-sonnet-4-6: $0.8524
  claude-opus-4-8:  $4.2621
────────────────────────────────────────────────────────────
```

Útil para comparar el costo-beneficio entre modelos antes de escalar a producción.

### Fase 2a — Propuesta de parche

Con `--propose-patches`, el agente genera además un diff propuesto y una explicación en lenguaje no técnico para cada hallazgo que apunte a un archivo concreto dentro de `--code-dir`. **Nunca aplica nada automáticamente** — solo propone, el humano decide si lo aplica. Aplicar el parche en sandbox, correr tests y re-escanear antes de aprobar es Fase 2b (ver Roadmap).

```bash
python3 -m cybersec scan --code-dir /ruta/proyecto --propose-patches --patch-dir ./patches
```

- Cada parche se guarda como `.patch` aplicable con `git apply <archivo>` en `--patch-dir` (default `./patches`).
- El reporte incluye una sección `PARCHES PROPUESTOS` con el diff completo, la explicación y la ruta donde se guardó.
- Solo reciben parche los hallazgos con un archivo identificado por el LLM y que no estén formalmente aceptados — hallazgos de red o logs quedan fuera de alcance (Fase 2 no toca infraestructura, solo código).
- Un fallo generando el parche de un hallazgo puntual (archivo no encontrado, respuesta inválida del LLM) nunca afecta a los demás — cada propuesta es independiente.
- Los headers de hunk (`@@ -a,b +c,d @@`) se recalculan de forma determinística a partir del cuerpo real del diff en vez de confiar en el conteo del LLM, que se equivoca con frecuencia en hunks largos — antes de este fix, alrededor de la mitad de los parches generados eran rechazados por `git apply` (`corrupt patch`) pese a que el contenido del cambio era correcto.

```
PARCHES PROPUESTOS
----------------------------------------
  [F001] Almacenamiento de contraseñas en texto plano durante el registro
  Archivo: core/tenant_management/services/auth_service.py
  Guardado en: patches/F001-almacenamiento-de-contrase-as-en-texto-p.patch

  Explicación: Se modificó el proceso de registro para que la contraseña
  se encripte de forma segura (hash) antes de guardarse...

  --- a/core/tenant_management/services/auth_service.py
  +++ b/core/tenant_management/services/auth_service.py
  @@ -40,7 +41,7 @@
  -                'password': password,
  +                'password': make_password(password),
```

Validado contra proyectos reales: los parches generados aplican limpio con `git apply --check`. La validación automática de que el parche resuelve el hallazgo (tests + re-scan) es explícitamente Fase 2b — Fase 2a solo propone.

### Formato del reporte

```
REPORTE DE SEGURIDAD — 2026-06-22 04:13 — 192.168.1.10
════════════════════════════════════════════════════════

RESUMEN EJECUTIVO
  Total hallazgos: 10  (Critical: 0 │ High: 8 │ Medium: 1 │ Low: 1)

HALLAZGOS
  [F001] Subida de Archivos Arbitrarios (Unrestricted File Upload)
  Severidad: High
  Evidencia: En views.py, _update_active_product_images extrae la extensión
             directamente del nombre del archivo sin validarla contra una lista blanca.
  Recomendación: Usar la función _safe_extension existente antes de guardar.

  ...

PRÓXIMOS PASOS
  1. Validar extensiones en todos los puntos de subida de archivos
  2. Agregar @login_required a vistas que exponen datos por job_id
  ...
```

---

## Tests

```bash
cd cybersec
source venv/bin/activate
pytest -v
```

223 tests cubriendo domain, tools, adapters, agent loop, pre-fetch, reporte y generación de parches (Fase 2a).

---

## Adaptadores LLM

### Gemini (API directa)

Usa la API de Google Gemini con function calling nativo. Requiere `GEMINI_API_KEY`.

### Vertex AI (Gemini en GCP)

Usa Application Default Credentials de GCP. No requiere API key — autentica con `gcloud auth application-default login`. Ideal para producción con créditos GCP.

```bash
python3 -m cybersec scan --adapter vertex --model gemini-2.5-pro --location global
```

### Claude vía Vertex AI

Permite usar modelos Claude (Anthropic) a través de Vertex AI. Requiere aceptar los términos de uso de Anthropic en el Model Garden de GCP.

```bash
python3 -m cybersec scan --adapter anthropic-vertex --model claude-sonnet-4-6
```

### OpenAI-compatible

Apunta a cualquier servidor con endpoint `/v1/chat/completions`: vLLM propio en GCP, Ollama en local, Groq, Together AI, OpenRouter. Requiere `OPENAI_COMPAT_BASE_URL` y `OPENAI_COMPAT_MODEL`.

**Setup en producción:** instancia GCP L4 con vLLM + Qwen2.5-Coder 14B (~$0.70/hr on-demand). Los datos del cliente viajan solo a tu instancia privada.

---

## Roadmap

| Fase | Estado | Descripción |
|---|---|---|
| **Fase 1 — Diagnóstico** | ✅ Completa | CLI que analiza y reporta vulnerabilidades reales |
| **Fase 2a — Propuesta de parche** | ✅ Completa | El agente genera un diff propuesto + explicación por hallazgo; el humano decide si lo aplica |
| **Fase 2b — Sandbox + tests** | Planeada | Aplica el parche en un entorno aislado, corre tests y re-escanea antes de pedir aprobación |
| **Fase 2c — Aplicación autónoma** | Planeada | Aplica el parche solo si los tests pasan, con rollback automático |
| **Fase 3 — Monitoreo** | Planeada | Daemon 24/7 que detecta ataques en tiempo real y envía alertas |

---

## Estado actual

Fase 1 completa y validada en producción contra repositorios reales. El agente encuentra vulnerabilidades reales — confirmado corrigiendo los hallazgos y verificando que eran explotables: IP Spoofing vía X-Forwarded-For, IDOR sin autenticación, XXE en parseo de SVG generado por IA, Unrestricted File Upload, middlewares de rate limiting registrados en código pero no activos en `settings.py`, credenciales GCP montadas en Docker, y más.

Fase 2a (propuesta de parche) completa y validada contra el mismo tipo de proyectos reales: los diffs generados aplican limpio con `git apply --check` de forma consistente, incluyendo casos no triviales como evitar doble-hasheo de contraseñas en Django (`password=None` + asignación directa del hash + `save()`, en vez de volver a hashear un valor que ya venía hasheado). Criterio de graduación a Fase 2b: métricas de precision/recall medidas contra la suite de validación, no solo que el diff aplique.

El explorador corre con `temperature=0.0`/`top_k=1` por defecto (validado empíricamente: reduce la varianza de hallazgos entre corridas frente al muestreo por defecto del modelo, aunque no la elimina del todo — el techo de determinismo real de las APIs de LLM alojadas parece estar ahí).

Resultados típicos: 4-10 hallazgos por corrida según el proyecto, ~220-420K tokens con gemini-3.5-flash/gemini-3.1-pro-preview (~$0.02-0.03 USD/scan), 5-9 iteraciones de las 15 disponibles. 223/223 tests pasando.
