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
| `scan_ports` | Wrapper de nmap — top 100 puertos TCP, detecta servicios sensibles expuestos (MySQL, Redis, VNC, etc.) |
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
│   ├── application/          # Loop agéntico (SecurityAgent) y generador de reportes
│   └── infrastructure/
│       ├── adapters/         # GeminiAdapter, OpenAICompatAdapter, AnthropicVertexAdapter
│       ├── tools/            # Las 7 herramientas de análisis
│       └── notifiers/        # MailgunNotifier (email)
├── tests/                    # 155 tests con pytest
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

155 tests cubriendo domain, tools, adapters, agent loop, pre-fetch y reporte.

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
| **Fase 2 — Remediación** | Planeada | El agente propone y aplica parches con confirmación del usuario |
| **Fase 3 — Monitoreo** | Planeada | Daemon 24/7 que detecta ataques en tiempo real y envía alertas |

---

## Estado actual

Fase 1 completa y validada en producción contra repositorios reales. El agente encuentra vulnerabilidades reales — confirmado corrigiendo los hallazgos y verificando que eran explotables: IP Spoofing vía X-Forwarded-For, IDOR sin autenticación, XXE en parseo de SVG generado por IA, Unrestricted File Upload, middlewares de rate limiting registrados en código pero no activos en `settings.py`, credenciales GCP montadas en Docker, y más.

Resultados típicos: 10 hallazgos por corrida (High: 4-8), ~263K tokens con gemini-2.5-pro (~$0.37 USD/scan), 5-9 iteraciones de las 15 disponibles. 155/155 tests pasando.
