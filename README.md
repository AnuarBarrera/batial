# Agente de Ciberseguridad con IA

CLI standalone en Python que analiza el estado de seguridad de un servidor Linux, orquesta un loop agentico con LLM y genera un reporte estructurado de vulnerabilidades — enviado por email al terminar.

Proyecto construido en el hackathon de Google (agentes de IA), Junio 2026.

---

## Qué hace

El agente recibe un scope de análisis (host, logs, directorio de código), lanza un loop agentico donde el LLM decide qué herramientas usar y en qué orden, ejecuta cada herramienta localmente y produce un reporte con hallazgos, severidad y recomendaciones concretas.

```
Usuario define scope → LLM decide tools → Tools corren en local → LLM genera diagnóstico → Reporte en pantalla + email
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
│   ├── application/          # Loop agentico (SecurityAgent) y generador de reportes
│   └── infrastructure/
│       ├── adapters/         # GeminiAdapter + OpenAICompatAdapter
│       ├── tools/            # Las 7 herramientas de análisis
│       └── notifiers/        # MailgunNotifier (email)
├── tests/                    # 100 tests con pytest
├── .env.example
├── requirements.txt
└── pytest.ini
```

**Principio clave:** el agente no conoce el proveedor de LLM — solo habla con `LLMAdapter`. Cambiar de Gemini a vLLM propio es cambiar una variable de entorno.

---

## Requisitos

- Python 3.10+
- `nmap` instalado en el sistema (`sudo apt install nmap`)
- `pip-audit` para análisis de dependencias Python (`pip install pip-audit`)
- `bandit` para análisis estático de código Python (`pip install bandit`, incluido en `requirements.txt`)

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

Copia `.env.example` a `.env` y completa los valores:

```env
# LLM — Gemini (créditos del hackathon)
GEMINI_API_KEY=tu_api_key
GEMINI_MODEL=gemini-2.5-flash-lite  # mayor cuota free-tier que gemini-2.5-flash

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

# Análisis completo con logs y email de reporte
python3 -m cybersec scan \
  --host 192.168.1.10 \
  --log /var/log/auth.log \
  --log /var/log/nginx/access.log \
  --type network \
  --type logs \
  --type config \
  --type deps \
  --email tu@email.com

# Usar vLLM propio en vez de Gemini
python3 -m cybersec scan --adapter openai --host 10.0.0.5
```

### Opciones del comando `scan`

| Opción | Default | Descripción |
|---|---|---|
| `--host` | `localhost` | IP o hostname a analizar |
| `--log` | — | Ruta a archivo de log (repetible) |
| `--code-dir` | — | Directorio de código para análisis estático |
| `--type` | todos | `network`, `logs`, `deps`, `code`, `config` (repetible) |
| `--email` | — | Email para recibir el reporte por Mailgun |
| `--adapter` | `gemini` | `gemini` o `openai` |

### Formato del reporte

```
REPORTE DE SEGURIDAD — 2026-06-09 14:32 — 192.168.1.10
══════════════════════════════════════════════════════

RESUMEN EJECUTIVO
  Total hallazgos: 4  │  Critical: 0  │  High: 2  │  Medium: 1  │  Low: 1

HALLAZGOS
  [HIGH-001] Brute force SSH detectado
  Severidad : High
  Evidencia : 127 intentos fallidos desde 45.33.32.156 en /var/log/auth.log
  Recomendación: Bloquear IP con ufw deny from 45.33.32.156; instalar fail2ban

  ...

PRÓXIMOS PASOS
  1. Bloquear IPs con actividad de brute force
  2. Desactivar PasswordAuthentication en sshd_config
  ...
```

---

## Tests

```bash
cd cybersec
source venv/bin/activate
pytest -v
```

100 tests cubriendo domain, tools, adapters, agent loop y reporte.

---

## Adaptadores LLM

### Gemini (default)

Usa la API de Google Gemini con function calling nativo. Requiere `GEMINI_API_KEY`. Modelo por defecto: `gemini-2.5-flash-lite` (configurable con `GEMINI_MODEL`).

### OpenAI-compatible

Apunta a cualquier servidor con endpoint `/v1/chat/completions`: vLLM propio en GCP, Ollama en local, Groq, Together AI, OpenRouter. Requiere `OPENAI_COMPAT_BASE_URL` y `OPENAI_COMPAT_MODEL`.

**Setup recomendado en producción:** instancia GCP L4 con vLLM + Qwen2.5-Coder 14B (~$0.70/hr on-demand). Los datos del cliente viajan solo a tu instancia privada, sin pasar por APIs públicas.

---

## Roadmap

| Fase | Estado | Descripción |
|---|---|---|
| **Fase 1 — Diagnóstico** | ✅ Completa y validada en producción | CLI que analiza y reporta |
| **Fase 2 — Remediación** | Planeada | El agente propone y aplica parches con confirmación del usuario |
| **Fase 3 — Monitoreo** | Planeada | Daemon 24/7 que detecta ataques en tiempo real y envía alertas |

---

## Estado actual

Fase 1 (MVP) completa y validada end-to-end con una corrida real de producción:
RESUMEN EJECUTIVO con conteo correcto de hallazgos, HALLAZGOS estructurados
ordenados por severidad (parseados desde `HALLAZGOS_JSON`), análisis del agente
sobre código fuente real (`list_code_files` + `read_code_snippet` + análisis
estático determinista con `scan_code_security`/bandit) y PRÓXIMOS PASOS
poblados con acciones priorizadas. 100/100 tests pasando.

Próximos pasos: pruebas adicionales contra otros repos y servidores para
evaluar cobertura de hallazgos, y luego Fase 2 (remediación asistida) sobre
un proyecto sin riesgo.
