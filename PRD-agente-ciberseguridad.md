# PRD — Agente de Ciberseguridad con IA
**Versión:** 0.2 — Revisado post-feedback  
**Fecha:** Junio 2026  
**Estado:** En definición  
**Changelog v0.2:** Corrección narrativa de privacidad (5.1), profundidad MVP de tools (4.3), nota arquitectural Fase 3 (3)

---

## 1. Contexto y Motivación

Este proyecto nace en el contexto de un hackathon de Google (agentes de IA), donde se desarrolló previamente un agente de branding que extrae el DNA de marca desde una URL y genera contenido profesional (imágenes, copy, hashtags). Con créditos adicionales de $1,000 USD vigentes por un año, se abre la oportunidad de construir un segundo agente orientado a ciberseguridad.

El dolor identificado en el mercado objetivo (PYMEs, startups, equipos técnicos pequeños) es la falta de presupuesto y expertise para mantener una postura de seguridad activa. No tienen un equipo de seguridad dedicado, pero sí tienen infraestructura vulnerable.

---

## 2. Objetivo del Producto

Construir un agente de IA de ciberseguridad que analice el estado de seguridad de un sistema local, genere un diagnóstico accionable y, en fases posteriores, aplique parches y monitoree en tiempo real.

---

## 3. Roadmap por Fases

### Fase 1 — Diagnóstico (MVP) ✅ Prioridad actual
Agente que analiza un sistema definido por el usuario y genera un reporte de vulnerabilidades estructurado.

### Fase 2 — Remediación Asistida
El agente propone y aplica parches sin interrumpir producción. Incluye sandboxing, testing automatizado y rollback.

### Fase 3 — Monitoreo en Vivo
El agente escucha eventos del sistema en tiempo real, detecta patrones de ataque y genera alertas.

> **Nota arquitectural:** La Fase 3 implica un cambio de paradigma. El "cliente local" deja de ser una CLI que el usuario ejecuta manualmente y se convierte en un **servicio de fondo (daemon / systemd service)** que corre 24/7 en el servidor del cliente. Este cambio debe planificarse antes de iniciar Fase 3 — no es una extensión natural del CLI, es una re-arquitectura del cliente.

---

## 4. Alcance — Fase 1 (MVP)

### 4.1 Interfaz de Usuario
- **CLI interactiva** como interfaz principal
- Comunicación síncrona: el usuario espera el resultado en la misma sesión
- Notificaciones asíncronas vía **email (Mailgun)** al finalizar el análisis
- Reporte también disponible en **UI** (web o TUI, a definir)

### 4.2 Scope Definition
Al iniciar sesión, el usuario define el alcance del análisis:
- Servicios / logs a analizar (auth.log, syslog, nginx, apache, etc.)
- Directorio de código a inspeccionar
- Rango de tiempo para análisis de logs
- Tipo de análisis: red, dependencias, configuración, código

Sin scope definido el agente no inicia el análisis.

### 4.3 Tools del Agente
El agente dispone de las siguientes herramientas ejecutadas en local. En el MVP cada tool tiene **alcance limitado y deliberado** — el objetivo es que el pipeline completo funcione end-to-end, no que cada tool sea exhaustiva.

| Tool | Descripción | Profundidad MVP |
|---|---|---|
| `scan_ports()` | Wrapper de nmap — detecta puertos abiertos y servicios expuestos | Top 100 puertos, sin fingerprinting profundo |
| `analyze_logs()` | Parsea auth.log, syslog, nginx/apache logs en busca de anomalías | Patrones básicos: failed logins, IPs repetidas, errores 5xx |
| `check_dependencies()` | Busca CVEs conocidos en paquetes instalados (pip, npm, apt) | Consulta a base CVE pública, sin exploits ni scoring detallado |
| `read_code_snippet()` | Pasa fragmentos de código al LLM para análisis estático | Archivos individuales, sin análisis de flujo entre módulos |
| `check_configs()` | Revisa permisos de archivos, SSH config, reglas de firewall | Checklist fijo de malas prácticas comunes |

> **Decisión de diseño:** Se mantienen las 5 tools en el MVP para demostrar el alcance completo del producto. La calidad y profundidad de cada una se incrementa en iteraciones posteriores. Reducir a 2 tools limitaría la propuesta de valor percibida en el hackathon y con clientes.

### 4.4 Formato del Reporte
El reporte de salida debe tener estructura fija y ser legible por perfiles no técnicos:

```
REPORTE DE SEGURIDAD — [fecha] — [scope]

RESUMEN EJECUTIVO
  Total hallazgos: X (Critical: N, High: N, Medium: N, Low: N)

HALLAZGOS
  [ID] Título del hallazgo
  Severidad: Critical / High / Medium / Low
  Evidencia: línea de log o fragmento de código
  Recomendación: acción concreta a tomar

PRÓXIMOS PASOS
  Lista priorizada de acciones
```

El reporte se entrega:
1. En pantalla al finalizar la sesión CLI
2. Por email vía Mailgun

---

## 5. Arquitectura Técnica

### 5.1 Modelo Híbrido

```
[Cliente Local]                        [GCP — Instancia Privada]
─────────────────────                  ─────────────────────────
CLI (interfaz)                         LLM Server (vLLM)
Tool Registry          ←── API ───→    Qwen2.5-Coder 14B
Session Manager                        Solo razona sobre
Logs, código, red                      fragmentos procesados
Notifiers (mail/TG)                    Zero-retention policy
```

**Modelo de privacidad:** Los fragmentos de logs y código procesados por las tools **sí viajan al LLM** para su análisis — eso es inherente al funcionamiento del agente. La diferencia clave es que el LLM corre en **tu propia instancia privada de GCP**, no en una API pública de terceros. Esto significa:

- Ningún proveedor externo (OpenAI, Anthropic, Google) procesa los datos del cliente
- La instancia de vLLM opera con **zero-retention** — no almacena prompts ni respuestas en disco
- El cliente controla completamente quién tiene acceso a la instancia GCP

**Mitigación opcional para clientes con requerimientos estrictos:** Agregar un paso de anonimización en el cliente antes de enviar datos al LLM — reemplazar IPs, tokens, nombres de usuario y rutas absolutas por placeholders genéricos. Esto es un nice-to-have para Fase 1, no un bloqueante.

### 5.2 LLM Adapter — Agnóstico desde el día 1

El agente no debe acoplarse a ningún proveedor de LLM. Se define una interfaz base:

```python
# base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class Message:
    role: str        # "user", "assistant", "tool"
    content: str
    tool_calls: list = None
    tool_results: list = None

class LLMAdapter(ABC):
    @abstractmethod
    def chat(self, messages: list[Message], tools: list = None) -> Message:
        pass

    @abstractmethod
    def supports_tools(self) -> bool:
        pass
```

Implementaciones iniciales:

```python
# adapters/gemini.py      — usa créditos del hackathon
# adapters/openai_compat.py — apunta a vLLM en GCP, Ollama, Groq, Together, OpenRouter
```

El agente solo conoce `LLMAdapter`. Cambiar de proveedor es cambiar una línea de configuración.

### 5.3 Modelo LLM Recomendado

| Modelo | VRAM | Caso de uso |
|---|---|---|
| Qwen2.5-Coder 14B (Q4) | ~10 GB | Análisis de código y logs — opción principal |
| DeepSeek-R1 14B (Q4) | ~10 GB | Razonamiento paso a paso — alternativa |
| Llama 3.1 8B (Q4) | ~6 GB | Menor costo, suficiente para Fase 1 |

### 5.4 Infraestructura GCP

- **Instancia:** L4 GPU (~$0.70/hr)
- **Servidor LLM:** vLLM con endpoint `/v1/chat/completions` (compatible OpenAI)
- **Estrategia de costos (producción):** GPU on-demand — prende al iniciar sesión, se apaga tras X minutos de inactividad, automatizado con Cloud Run
- **Estrategia MVP / Hackathon:** La instancia permanece encendida durante el desarrollo y las demos. El on-demand es una optimización de costos para después, no un requisito del MVP.

> **Nota de UX — Latencia de arranque:** Si la GPU está apagada, el arranque completo (VM + carga del modelo en VRAM) toma entre 2 y 4 minutos. En una CLI síncrona esto se percibe como un cuelgue. Para producción con on-demand, la solución es mostrar un spinner con mensajes de estado ("Iniciando infraestructura...", "Cargando modelo...") o bien pre-calentar la instancia al detectar la primera conexión del cliente antes de que el análisis empiece.

### 5.5 Infraestructura Existente (reutilizable)

| Componente | Uso en este proyecto |
|---|---|
| Gemini Adapter | Adapter inicial mientras se configura GCP |
| Mailgun | Envío del reporte final por email |
| Telegram Bot | Notificaciones de sesión completada (secundario) |
| Webhook | Posible integración futura con servicios de monitoreo |

---

## 6. Stack Tecnológico

| Capa | Tecnología |
|---|---|
| Lenguaje | Python |
| CLI | Click o Typer |
| Tool execution | Subprocess + wrappers Python |
| LLM client | Interfaz propia (LLMAdapter) |
| LLM en GCP | vLLM + Qwen2.5-Coder 14B |
| LLM inicial | Gemini (adapter existente del hackathon) |
| Email | Mailgun (infraestructura existente) |
| Mensajería | Telegram Bot (infraestructura existente) |

---

## 7. Criterios de Éxito — Fase 1

- [ ] El agente completa un análisis de scope definido sin intervención manual
- [ ] El reporte incluye al menos una vulnerabilidad con evidencia concreta y recomendación accionable
- [ ] El reporte llega por email al finalizar la sesión
- [ ] El adapter de LLM puede cambiar de Gemini a OpenAI-compatible sin modificar lógica del agente
- [ ] El agente funciona con Qwen 14B en GCP y también en local (Ollama) sin cambios de código

---

## 8. Riesgos y Consideraciones

| Riesgo | Mitigación |
|---|---|
| Presupuesto GPU ($1,000/año) | GPU on-demand en producción; instancia fija durante MVP y hackathon |
| Narrativa de privacidad mal comunicada | Clarificar que los datos van a instancia GCP privada con zero-retention, no a APIs públicas |
| Falsos positivos en diagnóstico | Severidad basada en evidencia concreta, no heurísticas vagas |
| Latencia de arranque GPU en producción | Spinner con mensajes de estado; pre-calentamiento de instancia al conectar cliente |
| Responsabilidad legal en Fase 2 (parches automáticos) | Fase 2 requiere confirmación explícita del usuario antes de aplicar cambios |
| Acoplamiento al SDK de Google | Desacoplar adapter antes de construir tools — prioridad inmediata |

---

## 9. Fuera de Alcance (Fase 1)

- Aplicación automática de parches (Fase 2)
- Monitoreo en tiempo real (Fase 3)
- Soporte para Windows (inicialmente solo Linux)
- Análisis de infraestructura cloud (AWS, GCP, Azure)
- Interfaz web (el CLI es suficiente para validar el producto)

---

## 10. Próximos Pasos Inmediatos

1. **Desacoplar el adapter de Gemini** — crear `LLMAdapter` base + `GeminiAdapter` + `OpenAICompatAdapter`
2. **Scaffold del CLI** — estructura de proyecto, session manager, tool registry vacío
3. **Implementar primera tool** — `analyze_logs()` como prueba de concepto end-to-end
4. **Configurar vLLM en GCP** — instancia L4 con Qwen2.5-Coder 14B, endpoint compatible OpenAI
5. **Primera sesión completa** — scope → tool → LLM → reporte en pantalla

---

*Este PRD es un documento vivo. Se actualiza conforme avanza el desarrollo.*
