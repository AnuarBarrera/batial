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
from cybersec.application.context_loader import load_project_context, load_exceptions
from cybersec.application.report import ReportGenerator, format_report_text


_COST_PER_1M = {
    "gemini-2.5-flash":      {"input": 0.075,  "output": 0.30},
    "gemini-2.5-pro":        {"input": 1.25,   "output": 10.00},
    "claude-haiku-4-5":      {"input": 0.80,   "output": 4.00},
    "claude-sonnet-4-5":     {"input": 3.00,   "output": 15.00},
    "claude-sonnet-4-6":     {"input": 3.00,   "output": 15.00},
    "claude-opus-4-8":       {"input": 15.00,  "output": 75.00},
}

def _print_token_summary(usage, adapter: str, model: str | None) -> None:
    if not usage or usage.total == 0:
        return
    effective_model = model or {"vertex": "gemini-2.5-flash", "gemini": "gemini-3.1-flash-lite",
                                 "anthropic-vertex": "claude-sonnet-4-5"}.get(adapter, "")
    click.echo("\n" + "─" * 60)
    click.echo(f"Tokens utilizados: {usage.input_tokens:,} entrada / {usage.output_tokens:,} salida "
               f"(total: {usage.total:,})")
    prices = _COST_PER_1M.get(effective_model)
    if prices:
        cost = (usage.input_tokens * prices["input"] + usage.output_tokens * prices["output"]) / 1_000_000
        click.echo(f"Costo estimado ({effective_model}): ${cost:.4f} USD")
    else:
        comparisons = []
        for m, p in _COST_PER_1M.items():
            c = (usage.input_tokens * p["input"] + usage.output_tokens * p["output"]) / 1_000_000
            comparisons.append(f"{m}: ${c:.4f}")
        click.echo("Costo estimado por modelo:")
        for line in comparisons:
            click.echo(f"  {line}")
    click.echo("─" * 60)


def _build_adapter(adapter_name: str, model: str = None, temperature: float = None, location: str = None):
    if adapter_name == "anthropic-vertex":
        from cybersec.infrastructure.adapters.anthropic_vertex import AnthropicVertexAdapter
        return AnthropicVertexAdapter(
            model=model or config.ANTHROPIC_VERTEX_MODEL,
            project=config.ANTHROPIC_VERTEX_PROJECT,
            region=location or config.ANTHROPIC_VERTEX_REGION,
            temperature=temperature,
        )
    elif adapter_name == "vertex":
        from cybersec.infrastructure.adapters.gemini import GeminiAdapter
        return GeminiAdapter(
            model=model or config.GEMINI_VERTEX_MODEL,
            temperature=temperature,
            project=config.GOOGLE_CLOUD_PROJECT,
            location=location or config.GOOGLE_CLOUD_LOCATION,
        )
    elif adapter_name == "gemini":
        from cybersec.infrastructure.adapters.gemini import GeminiAdapter
        if not config.GEMINI_API_KEY:
            raise click.UsageError("GEMINI_API_KEY no configurada en .env")
        return GeminiAdapter(api_key=config.GEMINI_API_KEY, model=model or config.GEMINI_MODEL, temperature=temperature)
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
@click.option("--adapter", default="gemini",
              type=click.Choice(["gemini", "openai", "vertex", "anthropic-vertex"]),
              show_default=True, help="Adaptador LLM a usar")
@click.option("--model", default=None,
              help="Modelo a usar (override del configurado por defecto, ej: claude-opus-4-8, gemini-2.5-pro)")
@click.option("--audit-model", default=None,
              help="Modelo para el paso de auditoría (override). Default: mismo adaptador con modelo de config)")
@click.option("--location", default=None,
              help="Región de Vertex AI (ej: us-central1, global). Override de GOOGLE_CLOUD_LOCATION / ANTHROPIC_VERTEX_REGION)")
@click.option("--trace-dir", default=None,
              help="Directorio donde guardar un trace JSONL de la corrida (diagnóstico)")
@click.option("--max-iterations", default=None, type=int,
              help="Límite de iteraciones del agente (default: 15). Sube para análisis más exhaustivos.")
@click.option("--verbose", is_flag=True, default=False,
              help="Muestra herramientas llamadas en cada iteración en lugar de la barra de progreso.")
@click.option("--exceptions-file", default=None,
              help="Archivo .md con hallazgos aceptados a nivel de host (puertos, infra). "
                   "Para excepciones de código coloca .cybersec-exceptions.md en --code-dir.")
def scan(host, logs, code_dir, types, email, adapter, model, audit_model, location, trace_dir,
         max_iterations, verbose, exceptions_file):
    """Ejecuta un análisis de seguridad en el sistema."""
    warnings = check_preconditions()
    for warning in warnings:
        click.echo(click.style(f"⚠️  {warning}", fg="yellow"))
    if warnings:
        click.echo()

    scope = ScanScope(
        target_host=host,
        log_files=list(logs),
        code_directory=code_dir,
        analysis_types=list(types) or ["network", "logs", "deps", "config"],
        email_report_to=email,
    )

    click.echo(f"\nIniciando análisis de seguridad en {host}...")
    click.echo(f"   Análisis: {', '.join(scope.analysis_types)}")
    if logs:
        click.echo(f"   Logs: {', '.join(logs)}")
    click.echo()

    llm = _build_adapter(adapter, model=model, location=location)
    if adapter == "gemini":
        audit_llm = _build_adapter("gemini", model=audit_model or config.GEMINI_AUDIT_MODEL, temperature=0.0)
    elif adapter == "vertex":
        audit_llm = _build_adapter("vertex", model=audit_model or config.GEMINI_VERTEX_AUDIT_MODEL, temperature=0.0, location=location)
    elif adapter == "anthropic-vertex":
        audit_llm = _build_adapter("anthropic-vertex", model=audit_model or config.ANTHROPIC_VERTEX_AUDIT_MODEL, temperature=0.0, location=location)
    else:
        audit_llm = None
    registry = get_registry()

    trace_cm = nullcontext()
    if trace_dir:
        Path(trace_dir).mkdir(parents=True, exist_ok=True)
        trace_path = Path(trace_dir) / f"run-{datetime.now().strftime('%Y%m%dT%H%M%S%f')}.jsonl"
        trace_cm = RunTracer(trace_path)
        click.echo(f"Trace de diagnóstico: {trace_path}")

    project_context = load_project_context(code_dir)
    accepted = load_exceptions(code_dir, exceptions_file)

    with trace_cm as tracer:
        effective_max = max_iterations or 15
        agent = SecurityAgent(
            adapter=llm, tool_registry=registry, audit_adapter=audit_llm, tracer=tracer,
            **({"max_iterations": max_iterations} if max_iterations is not None else {}),
        )

        if verbose:
            def _on_iteration(num: int, tool_calls: list) -> None:
                if not tool_calls:
                    click.echo(f"[{num}/{effective_max}] → sin herramientas — generando reporte")
                    return
                parts = []
                for tc in tool_calls:
                    args = tc.get("args", {})
                    first_val = next(iter(args.values()), None) if args else None
                    if first_val and isinstance(first_val, str):
                        label = f"{tc['name']}({first_val.split('/')[-1]})"
                    else:
                        label = tc["name"]
                    parts.append(label)
                click.echo(f"[{num}/{effective_max}] {', '.join(parts)}")

            analysis_text, token_usage = agent.run(
                scope,
                on_progress=lambda step: click.echo(f"  {step}") if "Auditando" in step else None,
                on_iteration=_on_iteration,
                project_context=project_context,
                accepted_findings=accepted,
            )
        else:
            total_steps = effective_max + 1
            with click.progressbar(length=total_steps, label="Analizando sistema",
                                    item_show_func=lambda step: step or "", show_eta=False) as bar:
                analysis_text, token_usage = agent.run(
                    scope,
                    on_progress=lambda step: bar.update(1, current_item=step),
                    project_context=project_context,
                    accepted_findings=accepted,
                )
                bar.update(max(0, bar.length - bar.pos), current_item="Completado")

    report = ReportGenerator().from_agent_output(agent_text=analysis_text, scope=scope)
    report_text = format_report_text(report)
    click.echo("\n" + report_text)

    _print_token_summary(token_usage, adapter, model)

    if email:
        from cybersec.infrastructure.notifiers.email import MailgunNotifier
        notifier = MailgunNotifier(
            api_key=config.MAILGUN_API_KEY,
            domain=config.MAILGUN_DOMAIN,
            sender=config.MAILGUN_SENDER_EMAIL,
        )
        if notifier.send(to=email, subject=f"Reporte de Seguridad — {host}", body=report_text):
            click.echo(f"\nReporte enviado a {email}")
        else:
            click.echo(f"\nNo se pudo enviar el reporte a {email}")
