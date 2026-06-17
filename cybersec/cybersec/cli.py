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


def _build_adapter(adapter_name: str, model: str = None, temperature: float = None):
    if adapter_name == "vertex":
        from cybersec.infrastructure.adapters.gemini import GeminiAdapter
        return GeminiAdapter(
            model=model or config.GEMINI_VERTEX_MODEL,
            temperature=temperature,
            project=config.GOOGLE_CLOUD_PROJECT,
            location=config.GOOGLE_CLOUD_LOCATION,
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
@click.option("--adapter", default="gemini", type=click.Choice(["gemini", "openai", "vertex"]),
              show_default=True, help="Adaptador LLM a usar (vertex usa ADC del servidor)")
@click.option("--trace-dir", default=None,
              help="Directorio donde guardar un trace JSONL de la corrida (diagnóstico)")
def scan(host, logs, code_dir, types, email, adapter, trace_dir):
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

    llm = _build_adapter(adapter)
    if adapter == "gemini":
        audit_llm = _build_adapter("gemini", model=config.GEMINI_AUDIT_MODEL, temperature=0.0)
    elif adapter == "vertex":
        audit_llm = _build_adapter("vertex", model=config.GEMINI_VERTEX_AUDIT_MODEL, temperature=0.0)
    else:
        audit_llm = None
    registry = get_registry()

    trace_cm = nullcontext()
    if trace_dir:
        Path(trace_dir).mkdir(parents=True, exist_ok=True)
        trace_path = Path(trace_dir) / f"run-{datetime.now().strftime('%Y%m%dT%H%M%S%f')}.jsonl"
        trace_cm = RunTracer(trace_path)
        click.echo(f"Trace de diagnóstico: {trace_path}")

    with trace_cm as tracer:
        agent = SecurityAgent(adapter=llm, tool_registry=registry, audit_adapter=audit_llm, tracer=tracer)

        # Estimación de pasos: hasta max_iterations del loop + 1 paso de auditoría final.
        # Si el agente termina antes, la barra se completa al 100% al finalizar.
        total_steps = 11
        with click.progressbar(length=total_steps, label="Analizando sistema",
                                item_show_func=lambda step: step or "", show_eta=False) as bar:
            analysis_text = agent.run(scope, on_progress=lambda step: bar.update(1, current_item=step))
            bar.update(max(0, bar.length - bar.pos), current_item="Completado")

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
            click.echo(f"\nReporte enviado a {email}")
        else:
            click.echo(f"\nNo se pudo enviar el reporte a {email}")
