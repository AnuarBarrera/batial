import click
from cybersec import config
from cybersec.domain.entities import ScanScope
from cybersec.infrastructure.tools.registry import get_registry
from cybersec.application.agent import SecurityAgent
from cybersec.application.report import ReportGenerator, format_report_text


def _build_adapter(adapter_name: str):
    if adapter_name == "gemini":
        from cybersec.infrastructure.adapters.gemini import GeminiAdapter
        if not config.GEMINI_API_KEY:
            raise click.UsageError("GEMINI_API_KEY no configurada en .env")
        return GeminiAdapter(api_key=config.GEMINI_API_KEY)
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
@click.option("--adapter", default="gemini", type=click.Choice(["gemini", "openai"]),
              show_default=True, help="Adaptador LLM a usar")
def scan(host, logs, code_dir, types, email, adapter):
    """Ejecuta un análisis de seguridad en el sistema."""
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
    registry = get_registry()
    agent = SecurityAgent(adapter=llm, tool_registry=registry)

    with click.progressbar(length=1, label="Analizando sistema", show_eta=False) as bar:
        analysis_text = agent.run(scope)
        bar.update(1)

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
