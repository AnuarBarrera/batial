from pathlib import Path

CONTEXT_FILES = ["CLAUDE.md", "GEMINI.md", "AGENTS.md", "memory.md"]
EXCEPTIONS_FILENAME = ".cybersec-exceptions.md"
MAX_CHARS_PER_FILE = 6000


def load_project_context(code_directory: str | None) -> str:
    if not code_directory:
        return ""
    base = Path(code_directory)
    sections = []
    for filename in CONTEXT_FILES:
        path = base / filename
        if not path.exists():
            continue
        content = path.read_text(errors="replace").strip()
        if not content:
            continue
        if len(content) > MAX_CHARS_PER_FILE:
            content = content[:MAX_CHARS_PER_FILE] + "\n\n[... truncado ...]"
        sections.append(f"### {filename}\n{content}")
    if not sections:
        return ""
    return (
        "CONTEXTO DEL PROYECTO (arquitectura, decisiones de negocio, deuda técnica conocida):\n\n"
        + "\n\n".join(sections)
    )


def load_exceptions(code_directory: str | None, exceptions_file: str | None) -> str:
    sections = []
    if exceptions_file:
        path = Path(exceptions_file)
        if path.exists():
            content = path.read_text(errors="replace").strip()
            if content:
                sections.append(content)
    if code_directory:
        path = Path(code_directory) / EXCEPTIONS_FILENAME
        if path.exists():
            content = path.read_text(errors="replace").strip()
            if content:
                sections.append(content)
    if not sections:
        return ""
    return (
        "HALLAZGOS DE SEGURIDAD ACEPTADOS FORMALMENTE (revisados y aprobados):\n"
        "Si detectas alguno de estos hallazgos, inclúyelo en HALLAZGOS_JSON con "
        '"status": "accepted" y "accepted_reason" con la razón indicada. '
        "No lo incluyas en PRÓXIMOS PASOS.\n\n"
        + "\n\n".join(sections)
    )
