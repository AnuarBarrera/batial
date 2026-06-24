import pytest
from cybersec.application.context_loader import load_project_context, load_exceptions, MAX_CHARS_PER_FILE


def test_load_project_context_returns_empty_when_no_dir():
    assert load_project_context(None) == ""


def test_load_project_context_returns_empty_when_no_files(tmp_path):
    assert load_project_context(str(tmp_path)) == ""


def test_load_project_context_reads_claude_md(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# Arquitectura\nUsamos Django con multi-tenant.")
    result = load_project_context(str(tmp_path))
    assert "CONTEXTO DEL PROYECTO" in result
    assert "CLAUDE.md" in result
    assert "multi-tenant" in result


def test_load_project_context_reads_multiple_files(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("contexto claude")
    (tmp_path / "GEMINI.md").write_text("contexto gemini")
    result = load_project_context(str(tmp_path))
    assert "CLAUDE.md" in result
    assert "GEMINI.md" in result
    assert "contexto claude" in result
    assert "contexto gemini" in result


def test_load_project_context_ignores_missing_files(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("solo claude")
    result = load_project_context(str(tmp_path))
    assert "GEMINI.md" not in result
    assert "solo claude" in result


def test_load_project_context_truncates_large_files(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("x" * (MAX_CHARS_PER_FILE + 500))
    result = load_project_context(str(tmp_path))
    assert "truncado" in result


def test_load_exceptions_returns_empty_when_no_sources():
    assert load_exceptions(None, None) == ""


def test_load_exceptions_reads_exceptions_file(tmp_path):
    f = tmp_path / "host-exceptions.md"
    f.write_text("## Puerto 8000\n**Razón:** Servicio LAN interno")
    result = load_exceptions(None, str(f))
    assert "HALLAZGOS DE SEGURIDAD ACEPTADOS" in result
    assert "Puerto 8000" in result


def test_load_exceptions_reads_cybersec_exceptions_from_code_dir(tmp_path):
    (tmp_path / ".cybersec-exceptions.md").write_text("## CSP unsafe-inline\n**Razón:** Templates inline")
    result = load_exceptions(str(tmp_path), None)
    assert "CSP unsafe-inline" in result


def test_load_exceptions_merges_both_sources(tmp_path):
    host_file = tmp_path / "host.md"
    host_file.write_text("## Puerto 8000\nServicio LAN")
    (tmp_path / ".cybersec-exceptions.md").write_text("## CSP unsafe\nTemplates inline")
    result = load_exceptions(str(tmp_path), str(host_file))
    assert "Puerto 8000" in result
    assert "CSP unsafe" in result


def test_load_exceptions_returns_empty_when_files_missing(tmp_path):
    assert load_exceptions(str(tmp_path), str(tmp_path / "no-existe.md")) == ""
