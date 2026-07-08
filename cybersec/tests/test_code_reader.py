# cybersec/tests/test_code_reader.py
import pytest
from cybersec.infrastructure.tools.code_reader import CodeReaderTool, ListCodeFilesTool

def test_name():
    assert CodeReaderTool().name == "read_code_snippet"

def test_reads_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('import os\npassword = "hardcoded"\n')
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert "import os" in r.content
    assert r.metadata["lines"] == 2

def test_missing_file():
    r = CodeReaderTool().execute(file_path="/no/existe.py")
    assert r.success is False

def test_truncates_large_file(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("x = 1\n" * 1200)
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert r.metadata["truncated"] is True
    assert "truncado" in r.content.lower()

def test_rejects_binary_extension(tmp_path):
    f = tmp_path / "app.exe"
    f.write_bytes(b"\x00\x01")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is False


def test_list_code_files_name():
    assert ListCodeFilesTool().name == "list_code_files"


def test_list_code_files_finds_relevant_files(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')")
    (tmp_path / "readme.md").write_text("# readme")
    (tmp_path / "config.yaml").write_text("key: value")
    r = ListCodeFilesTool().execute(directory=str(tmp_path))
    assert r.success is True
    assert "app.py" in r.content
    assert "config.yaml" in r.content
    assert "readme.md" in r.content


def test_list_code_files_excludes_noise_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x = 1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("module.exports = {}")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.cfg").write_text("[core]")
    r = ListCodeFilesTool().execute(directory=str(tmp_path))
    assert "main.py" in r.content
    assert "node_modules" not in r.content
    assert ".git" not in r.content


def test_list_code_files_includes_env_dotfile(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / ".env").write_text("API_KEY=secret")
    r = ListCodeFilesTool().execute(directory=str(tmp_path))
    assert "app.py" in r.content
    assert ".env" in r.content


def test_list_code_files_includes_env_variants(tmp_path):
    (tmp_path / ".env.local").write_text("DEBUG=True")
    (tmp_path / ".env.production").write_text("SECRET=abc")
    (tmp_path / "prod.env").write_text("TOKEN=xyz")
    r = ListCodeFilesTool().execute(directory=str(tmp_path))
    assert ".env.local" in r.content
    assert ".env.production" in r.content
    assert "prod.env" in r.content


def test_read_code_snippet_redacts_env_secrets(tmp_path):
    f = tmp_path / ".env"
    f.write_text("API_KEY=supersecret123\nDEBUG=True\nSECRET_KEY=abc-xyz-789\n")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert "API_KEY=[REDACTED]" in r.content
    assert "SECRET_KEY=[REDACTED]" in r.content
    assert "supersecret123" not in r.content
    assert "abc-xyz-789" not in r.content
    assert "DEBUG=True" in r.content


def test_read_code_snippet_redacts_env_extension_file(tmp_path):
    f = tmp_path / "prod.env"
    f.write_text("DATABASE_URL=postgres://user:pass@host/db\nDEBUG=false\n")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert "DATABASE_URL=[REDACTED]" in r.content
    assert "postgres://user:pass@host/db" not in r.content
    assert "DEBUG=false" in r.content


def test_read_code_snippet_preserves_comments_and_empty_lines_in_env(tmp_path):
    f = tmp_path / ".env"
    f.write_text("# Configuración\n\nAPI_KEY=secret\nDEBUG=True\n")
    r = CodeReaderTool().execute(file_path=str(f))
    assert "# Configuración" in r.content
    assert "API_KEY=[REDACTED]" in r.content
    assert "DEBUG=True" in r.content


def test_read_code_snippet_shows_redacted_note_for_env_files(tmp_path):
    f = tmp_path / ".env"
    f.write_text("KEY=value\n")
    r = CodeReaderTool().execute(file_path=str(f))
    assert "redactados" in r.content


def test_list_code_files_missing_directory():
    r = ListCodeFilesTool().execute(directory="/no/existe")
    assert r.success is False


def test_reads_file_inside_code_directory(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    r = CodeReaderTool().execute(file_path=str(tmp_path / "app.py"), code_directory=str(tmp_path))
    assert r.success is True
    assert "x = 1" in r.content


def test_rejects_file_outside_code_directory(tmp_path):
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    outside = tmp_path / "secret.env"
    outside.write_text("API_KEY=supersecret")
    r = CodeReaderTool().execute(file_path=str(outside), code_directory=str(code_dir))
    assert r.success is False
    assert "supersecret" not in r.content


def test_rejects_traversal_outside_code_directory(tmp_path):
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    outside = tmp_path / "secret.env"
    outside.write_text("API_KEY=supersecret")
    r = CodeReaderTool().execute(file_path=str(code_dir / "../secret.env"), code_directory=str(code_dir))
    assert r.success is False
    assert "supersecret" not in r.content


def test_ignores_code_directory_when_not_provided(tmp_path):
    # Compatibilidad hacia atrás: sin code_directory, no hay confinamiento (llamadas directas/tests).
    f = tmp_path / "app.py"
    f.write_text("x = 1")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True


def test_list_code_files_allows_directory_equal_to_code_directory(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    r = ListCodeFilesTool().execute(directory=str(tmp_path), code_directory=str(tmp_path))
    assert r.success is True
    assert "app.py" in r.content


def test_list_code_files_rejects_directory_outside_code_directory(tmp_path):
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    outside = tmp_path / "other"
    outside.mkdir()
    (outside / "secret.py").write_text("TOKEN = 'x'")
    r = ListCodeFilesTool().execute(directory=str(outside), code_directory=str(code_dir))
    assert r.success is False
