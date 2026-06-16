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
    assert "readme.md" not in r.content


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


def test_list_code_files_excludes_env_files(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / ".env").write_text("API_KEY=secret")
    r = ListCodeFilesTool().execute(directory=str(tmp_path))
    assert "app.py" in r.content
    assert ".env" not in r.content


def test_list_code_files_missing_directory():
    r = ListCodeFilesTool().execute(directory="/no/existe")
    assert r.success is False
