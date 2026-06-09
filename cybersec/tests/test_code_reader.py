# cybersec/tests/test_code_reader.py
import pytest
from cybersec.infrastructure.tools.code_reader import CodeReaderTool

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
    f.write_text("x = 1\n" * 500)
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is True
    assert r.metadata["truncated"] is True
    assert "truncado" in r.content.lower()

def test_rejects_binary_extension(tmp_path):
    f = tmp_path / "app.exe"
    f.write_bytes(b"\x00\x01")
    r = CodeReaderTool().execute(file_path=str(f))
    assert r.success is False
