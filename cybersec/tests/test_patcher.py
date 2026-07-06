# cybersec/tests/test_patcher.py
import json
from unittest.mock import MagicMock
from cybersec.domain.entities import Finding
from cybersec.domain.llm_adapter import Message
from cybersec.domain.tools import ToolResult
from cybersec.application.patcher import PatchProposer, write_patch_files


def _adapter(response_content=None, raise_exc=None):
    a = MagicMock()
    if raise_exc is not None:
        a.chat.side_effect = raise_exc
    else:
        a.chat.return_value = Message(role="assistant", content=response_content)
    return a


def _read_tool(success=True, content="# arquivo\n```python\npassword = '123'\n```"):
    t = MagicMock()
    t.execute.return_value = ToolResult(content=content, tool_name="read_code_snippet", success=success)
    return t


def _json_response(diff="", explanation=""):
    body = json.dumps({"diff": diff, "explanation": explanation})
    return f"```json\n{body}\n```"


def test_propose_all_success(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "Password en texto plano", "Critical", "e", "r", file_path="auth.py")
    adapter = _adapter(response_content=_json_response(
        diff="--- a/auth.py\n+++ b/auth.py\n@@ -1 +1 @@\n-password = plain\n+password = hashed",
        explanation="Hashea la contraseña",
    ))
    registry = {"read_code_snippet": _read_tool()}
    PatchProposer(adapter, registry).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "proposed"
    assert "hashed" in finding.patch_diff
    assert finding.patch_explanation == "Hashea la contraseña"


def test_propose_all_skips_finding_without_file_path(tmp_path):
    finding = Finding("F001", "Puerto expuesto", "Medium", "e", "r")
    adapter = _adapter()
    PatchProposer(adapter, {}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == ""
    adapter.chat.assert_not_called()


def test_propose_all_marks_not_applicable_when_file_missing(tmp_path):
    finding = Finding("F001", "X", "High", "e", "r", file_path="no-existe.py")
    adapter = _adapter()
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "not_applicable"
    adapter.chat.assert_not_called()


def test_propose_all_marks_not_applicable_when_read_tool_missing(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "High", "e", "r", file_path="auth.py")
    adapter = _adapter()
    PatchProposer(adapter, {}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "not_applicable"
    adapter.chat.assert_not_called()


def test_propose_all_skips_accepted_finding(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py", status="accepted")
    adapter = _adapter()
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == ""
    adapter.chat.assert_not_called()


def test_propose_all_marks_error_on_adapter_exception(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    adapter = _adapter(raise_exc=RuntimeError("boom"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "error"


def test_propose_all_marks_error_on_invalid_json(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    adapter = _adapter(response_content="no hay json aquí")
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "error"


def test_propose_all_marks_error_on_empty_diff(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    adapter = _adapter(response_content=_json_response(diff="", explanation="no se pudo generar un parche seguro"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "error"


def test_propose_all_isolates_failures_between_findings(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    ok = Finding("F001", "OK", "Critical", "e", "r", file_path="auth.py")
    bad = Finding("F002", "Bad", "High", "e", "r", file_path="no-existe.py")
    adapter = _adapter(response_content=_json_response(diff="--- a/x\n+++ b/x", explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([bad, ok], str(tmp_path))
    assert bad.patch_status == "not_applicable"
    assert ok.patch_status == "proposed"


def test_propose_all_marks_not_applicable_for_path_outside_code_directory(tmp_path):
    code_dir = tmp_path / "project"
    code_dir.mkdir()
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("password = '123'")
    finding = Finding("F001", "X", "High", "e", "r", file_path="../outside.py")
    adapter = _adapter()
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(code_dir))
    assert finding.patch_status == "not_applicable"
    adapter.chat.assert_not_called()


def test_propose_all_marks_error_when_read_tool_raises_and_isolates_next_finding(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    failing = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    ok = Finding("F002", "OK", "Critical", "e", "r", file_path="auth.py")
    raising_tool = MagicMock()
    raising_tool.execute.side_effect = RuntimeError("disk error")
    adapter = _adapter(response_content=_json_response(diff="--- a/x\n+++ b/x", explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": raising_tool}).propose_all([failing, ok], str(tmp_path))
    assert failing.patch_status == "error"
    # ok would also error because it shares the same raising tool, but the point is propose_all
    # doesn't crash and processes both findings
    assert ok.patch_status == "error"


def test_write_patch_files_creates_dir_and_writes_diff(tmp_path):
    finding = Finding("F001", "Password en texto plano", "Critical", "e", "r")
    finding.patch_status = "proposed"
    finding.patch_diff = "--- a/auth.py\n+++ b/auth.py\n@@ -1 +1 @@\n-old\n+new"
    patch_dir = tmp_path / "patches"
    paths = write_patch_files([finding], str(patch_dir))
    expected_path = patch_dir / "F001-password-en-texto-plano.patch"
    assert paths == {"F001": str(expected_path)}
    assert expected_path.read_text().startswith("--- a/auth.py")


def test_write_patch_files_skips_non_proposed_findings(tmp_path):
    finding = Finding("F001", "X", "High", "e", "r")
    paths = write_patch_files([finding], str(tmp_path / "patches"))
    assert paths == {}
    assert not (tmp_path / "patches").exists()
