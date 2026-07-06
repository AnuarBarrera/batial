# cybersec/tests/test_domain.py
from cybersec.domain.entities import ScanScope, Finding, SecurityReport
from cybersec.domain.tools import BaseTool, ToolResult
from cybersec.domain.llm_adapter import LLMAdapter, Message
import inspect

def test_scan_scope_defaults():
    scope = ScanScope(target_host="localhost")
    assert scope.log_files == []
    assert scope.code_directory is None
    assert scope.analysis_types == []

def test_finding_fields():
    f = Finding(id="F001", title="SSH root", severity="High",
                evidence="PermitRootLogin yes", recommendation="Cambiarlo a no")
    assert f.severity == "High"

def test_security_report_summary():
    report = SecurityReport(findings=[
        Finding("F001", "A", "Critical", "e", "r"),
        Finding("F002", "B", "High", "e", "r"),
        Finding("F003", "C", "High", "e", "r"),
    ])
    s = report.summary()
    assert s["total"] == 3
    assert s["Critical"] == 1
    assert s["High"] == 2
    assert s["Medium"] == 0

def test_security_report_next_steps_default():
    report = SecurityReport()
    assert report.next_steps == []

def test_llm_adapter_is_abstract():
    assert inspect.isabstract(LLMAdapter)

def test_message_defaults():
    m = Message(role="user", content="hola")
    assert m.tool_calls is None
    assert m.tool_results is None

def test_base_tool_error_helper():
    class Dummy(BaseTool):
        name = "dummy"
        def execute(self, **kwargs) -> ToolResult:
            return self._error("fallo")
    r = Dummy().execute()
    assert r.success is False
    assert r.tool_name == "dummy"
    assert r.error == "fallo"

def test_finding_patch_fields_default_empty():
    f = Finding(id="F001", title="X", severity="High", evidence="e", recommendation="r")
    assert f.file_path == ""
    assert f.patch_diff == ""
    assert f.patch_explanation == ""
    assert f.patch_status == ""

def test_finding_accepts_patch_fields():
    f = Finding(
        id="F001", title="X", severity="High", evidence="e", recommendation="r",
        file_path="core/auth.py", patch_diff="--- a/x\n+++ b/x", patch_status="proposed",
    )
    assert f.file_path == "core/auth.py"
    assert f.patch_status == "proposed"
