# cybersec/tests/test_patcher.py
import json
from unittest.mock import MagicMock
from cybersec.domain.entities import Finding
from cybersec.domain.llm_adapter import Message
from cybersec.domain.tools import ToolResult
from cybersec.application.patcher import PatchProposer, write_patch_files, _fix_hunk_headers


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


def test_fix_hunk_headers_corrects_wrong_counts():
    # Caso real observado: el LLM dijo "9,9" pero el cuerpo del hunk tiene 7 líneas de cada lado.
    diff = (
        "--- a/core/agent/tests/test_tools.py\n"
        "+++ b/core/agent/tests/test_tools.py\n"
        "@@ -72,9 +72,9 @@\n"
        " \n"
        " class TestTranscribeAudioTool:\n"
        "-    def test_missing_file_returns_error(self):\n"
        "+    def test_missing_file_returns_error(self, tmp_path):\n"
        "         tool = TranscribeAudioTool()\n"
        "-        result = tool.execute(audio_path='/tmp/nonexistent_file_abc123.ogg')\n"
        "+        result = tool.execute(audio_path=str(tmp_path / 'nonexistent_file_abc123.ogg'))\n"
        "         assert result.success is False\n"
        "         assert result.error is not None\n"
    )
    fixed = _fix_hunk_headers(diff)
    assert "@@ -72,7 +72,7 @@" in fixed
    assert "@@ -72,9 +72,9 @@" not in fixed
    # el cuerpo del hunk no debe tocarse, solo el header
    assert "-    def test_missing_file_returns_error(self):" in fixed
    assert "+        result = tool.execute(audio_path=str(tmp_path / 'nonexistent_file_abc123.ogg'))" in fixed


def test_fix_hunk_headers_handles_multiple_hunks():
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,5 +1,6 @@\n"
        " a\n"
        " b\n"
        "+c\n"
        " d\n"
        " e\n"
        "@@ -20,3 +21,2 @@\n"
        " x\n"
        "-y\n"
        " z\n"
    )
    fixed = _fix_hunk_headers(diff)
    assert "@@ -1,4 +1,5 @@" in fixed
    assert "@@ -20,3 +21,2 @@" in fixed  # ya estaba bien, no cambia


def test_fix_hunk_headers_leaves_correct_headers_unchanged():
    diff = (
        "--- a/auth.py\n"
        "+++ b/auth.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-password = plain\n"
        "+password = hashed\n"
    )
    assert _fix_hunk_headers(diff) == diff


def test_propose_all_corrects_malformed_hunk_header_from_llm(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    # header dice "3,3" pero el cuerpo tiene solo 1 línea de cada lado — mal contado por el LLM
    bad_diff = "--- a/auth.py\n+++ b/auth.py\n@@ -1,3 +1,3 @@\n-password = plain\n+password = hashed"
    adapter = _adapter(response_content=_json_response(diff=bad_diff, explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "proposed"
    assert "@@ -1,1 +1,1 @@" in finding.patch_diff


def test_propose_all_uses_relative_path_in_prompt_when_file_path_is_absolute(tmp_path):
    # Caso real observado: el LLM devuelve file_path como ruta absoluta en
    # HALLAZGOS_JSON. El header del diff debe usar SIEMPRE la ruta relativa
    # a code_directory — una ruta absoluta en el header rompe 'git apply -p1'
    # (produce 'a/home/usuario/...' en vez de 'a/auth.py').
    (tmp_path / "auth.py").write_text("password = '123'")
    absolute_file_path = str(tmp_path / "auth.py")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path=absolute_file_path)
    adapter = _adapter(response_content=_json_response(diff="--- a/x\n+++ b/x", explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    assert finding.patch_status == "proposed"
    prompt_sent = adapter.chat.call_args[0][0][0].content
    assert absolute_file_path not in prompt_sent
    assert "auth.py" in prompt_sent
    assert f"--- a/{absolute_file_path}" not in prompt_sent


def test_propose_all_keeps_relative_path_when_file_path_already_relative(tmp_path):
    (tmp_path / "auth.py").write_text("password = '123'")
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    adapter = _adapter(response_content=_json_response(diff="--- a/x\n+++ b/x", explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool()}).propose_all([finding], str(tmp_path))
    prompt_sent = adapter.chat.call_args[0][0][0].content
    assert "Archivo afectado (auth.py):" in prompt_sent


def test_fix_hunk_headers_relocates_start_line_using_real_file_content():
    # Caso real observado: el LLM cuenta bien las líneas del hunk (old_count/
    # new_count correctos) pero calcula mal desde qué línea empieza — el
    # contexto real está 2 líneas antes de lo que dice el header.
    original_content = (
        "linea1\n"
        "linea2\n"
        "# Crear el usuario\n"
        "user = User.objects.create_user(\n"
        "    password=old_value,\n"
        ")\n"
    )
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -5,4 +5,4 @@\n"  # el LLM dice línea 5, el contexto real empieza en línea 3
        " # Crear el usuario\n"
        " user = User.objects.create_user(\n"
        "-    password=old_value,\n"
        "+    password=new_value,\n"
        " )\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    assert "@@ -3,4 +3,4 @@" in fixed
    assert "@@ -5,4 +5,4 @@" not in fixed


def test_fix_hunk_headers_leaves_start_line_unchanged_when_context_not_found():
    original_content = "algo completamente distinto\n"
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -5,2 +5,2 @@\n"
        " contexto\n"
        "-old\n"
        "+new\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    assert "@@ -5,2 +5,2 @@" in fixed


def test_fix_hunk_headers_relocates_multiple_hunks_with_cumulative_offset():
    original_content = (
        "a\n"
        "b\n"
        "c\n"
        "d\n"
        "e\n"
        "f\n"
        "g\n"
        "h\n"
        "i\n"
    )
    # ambos hunks dicen líneas erróneas; el segundo hunk debe relocalizarse
    # usando el offset acumulado del primero (que insertó 1 línea neta).
    # el primer hunk termina en una línea de contexto real (no en una
    # línea añadida) para no disparar la extensión de contexto trailing
    # y mantener el foco de este test en la relocalización con offset.
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -99,3 +99,4 @@\n"
        " a\n"
        " b\n"
        "+nueva\n"
        " c\n"
        "@@ -50,2 +50,2 @@\n"
        " h\n"
        "-i\n"
        "+i_modificada\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    assert "@@ -1,3 +1,4 @@" in fixed
    assert "@@ -8,2 +9,2 @@" in fixed


def test_propose_all_passes_real_file_content_to_hunk_relocation(tmp_path):
    (tmp_path / "auth.py").write_text(
        "linea1\npassword = 'old'\nlinea3\n"
    )
    finding = Finding("F001", "X", "Critical", "e", "r", file_path="auth.py")
    # header con línea de inicio mal calculada por el LLM (dice 99, el
    # contexto real está en la línea 2)
    bad_diff = (
        "--- a/auth.py\n+++ b/auth.py\n"
        "@@ -99,1 +99,1 @@\n"
        "-password = 'old'\n"
        "+password = 'new'\n"
    )
    adapter = _adapter(response_content=_json_response(diff=bad_diff, explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool(content="password = 'old'")}).propose_all(
        [finding], str(tmp_path)
    )
    assert finding.patch_status == "proposed"
    # el hunk original terminaba justo en la línea añadida, sin contexto;
    # se extiende con "linea3" (contexto real disponible tras la línea 2)
    assert "@@ -2,2 +2,2 @@" in finding.patch_diff
    assert " linea3" in finding.patch_diff


def test_fix_hunk_headers_adds_trailing_context_when_hunk_ends_on_added_line():
    # Caso real observado: 'git apply' rechaza un hunk que termina justo en
    # una línea añadida sin ninguna línea de contexto después, aunque el
    # contenido y la posición sean correctos. Si pudimos relocalizar el
    # hunk (conocemos su posición real), extendemos con contexto real del
    # archivo para darle a 'git apply' un ancla al final.
    original_content = (
        "def health():\n"
        "    return jsonify({'status': 'ok'})\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    port = int(os.environ.get('PORT', 8080))\n"
        "    app.run(host='0.0.0.0', port=port)\n"
    )
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,2 @@\n"  # posición irrelevante, se relocaliza
        " def health():\n"
        "-    return jsonify({'status': 'ok'})\n"
        "+    return jsonify({'status': 'healthy'})\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    # el header debe reflejar el conteo ampliado con hasta 3 líneas de
    # contexto trailing real (línea vacía + if __name__ + port=...)
    assert "@@ -1,5 +1,5 @@" in fixed
    assert "\n if __name__ == '__main__':" in fixed


def test_fix_hunk_headers_does_not_add_trailing_context_when_hunk_already_has_it():
    original_content = "a\nb\nc\nd\ne\n"
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,3 +1,3 @@\n"
        " a\n"
        "-b\n"
        "+b_new\n"
        " c\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    assert "@@ -1,3 +1,3 @@" in fixed


def test_fix_hunk_headers_does_not_add_trailing_context_when_relocation_failed():
    # sin coincidencia inequívoca (contenido no encontrado) no se agrega
    # contexto extra "adivinado" — sería inseguro sin confirmar la posición real
    original_content = "algo completamente distinto\n"
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -5,1 +5,1 @@\n"
        "-old\n"
        "+new\n"
    )
    fixed = _fix_hunk_headers(diff, original_content=original_content)
    assert "@@ -5,1 +5,1 @@" in fixed


def test_fix_hunk_headers_does_not_add_trailing_context_without_original_content():
    diff = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-old\n"
        "+new\n"
    )
    fixed = _fix_hunk_headers(diff)
    assert "@@ -1,1 +1,1 @@" in fixed


def test_propose_all_extends_trailing_context_for_real_mcp_server_case(tmp_path):
    # Reproduce el caso real de F002/run1: el LLM genera un hunk que
    # termina justo en la línea modificada (host='0.0.0.0' -> '127.0.0.1'),
    # sin contexto después, lo cual 'git apply' rechaza. A diferencia del
    # caso real (donde el cambio estaba en la última línea del archivo, sin
    # contexto real disponible para agregar), aquí el cambio está en medio
    # del archivo para verificar que SÍ se usa el contexto disponible.
    real_content = (
        "def health():\n"
        "    return jsonify({'status': 'ok'})\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    port = int(os.environ.get('PORT', 8080))\n"
        "    app.run(host='0.0.0.0', port=port)\n"
        "    log.info('started')\n"
    )
    (tmp_path / "server.py").write_text(real_content)
    finding = Finding("F001", "X", "Medium", "e", "r", file_path="server.py")
    bad_diff = (
        "--- a/server.py\n+++ b/server.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-    app.run(host='0.0.0.0', port=port)\n"
        "+    app.run(host='127.0.0.1', port=port)\n"
    )
    adapter = _adapter(response_content=_json_response(diff=bad_diff, explanation="ok"))
    PatchProposer(adapter, {"read_code_snippet": _read_tool(content=real_content)}).propose_all(
        [finding], str(tmp_path)
    )
    assert finding.patch_status == "proposed"
    # el hunk original terminaba justo en la línea modificada (2 líneas de
    # cuerpo); tras extender con contexto trailing debe incluir la línea
    # real siguiente del archivo
    assert " log.info('started')" in finding.patch_diff
