from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

MAX_LINES = 300
ALLOWED = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".sh",
           ".yaml", ".yml", ".env", ".conf", ".cfg", ".ini", ".toml"}


class CodeReaderTool(BaseTool):
    name = "read_code_snippet"

    def execute(self, file_path: str = "", **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return self._error(f"Archivo no existe: {file_path}")
        if path.suffix.lower() not in ALLOWED:
            return self._error(f"Extensión no permitida: {path.suffix}")
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as e:
            return self._error(f"Error leyendo {file_path}: {e}")

        truncated = len(lines) > MAX_LINES
        snippet = "\n".join(lines[:MAX_LINES])
        suffix = f"\n\n[archivo truncado — primeras {MAX_LINES} de {len(lines)} líneas]" if truncated else ""
        ext = path.suffix.lstrip(".")
        content = f"# {file_path}\n```{ext}\n{snippet}{suffix}\n```"
        return ToolResult(
            content=content, tool_name=self.name, success=True,
            metadata={"file_path": str(path), "lines": len(lines), "truncated": truncated},
        )
