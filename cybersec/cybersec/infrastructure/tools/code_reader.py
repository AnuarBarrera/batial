import os
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

MAX_LINES = 300
MAX_FILES = 200
ALLOWED = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".sh",
           ".yaml", ".yml", ".env", ".conf", ".cfg", ".ini", ".toml"}
# .env excluido del listado para no exponer secretos al LLM al enumerar archivos.
LISTABLE = ALLOWED - {".env"}
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".pytest_cache"}


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


class ListCodeFilesTool(BaseTool):
    name = "list_code_files"

    def execute(self, directory: str = "", **kwargs) -> ToolResult:
        path = Path(directory)
        if not path.is_dir():
            return self._error(f"Directorio no existe: {directory}")

        files = []
        for root, dirs, filenames in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS)
            for filename in sorted(filenames):
                if Path(filename).suffix.lower() in LISTABLE:
                    files.append(str(Path(root) / filename))
                    if len(files) >= MAX_FILES:
                        break
            if len(files) >= MAX_FILES:
                break

        if not files:
            return ToolResult(
                content=f"No se encontraron archivos de código relevantes en {directory}.",
                tool_name=self.name, success=True, metadata={"directory": directory, "count": 0},
            )

        content = "\n".join(files)
        if len(files) >= MAX_FILES:
            content += f"\n\n[lista truncada a {MAX_FILES} archivos]"
        return ToolResult(
            content=content, tool_name=self.name, success=True,
            metadata={"directory": directory, "count": len(files)},
        )
