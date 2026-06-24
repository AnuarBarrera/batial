import os
import re
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

MAX_LINES = 1000
MAX_FILES = 500
ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".sh",
                      ".yaml", ".yml", ".env", ".conf", ".cfg", ".ini", ".toml"}
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".pytest_cache"}

_ENV_SAFE_VALUES = {"", "true", "false", "yes", "no", "0", "1", "none", "null", "*",
                    "localhost", "127.0.0.1", "development", "production", "staging"}


def _is_env_file(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith(".env") or path.suffix.lower() == ".env"


def _is_allowed(path: Path) -> bool:
    return path.suffix.lower() in ALLOWED_EXTENSIONS or _is_env_file(path)


def _redact_env_values(content: str) -> str:
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
        if m:
            key = m.group(1)
            raw_value = m.group(2).strip()
            unquoted = raw_value.strip('"').strip("'").lower()
            if unquoted in _ENV_SAFE_VALUES:
                lines.append(line)
            else:
                lines.append(f"{key}=[REDACTED]")
        else:
            lines.append(line)
    return "\n".join(lines)


class CodeReaderTool(BaseTool):
    name = "read_code_snippet"

    def execute(self, file_path: str = "", **kwargs) -> ToolResult:
        path = Path(file_path)
        if not path.exists():
            return self._error(f"Archivo no existe: {file_path}")
        if not _is_allowed(path):
            return self._error(f"Extensión no permitida: {path.suffix}")
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as e:
            return self._error(f"Error leyendo {file_path}: {e}")

        truncated = len(lines) > MAX_LINES
        snippet = "\n".join(lines[:MAX_LINES])
        trunc_suffix = f"\n\n[archivo truncado — primeras {MAX_LINES} de {len(lines)} líneas]" if truncated else ""

        if _is_env_file(path):
            snippet = _redact_env_values(snippet)
            header = (f"# {file_path}\n"
                      "[valores de variables redactados — solo se muestran nombres de clave "
                      "y valores no sensibles (true/false, localhost, vacíos)]\n```env\n")
        else:
            ext = path.suffix.lstrip(".")
            header = f"# {file_path}\n```{ext}\n"

        content = f"{header}{snippet}{trunc_suffix}\n```"
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
                if _is_allowed(Path(filename)):
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
