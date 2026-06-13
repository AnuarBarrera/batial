import json
import subprocess
from cybersec.domain.tools import BaseTool, ToolResult
from .code_reader import EXCLUDED_DIRS

_EXCLUDE_PATTERN = ",".join(f"*/{d}/*" for d in sorted(EXCLUDED_DIRS))
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_SEVERITY_ICONS = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}
MAX_RESULTS = 25


class StaticAnalyzerTool(BaseTool):
    name = "scan_code_security"

    def execute(self, directory: str = "", **kwargs) -> ToolResult:
        if not directory:
            return self._error("Debes especificar 'directory'.")

        try:
            p = subprocess.run(
                ["bandit", "-r", directory, "-f", "json", "-q", "-x", _EXCLUDE_PATTERN],
                capture_output=True, text=True, timeout=120,
            )
        except FileNotFoundError:
            return ToolResult(
                content="ℹ️  bandit no disponible. Instala con: pip install bandit",
                tool_name=self.name, success=True,
            )
        except subprocess.TimeoutExpired:
            return self._error(f"bandit excedió el tiempo límite analizando {directory}.")

        try:
            data = json.loads(p.stdout)
        except json.JSONDecodeError:
            return self._error(f"No se pudo parsear salida de bandit: {p.stderr or p.stdout}")

        results = sorted(
            data.get("results", []),
            key=lambda r: _SEVERITY_ORDER.get(r.get("issue_severity"), 3),
        )
        if not results:
            return ToolResult(
                content=f"✅ bandit: sin hallazgos de seguridad en {directory}.",
                tool_name=self.name, success=True, metadata={"directory": directory, "count": 0},
            )

        counts: dict[str, int] = {}
        for r in results:
            sev = r.get("issue_severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
        summary = ", ".join(
            f"{sev}: {n}" for sev, n in sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 3))
        )

        lines = [f"bandit — {len(results)} hallazgo(s) en {directory} ({summary}):"]
        for r in results[:MAX_RESULTS]:
            sev = r.get("issue_severity", "UNKNOWN")
            icon = _SEVERITY_ICONS.get(sev, "⚪")
            lines.append(
                f"  {icon} [{sev}] {r.get('test_id')} {r.get('test_name')} — "
                f"{r.get('filename')}:{r.get('line_number')} — {r.get('issue_text')}"
            )
        if len(results) > MAX_RESULTS:
            lines.append(f"  ... ({len(results) - MAX_RESULTS} hallazgos adicionales omitidos)")

        return ToolResult(
            content="\n".join(lines), tool_name=self.name, success=True,
            metadata={"directory": directory, "count": len(results), "by_severity": counts},
        )
