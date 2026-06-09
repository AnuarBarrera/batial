import re
import logging
from collections import defaultdict
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_FAILED_SSH = re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)")
_NGINX_5XX = re.compile(r'" [5]\d{2} ')
_SUDO = re.compile(r"sudo:.*COMMAND=")
BRUTE_THRESHOLD = 10


class LogAnalyzerTool(BaseTool):
    name = "analyze_logs"

    def execute(self, log_files: list[str] = None, **kwargs) -> ToolResult:
        if not log_files:
            return self._error("No se proporcionaron archivos de log.")

        found = [p for p in log_files if Path(p).exists()]
        if not found:
            return self._error(f"Archivos no encontrados: {log_files}")

        failed: defaultdict[str, int] = defaultdict(int)
        errors_5xx: list[str] = []
        sudo_events: list[str] = []
        total_lines = 0

        for path in found:
            try:
                lines = Path(path).read_text(errors="replace").splitlines()
            except OSError as e:
                logger.warning(f"No se pudo leer {path}: {e}")
                continue
            total_lines += len(lines)
            for line in lines:
                m = _FAILED_SSH.search(line)
                if m:
                    failed[m.group(1)] += 1
                if _NGINX_5XX.search(line):
                    errors_5xx.append(line.strip())
                if _SUDO.search(line):
                    sudo_events.append(line.strip())

        findings = []
        brute_ips = []
        for ip, count in failed.items():
            if count > BRUTE_THRESHOLD:
                findings.append(f"⚠️  Brute force SSH desde {ip}: {count} intentos fallidos")
                brute_ips.append(ip)
            else:
                findings.append(f"ℹ️  Intentos SSH fallidos desde {ip}: {count}")

        for line in errors_5xx[:10]:
            findings.append(f"⚠️  Error HTTP 5xx: {line[:120]}")

        for line in sudo_events[:5]:
            findings.append(f"ℹ️  Evento sudo: {line[:120]}")

        content = (
            f"✅ Análisis completado. {total_lines} líneas. Sin anomalías."
            if not findings
            else f"Análisis de logs ({total_lines} líneas, {len(found)} archivos):\n\n" + "\n".join(findings)
        )
        return ToolResult(
            content=content, tool_name=self.name, success=True,
            metadata={
                "lines_processed": total_lines,
                "brute_force_ips": brute_ips,
                "errors_5xx_count": len(errors_5xx),
            },
        )
