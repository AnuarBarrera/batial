import re
import subprocess
import logging
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)

SENSITIVE = {
    21: "FTP sin cifrado",
    23: "Telnet sin cifrado",
    3306: "MySQL expuesto",
    5432: "PostgreSQL expuesto",
    6379: "Redis expuesto",
    27017: "MongoDB expuesto",
    5900: "VNC expuesto",
    9200: "Elasticsearch expuesto",
}


class PortScannerTool(BaseTool):
    name = "scan_ports"

    def execute(self, host: str = "localhost", **kwargs) -> ToolResult:
        try:
            proc = subprocess.run(
                ["nmap", "--top-ports", "100", "-T4", host],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            return self._error("nmap no instalado. Instala con: sudo apt install nmap")
        except subprocess.TimeoutExpired:
            return self._error(f"Timeout escaneando {host}")

        if proc.returncode != 0:
            return self._error(f"nmap error: {proc.stderr[:200]}")

        matches = _PORT_RE.findall(proc.stdout)
        open_ports = [(int(p), svc) for p, svc in matches]
        sensitive = {p: SENSITIVE[p] for p, _ in open_ports if p in SENSITIVE}

        lines = [f"Escaneo de puertos — {host} (top 100):"]
        for port, svc in open_ports:
            warn = SENSITIVE.get(port, "")
            lines.append(f"  {'⚠️ ' if warn else '  '}{port}/tcp  {svc}  {warn}")

        if not open_ports:
            lines.append("  Sin puertos abiertos en top 100.")

        return ToolResult(
            content="\n".join(lines), tool_name=self.name, success=True,
            metadata={"host": host, "open_ports": [p for p, _ in open_ports], "sensitive_ports": sensitive},
        )
