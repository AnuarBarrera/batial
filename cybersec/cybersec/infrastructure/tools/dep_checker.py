import json
import subprocess
import logging
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return -1, ""
    except subprocess.TimeoutExpired:
        return -2, ""


def _check_pip() -> str:
    code, out = _run(["pip-audit", "--format", "json"])
    if code == -1:
        return "ℹ️  pip-audit no disponible. Instala con: pip install pip-audit"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "⚠️  No se pudo parsear salida de pip-audit."
    dependencies = data.get("dependencies", [])
    vulns = [p for p in dependencies if p.get("vulns")]
    if not vulns:
        return "✅ pip: Sin vulnerabilidades conocidas."
    lines = ["pip — vulnerabilidades encontradas:"]
    for pkg in vulns:
        for v in pkg["vulns"]:
            fix = v.get("fix_versions", ["?"])[0]
            lines.append(f"  ⚠️  {pkg['name']} {pkg['version']}: {v['id']} → fix en {fix}")
    return "\n".join(lines)


def _check_npm() -> str:
    code, out = _run(["npm", "audit", "--json"], timeout=30)
    if code == -1:
        return "ℹ️  npm no disponible."
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "⚠️  No se pudo parsear npm audit."
    meta = data.get("metadata", {}).get("vulnerabilities", {})
    critical, high = meta.get("critical", 0), meta.get("high", 0)
    if critical == 0 and high == 0:
        return "✅ npm: Sin vulnerabilidades críticas o altas."
    lines = [f"npm — {critical} críticas, {high} altas:"]
    for name, vuln in data.get("vulnerabilities", {}).items():
        via = vuln.get("via", [{}])
        cve = via[0].get("cve", "") if isinstance(via[0], dict) else ""
        lines.append(f"  ⚠️  {name} [{vuln.get('severity')}] {cve}")
    return "\n".join(lines)


class DependencyCheckerTool(BaseTool):
    name = "check_dependencies"

    def execute(self, package_managers: list[str] = None, **kwargs) -> ToolResult:
        managers = package_managers or ["pip", "npm"]
        sections = []
        if "pip" in managers:
            sections.append(_check_pip())
        if "npm" in managers:
            sections.append(_check_npm())
        content = "\n\n".join(sections) if sections else "Sin gestores de paquetes configurados."
        return ToolResult(content=content, tool_name=self.name, success=True, metadata={"managers": managers})
