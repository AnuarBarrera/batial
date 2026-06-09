import re
import stat
import subprocess
import logging
from pathlib import Path
from cybersec.domain.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

SSH_CHECKS = [
    (re.compile(r"^\s*PermitRootLogin\s+yes", re.I | re.M),
     "PermitRootLogin yes — login directo como root via SSH", "High"),
    (re.compile(r"^\s*PasswordAuthentication\s+yes", re.I | re.M),
     "PasswordAuthentication yes — vulnerable a brute force", "Medium"),
    (re.compile(r"^\s*Port\s+22\b", re.I | re.M),
     "Puerto 22 por defecto — expuesto a scanners", "Low"),
]

SENSITIVE_FILES = [
    ("/etc/passwd", 0o644, "Permisos incorrectos en /etc/passwd"),
    ("/etc/shadow", 0o640, "Permisos incorrectos en /etc/shadow"),
]


def _run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, p.stdout, p.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def _check_ssh(path: str) -> tuple[list[str], list[dict]]:
    p = Path(path)
    if not p.exists():
        return [f"ℹ️  sshd_config no encontrado en {path}"], []
    content = p.read_text(errors="replace")
    issues, raw = [], []
    for pattern, msg, severity in SSH_CHECKS:
        if pattern.search(content):
            issues.append(f"⚠️  [{severity}] {msg}")
            raw.append({"severity": severity, "message": msg})
    return issues or ["✅ SSH config sin problemas detectados."], raw


def _check_permissions() -> list[str]:
    lines = []
    for path, expected, msg in SENSITIVE_FILES:
        p = Path(path)
        if p.exists() and stat.S_IMODE(p.stat().st_mode) > expected:
            lines.append(f"⚠️  {msg} (actual: {oct(stat.S_IMODE(p.stat().st_mode))})")
    return lines or ["✅ Permisos de archivos sensibles: OK"]


def _check_firewall() -> list[str]:
    code, out, _ = _run_cmd(["ufw", "status"])
    if code == 0:
        first_line = out.strip().splitlines()[0] if out.strip() else ""
        if "inactive" in first_line.lower():
            return [f"⚠️  [High] UFW desactivado ({first_line})"]
        return [f"✅ UFW: {first_line}"]

    # `ufw status` falló (normalmente por falta de sudo) — fallback con systemctl,
    # que no requiere privilegios elevados.
    _, out2, _ = _run_cmd(["systemctl", "is-active", "ufw"])
    state = out2.strip().lower()
    if state == "active":
        return ["✅ UFW activo (verificado via systemctl; reglas no visibles sin sudo)"]
    if state == "inactive":
        return ["⚠️  [High] UFW inactivo (systemctl is-active ufw → inactive)"]

    code3, out3, _ = _run_cmd(["iptables", "-L", "-n"])
    if code3 == 0:
        if out3.splitlines() and "ACCEPT" in out3.splitlines()[0]:
            return ["⚠️  [High] iptables: política por defecto ACCEPT"]
        return ["✅ iptables activo"]
    return ["ℹ️  Sin firewall detectado (ufw/iptables no disponibles)"]


class ConfigCheckerTool(BaseTool):
    name = "check_configs"

    def execute(self, ssh_config_path: str = "/etc/ssh/sshd_config", **kwargs) -> ToolResult:
        ssh_lines, ssh_issues = _check_ssh(ssh_config_path)
        content = "\n\n".join([
            "=== SSH Config ===\n" + "\n".join(ssh_lines),
            "=== Permisos ===\n" + "\n".join(_check_permissions()),
            "=== Firewall ===\n" + "\n".join(_check_firewall()),
        ])
        return ToolResult(content=content, tool_name=self.name, success=True,
                          metadata={"ssh_issues": ssh_issues})
