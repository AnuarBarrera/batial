from .log_analyzer import LogAnalyzerTool
from .port_scanner import PortScannerTool
from .dep_checker import DependencyCheckerTool
from .code_reader import CodeReaderTool, ListCodeFilesTool
from .config_checker import ConfigCheckerTool
from .static_analyzer import StaticAnalyzerTool

TOOL_SCHEMAS = [
    {
        "name": "analyze_logs",
        "description": "Analiza archivos de log (auth.log, syslog, nginx, apache) buscando brute force SSH, IPs repetidas y errores HTTP 5xx.",
        "parameters": {
            "log_files": {"type": "array", "description": "Lista de rutas absolutas a archivos de log", "required": True},
        },
    },
    {
        "name": "scan_ports",
        "description": "Escanea los top 1000 puertos TCP con nmap. Detecta puertos abiertos y servicios sensibles expuestos.",
        "parameters": {
            "host": {"type": "string", "description": "IP o hostname a escanear (ej. localhost, 192.168.1.1)", "required": True},
        },
    },
    {
        "name": "check_dependencies",
        "description": "Verifica paquetes pip/npm instalados contra CVEs conocidos usando pip-audit y npm audit.",
        "parameters": {
            "package_managers": {"type": "array", "description": "Lista de gestores a revisar: ['pip', 'npm']"},
        },
    },
    {
        "name": "list_code_files",
        "description": "Lista archivos de código fuente dentro de un directorio (recursivo, excluye .git/node_modules/venv/etc.). "
                        "Úsalo primero para descubrir qué archivos existen antes de leerlos con read_code_snippet.",
        "parameters": {
            "directory": {"type": "string", "description": "Ruta absoluta al directorio de código a listar", "required": True},
        },
    },
    {
        "name": "read_code_snippet",
        "description": "Lee un archivo de código fuente (.py, .js, .ts, .go, .sh, .env, .conf, .yaml, etc.) para análisis estático.",
        "parameters": {
            "file_path": {"type": "string", "description": "Ruta absoluta al archivo a analizar", "required": True},
        },
    },
    {
        "name": "check_configs",
        "description": "Revisa configuración SSH (sshd_config), permisos de /etc/passwd y /etc/shadow, y estado del firewall (ufw/iptables).",
        "parameters": {
            "ssh_config_path": {"type": "string", "description": "Ruta al sshd_config (default: /etc/ssh/sshd_config)"},
        },
    },
    {
        "name": "scan_code_security",
        "description": "Análisis estático de seguridad con bandit sobre un directorio de código: detecta de forma "
                        "determinista secretos hardcodeados, funciones peligrosas (eval/exec, shell=True), "
                        "criptografía débil, SQL injection y otros patrones inseguros, con severidad por hallazgo.",
        "parameters": {
            "directory": {"type": "string", "description": "Ruta absoluta al directorio de código a analizar", "required": True},
        },
    },
]

_REGISTRY = None


def get_registry() -> dict:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = {
            "analyze_logs": LogAnalyzerTool(),
            "scan_ports": PortScannerTool(),
            "check_dependencies": DependencyCheckerTool(),
            "read_code_snippet": CodeReaderTool(),
            "list_code_files": ListCodeFilesTool(),
            "check_configs": ConfigCheckerTool(),
            "scan_code_security": StaticAnalyzerTool(),
        }
    return _REGISTRY


def get_tool(name: str):
    return get_registry().get(name)


def get_tool_schemas() -> list[dict]:
    return TOOL_SCHEMAS
