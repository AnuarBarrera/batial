import shutil

_TOOLS = {
    "nmap": "el análisis de puertos (scan_ports) no funcionará. Instala con: sudo apt install nmap",
    "pip-audit": "el análisis de dependencias Python (check_dependencies) no funcionará. "
                  "Instala con: pip install pip-audit",
}


def check_preconditions() -> list[str]:
    """Verifica herramientas externas opcionales y devuelve advertencias para las que falten."""
    return [
        f"{tool} no está instalado — {msg}"
        for tool, msg in _TOOLS.items()
        if shutil.which(tool) is None
    ]
