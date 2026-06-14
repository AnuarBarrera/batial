import json
from datetime import datetime, timezone
from pathlib import Path


class RunTracer:
    """Escribe un evento JSON por línea a un archivo, para diagnóstico de corridas del agente."""

    def __init__(self, path):
        self._file = open(Path(path), "w", encoding="utf-8")

    def record(self, event: str, **fields) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        self._file.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
