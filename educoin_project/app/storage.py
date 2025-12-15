from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Any


class LedgerStore:
    """Thread-safe wrapper around a JSON file used to persist ledger data."""

    def __init__(self, data_path: str):
        self._path = Path(data_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._write({"accounts": [], "transactions": []})

    def load(self) -> Dict[str, Any]:
        with self._lock:
            with self._path.open("r", encoding="utf-8") as f:
                return json.load(f)

    def save(self, payload: Dict[str, Any]) -> None:
        self._write(payload)

    def _write(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            tmp = self._path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            tmp.replace(self._path)
