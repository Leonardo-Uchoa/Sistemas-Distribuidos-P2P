from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List

_LOCK = threading.Lock()


def _ensure_state_schema(state: Dict[str, Any]) -> Dict[str, Any]:
    """Garante que o estado tenha os campos esperados (migração leve)."""
    # Ledger
    state.setdefault("version", 2)
    state.setdefault("users", {})          # chave_pub -> dict usuario
    state.setdefault("txs", [])            # lista de transações
    state.setdefault("last_updated", None)

    # Cluster / rede
    state.setdefault("members", {})        # url -> {"id": int, "last_seen": float}
    state.setdefault("leader_url", None)   # url do líder atual (não preemptivo)
    return state


def load_state(state_path: str) -> Dict[str, Any]:
    """Carrega o estado local do nó (ou cria um estado vazio)."""
    with _LOCK:
        if not os.path.exists(state_path):
            return _ensure_state_schema({})
        with open(state_path, "r", encoding="utf-8") as f:
            return _ensure_state_schema(json.load(f))


def save_state(state_path: str, state: Dict[str, Any]) -> None:
    """Persiste estado local no disco (volume do container)."""
    tmp_path = state_path + ".tmp"
    with _LOCK:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, state_path)


def load_config(config_path: str) -> Dict[str, Any]:
    """Config local (não distribuída): self_url e peers conhecidos."""
    with _LOCK:
        if not os.path.exists(config_path):
            return {"self_url": "", "peers": []}  # peers = lista de URLs
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            cfg.setdefault("self_url", "")
            cfg.setdefault("peers", [])
            return cfg


def save_config(config_path: str, cfg: Dict[str, Any]) -> None:
    tmp_path = config_path + ".tmp"
    with _LOCK:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, config_path)
