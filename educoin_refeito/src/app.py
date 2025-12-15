import os
import json
import time
import random
import threading
from typing import Any, Dict, Tuple, Optional

import requests
from flask import Flask, jsonify, request, render_template

from funcoes import (
    criar_usuario,
    aplicar_transferencia,
    normalizar_url,
)

# ============================================
# Persistência simples (JSON em /data)
# ============================================
DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8000"))

STATE_PATH = os.path.join(DATA_DIR, "state.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")

os.makedirs(DATA_DIR, exist_ok=True)

def _default_state() -> Dict[str, Any]:
    return {
        "leader_url": None,
        "members": {},      # url -> {id:int, last_seen: float}
        "usuarios": {},     # chave_pub -> user dict
        "txs": [],          # list[tx]
        "last_updated": None,
    }

def _default_config() -> Dict[str, Any]:
    return {
        "self_url": None,
        "peers": [],
    }

def _load_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _atomic_save_json(path: str, data: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)

state: Dict[str, Any] = _load_json(STATE_PATH, _default_state())
config: Dict[str, Any] = _load_json(CONFIG_PATH, _default_config())

# Garante chaves mínimas
for k, v in _default_state().items():
    state.setdefault(k, v)
for k, v in _default_config().items():
    config.setdefault(k, v)

# ID do nó: aleatório a cada execução (requisito)
NODE_ID = random.randint(1, 9999)
NODE_ID_STR = f"{NODE_ID:04d}"

# Lock para evitar gravação concorrente
_lock = threading.RLock()

# ============================================
# Funções de rede / eleição
# ============================================
ACTIVE_WINDOW_SEC = 12.0  # um nó é "ativo" se foi visto nos últimos X segundos
LEADER_FAILS_TO_ELECT = 3

def _now_ts() -> float:
    return time.time()

def _get_self_url() -> Optional[str]:
    u = (config.get("self_url") or "").strip()
    return u or None

def _is_leader() -> bool:
    self_url = _get_self_url()
    return bool(self_url and state.get("leader_url") == self_url)

def _mark_member(url: str, node_id: Optional[int] = None) -> None:
    if not url:
        return
    m = state.setdefault("members", {})
    info = m.get(url) or {}
    if node_id is not None:
        info["id"] = int(node_id)
    info["last_seen"] = _now_ts()
    m[url] = info

def _save_all() -> None:
    with _lock:
        _atomic_save_json(STATE_PATH, state)
        _atomic_save_json(CONFIG_PATH, config)

def _http_get(url: str, path: str, timeout: float = 0.9):
    return requests.get(url + path, timeout=timeout)

def _http_post(url: str, path: str, payload: Dict[str, Any], timeout: float = 1.2):
    return requests.post(url + path, json=payload, timeout=timeout)

def _leader_reachable() -> bool:
    leader = state.get("leader_url")
    self_url = _get_self_url()
    if not leader or not self_url:
        return False
    if leader == self_url:
        return True
    try:
        r = _http_get(leader, "/health", timeout=0.7)
        if r.status_code == 200:
            j = r.json()
            _mark_member(leader, j.get("id"))
            return True
        return False
    except Exception:
        return False

def _elect_leader(reason: str) -> None:
    """Eleição: maior ID entre nós ativos. Só é chamada quando leader caiu/está ausente."""
    self_url = _get_self_url()
    if not self_url:
        return

    # Atualiza "eu" como membro ativo
    _mark_member(self_url, NODE_ID)

    # Candidatos ativos
    candidates: list[Tuple[int, str]] = []
    for url, info in (state.get("members") or {}).items():
        try:
            nid = int(info.get("id", -1))
            last_seen = float(info.get("last_seen", 0.0))
        except Exception:
            continue
        if url == self_url:
            candidates.append((NODE_ID, url))
            continue
        if (_now_ts() - last_seen) <= ACTIVE_WINDOW_SEC:
            candidates.append((nid, url))

    if not candidates:
        candidates = [(NODE_ID, self_url)]

    winner_id, winner_url = max(candidates, key=lambda t: (t[0], t[1]))
    old = state.get("leader_url")
    state["leader_url"] = winner_url
    _save_all()

    # Se eu virei líder: broadcast do estado (para não ficar inconsistente)
    if winner_url == self_url:
        _broadcast_state(note=f"eleição ({reason}) -> líder {winner_id}")
    else:
        # se outro virou líder, tenta puxar estado dele
        _pull_state_from_leader()

def _ensure_leader_or_elect() -> None:
    """Garante que existe um líder alcançável. Se não existir, roda eleição."""
    self_url = _get_self_url()
    if not self_url:
        return

    if state.get("leader_url") is None:
        # bootstrap: sozinho até conectar com alguém
        state["leader_url"] = self_url
        _mark_member(self_url, NODE_ID)
        _save_all()
        return

    # líder existe: só muda se cair
    if not _leader_reachable():
        state["leader_url"] = None
        _save_all()
        _elect_leader("líder inacessível")

def _pull_state_from_leader() -> bool:
    """Puxa o ledger do líder e aplica localmente."""
    leader = state.get("leader_url")
    self_url = _get_self_url()
    if not leader or not self_url or leader == self_url:
        return False
    try:
        r = _http_get(leader, "/api/state", timeout=1.2)
        if r.status_code != 200:
            return False
        j = r.json()
        ledger = j.get("state") or {}
        # Mantém config local, mas atualiza ledger + leader + members
        with _lock:
            state["leader_url"] = ledger.get("leader_url", leader)
            state["usuarios"] = ledger.get("usuarios", {})
            state["txs"] = ledger.get("txs", [])
            state["last_updated"] = ledger.get("last_updated")
            # merge membros
            members = state.setdefault("members", {})
            for url, info in (ledger.get("members") or {}).items():
                members[url] = info
            _mark_member(self_url, NODE_ID)
            _save_all()
        return True
    except Exception:
        return False

def _broadcast_state(note: str = "") -> Dict[str, Any]:
    """Líder envia o estado completo aos peers."""
    if not _is_leader():
        return {"ok": False, "msg": "não sou líder"}
    peers = list(dict.fromkeys(config.get("peers") or []))  # unique
    ok, fail = [], []
    payload = {
        "leader_url": state.get("leader_url"),
        "members": state.get("members", {}),
        "usuarios": state.get("usuarios", {}),
        "txs": state.get("txs", []),
        "last_updated": state.get("last_updated"),
        "note": note,
    }
    for p in peers:
        try:
            p = normalizar_url(p)
        except Exception:
            continue
        if p == _get_self_url():
            continue
        try:
            r = _http_post(p, "/sync", payload, timeout=1.5)
            if r.status_code == 200:
                ok.append(p)
            else:
                fail.append(p)
        except Exception:
            fail.append(p)
    return {"ok": True, "broadcast": {"ok": ok, "fail": fail}}

def _merge_peers(new_peers: list[str]) -> None:
    peers = config.setdefault("peers", [])
    s = set(peers)
    for p in new_peers:
        try:
            p = normalizar_url(p)
        except Exception:
            continue
        if p not in s:
            peers.append(p)
            s.add(p)

# ============================================
# Flask App
# ============================================
app = Flask(__name__, template_folder="templates", static_folder="static")

@app.get("/")
def root():
    return jsonify({"ok": True, "msg": "EduCoin rodando", "dashboard": "/dashboard"})

@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.get("/health")
def health():
    self_url = _get_self_url()
    if self_url:
        _mark_member(self_url, NODE_ID)
        _save_all()
    return jsonify({
        "ok": True,
        "id": NODE_ID,
        "id_str": NODE_ID_STR,
        "self_url": self_url,
        "leader_url": state.get("leader_url"),
        "is_leader": _is_leader(),
        "ts": _now_ts(),
    })

@app.get("/api/state")
def api_state():
    _ensure_leader_or_elect()
    return jsonify({
        "ok": True,
        "node": {"id": NODE_ID, "id_str": NODE_ID_STR},
        "config": config,
        "state": state,
        "is_leader": _is_leader(),
    })

@app.post("/config/self")
def config_self():
    payload = request.get_json(silent=True) or {}
    try:
        self_url = normalizar_url(payload.get("self_url") or "")
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400

    with _lock:
        config["self_url"] = self_url
        _mark_member(self_url, NODE_ID)
        # bootstrap: se não tem líder definido, eu sou líder (até cair)
        if not state.get("leader_url"):
            state["leader_url"] = self_url
        _save_all()

    return jsonify({
        "ok": True,
        "msg": "meu_url salvo",
        "self_url": self_url,
        "leader_url": state.get("leader_url"),
        "is_leader": _is_leader(),
    })

@app.post("/peers/connect")
def peers_connect():
    """Conecta a um peer via UI. Requer self_url definido."""
    self_url = _get_self_url()
    if not self_url:
        return jsonify({"ok": False, "msg": "Defina primeiro o meu_url (self_url) na interface."}), 400

    payload = request.get_json(silent=True) or {}
    try:
        peer_url = normalizar_url(payload.get("peer_url") or "")
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400

    _ensure_leader_or_elect()

    # adiciona peer localmente
    _merge_peers([peer_url])
    _save_all()

    # handshake: informa meu_url + meu id
    join_payload = {"url": self_url, "id": NODE_ID}
    join_resp: Dict[str, Any] = {}
    try:
        r = _http_post(peer_url, "/p2p/join", join_payload, timeout=2.0)
        join_resp = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text}
    except Exception as e:
        return jsonify({"ok": False, "msg": f"Falha ao conectar: {e}", "peer_url": peer_url}), 502

    # merge membros / peers / leader
    with _lock:
        # marca peer
        if join_resp.get("self"):
            _mark_member(join_resp["self"].get("url", peer_url), join_resp["self"].get("id"))
        else:
            _mark_member(peer_url)

        # merge members
        members = join_resp.get("members") or {}
        for url, info in members.items():
            state.setdefault("members", {})[url] = info

        # merge peers
        _merge_peers(join_resp.get("peers") or [])

        # se eu ainda não tenho líder, uso o líder informado
        if not state.get("leader_url") and join_resp.get("leader_url"):
            state["leader_url"] = join_resp.get("leader_url")

        # se o peer é líder e mandou ledger, posso sincronizar direto
        ledger = join_resp.get("ledger")
        if isinstance(ledger, dict) and ledger:
            state["leader_url"] = join_resp.get("leader_url") or state.get("leader_url")
            state["usuarios"] = ledger.get("usuarios", state.get("usuarios", {}))
            state["txs"] = ledger.get("txs", state.get("txs", []))
            state["last_updated"] = ledger.get("last_updated", state.get("last_updated"))
            # merge members do ledger
            for url, info in (ledger.get("members") or {}).items():
                state.setdefault("members", {})[url] = info

        _mark_member(self_url, NODE_ID)
        _save_all()

    # Após conectar, tenta sincronizar com o líder (se eu não for líder)
    if not _is_leader():
        _pull_state_from_leader()
    else:
        _broadcast_state(note="novo peer conectado")

    return jsonify({
        "ok": True,
        "msg": "peer conectado",
        "peer_url": peer_url,
        "join": join_resp,
        "is_leader": _is_leader(),
        "leader_url": state.get("leader_url"),
        "peers": config.get("peers", []),
    })

@app.post("/p2p/join")
def p2p_join():
    """Handshake recebido de outro nó."""
    payload = request.get_json(silent=True) or {}
    try:
        other_url = normalizar_url(payload.get("url") or "")
        other_id = int(payload.get("id"))
    except Exception:
        return jsonify({"ok": False, "msg": "payload inválido (url/id)"}), 400

    self_url = _get_self_url()
    if not self_url:
        # eu ainda não tenho meu_url, mas posso responder com meu endereço "desconhecido"
        # (recomendado: usuário setar self_url antes de conectar)
        pass

    _ensure_leader_or_elect()

    with _lock:
        _merge_peers([other_url])
        _mark_member(other_url, other_id)
        if self_url:
            _mark_member(self_url, NODE_ID)
        _save_all()

    # Se eu sou líder, já sincronizo o peer
    if _is_leader():
        try:
            _http_post(other_url, "/sync", {
                "leader_url": state.get("leader_url"),
                "members": state.get("members", {}),
                "usuarios": state.get("usuarios", {}),
                "txs": state.get("txs", []),
                "last_updated": state.get("last_updated"),
                "note": "sync em join",
            }, timeout=2.0)
        except Exception:
            pass

    resp = {
        "ok": True,
        "self": {"id": NODE_ID, "id_str": NODE_ID_STR, "url": self_url},
        "leader_url": state.get("leader_url"),
        "members": state.get("members", {}),
        "peers": config.get("peers", []),
    }
    if _is_leader():
        resp["ledger"] = {
            "leader_url": state.get("leader_url"),
            "members": state.get("members", {}),
            "usuarios": state.get("usuarios", {}),
            "txs": state.get("txs", []),
            "last_updated": state.get("last_updated"),
        }
    return jsonify(resp)

@app.post("/sync")
def sync():
    """Recebe estado do líder."""
    payload = request.get_json(silent=True) or {}
    with _lock:
        # Atualiza leader + ledger
        state["leader_url"] = payload.get("leader_url") or state.get("leader_url")
        state["usuarios"] = payload.get("usuarios", state.get("usuarios", {}))
        state["txs"] = payload.get("txs", state.get("txs", []))
        state["last_updated"] = payload.get("last_updated", state.get("last_updated"))

        # merge members
        members = payload.get("members") or {}
        for url, info in members.items():
            state.setdefault("members", {})[url] = info

        self_url = _get_self_url()
        if self_url:
            _mark_member(self_url, NODE_ID)

        _save_all()

    return jsonify({"ok": True, "msg": "sincronizado"})

def _forward_to_leader(path: str, payload: Dict[str, Any]):
    leader = state.get("leader_url")
    self_url = _get_self_url()
    if not leader or not self_url:
        return None
    if leader == self_url:
        return None
    try:
        r = _http_post(leader, path, payload, timeout=2.5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return None

@app.post("/register")
def register():
    """Cadastro de conta. Sempre processado pelo líder."""
    self_url = _get_self_url()
    if not self_url:
        return jsonify({"ok": False, "msg": "Defina primeiro o meu_url (self_url) na seção Rede (P2P)."}), 400

    _ensure_leader_or_elect()

    if not _is_leader():
        fwd = _forward_to_leader("/register", request.get_json(silent=True) or {})
        if fwd is not None:
            return fwd
        # líder caiu e ainda não conseguimos eleger? tenta eleger e continuar
        _ensure_leader_or_elect()
        if not _is_leader():
            return jsonify({"ok": False, "msg": "Líder indisponível. Tente novamente."}), 503

    payload = request.get_json(silent=True) or {}
    try:
        user, priv = criar_usuario(payload)
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400

    pub = user["chave_pub"]
    with _lock:
        # impede duplicar pub
        if pub in state["usuarios"]:
            # mantém saldo e dados antigos, mas devolve msg
            existing = state["usuarios"][pub]
            return jsonify({
                "ok": True,
                "msg": "Usuário já existia (mesma frase).",
                "chave_pub": pub,
                "saldo": existing.get("saldo"),
                "priv": priv,
            })

        state["usuarios"][pub] = user
        state["last_updated"] = user.get("criado_em")
        _save_all()

    b = _broadcast_state(note="novo cadastro")
    return jsonify({
        "ok": True,
        "msg": "Cadastro realizado com sucesso (estado propagado).",
        "user": user,
        "chave_pub": pub,
        "priv": priv,  # mostrado uma vez
        "broadcast": b.get("broadcast", {}),
    })

@app.post("/transfer")
def transfer():
    """Transferência de moedas. Sempre processada pelo líder."""
    self_url = _get_self_url()
    if not self_url:
        return jsonify({"ok": False, "msg": "Defina primeiro o meu_url (self_url) na seção Rede (P2P)."}), 400

    _ensure_leader_or_elect()

    if not _is_leader():
        fwd = _forward_to_leader("/transfer", request.get_json(silent=True) or {})
        if fwd is not None:
            return fwd
        _ensure_leader_or_elect()
        if not _is_leader():
            return jsonify({"ok": False, "msg": "Líder indisponível. Tente novamente."}), 503

    payload = request.get_json(silent=True) or {}
    priv = (payload.get("priv") or "").strip()
    dest_pub = (payload.get("dest_pub") or "").strip()
    try:
        quantia = int(payload.get("quantia"))
    except Exception:
        return jsonify({"ok": False, "msg": "Quantia inválida."}), 400

    try:
        tx = aplicar_transferencia(state, priv, dest_pub, quantia)
        _save_all()
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 400

    b = _broadcast_state(note="nova transferência")
    return jsonify({
        "ok": True,
        "msg": "Transferência realizada com sucesso (estado propagado).",
        "tx": tx,
        "broadcast": b.get("broadcast", {}),
    })

# ============================================
# Threads de monitoramento
# ============================================
def _leader_watchdog_loop():
    fails = 0
    while True:
        try:
            time.sleep(2.5)
            self_url = _get_self_url()
            if not self_url:
                continue

            leader = state.get("leader_url")
            if not leader or leader == self_url:
                fails = 0
                continue

            try:
                r = _http_get(leader, "/health", timeout=0.7)
                if r.status_code == 200:
                    j = r.json()
                    _mark_member(leader, j.get("id"))
                    _save_all()
                    fails = 0
                else:
                    fails += 1
            except Exception:
                fails += 1

            if fails >= LEADER_FAILS_TO_ELECT:
                # leader caiu -> eleição
                with _lock:
                    state["leader_url"] = None
                    _save_all()
                _elect_leader("watchdog")
                fails = 0

        except Exception:
            # nunca derruba a thread
            pass

def _leader_ping_peers_loop():
    while True:
        try:
            time.sleep(4.0)
            if not _is_leader():
                continue
            self_url = _get_self_url()
            if not self_url:
                continue

            peers = list(dict.fromkeys(config.get("peers") or []))
            for p in peers:
                try:
                    p = normalizar_url(p)
                except Exception:
                    continue
                if p == self_url:
                    continue
                try:
                    r = _http_get(p, "/health", timeout=0.9)
                    if r.status_code == 200:
                        j = r.json()
                        _mark_member(p, j.get("id"))
                        _save_all()
                except Exception:
                    # só deixa last_seen expirar
                    pass
        except Exception:
            pass

threading.Thread(target=_leader_watchdog_loop, daemon=True).start()
threading.Thread(target=_leader_ping_peers_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
