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
        "lamport_clock": 0,
    }

def _default_config() -> Dict[str, Any]:
    return {
        "self_url": None,
        "peers": [],
        "known_peers": [],
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

# Falhas de peers monitoradas em memória
_peer_failures: Dict[str, int] = {}

def _clock_value() -> int:
    try:
        return int(state.get("lamport_clock", 0))
    except Exception:
        return 0

def _clock_send_event() -> int:
    """Incrementa relógio lógico para eventos locais/send."""
    with _lock:
        state["lamport_clock"] = _clock_value() + 1
        return state["lamport_clock"]

def _clock_receive_event(remote_clock: Optional[int]) -> int:
    """Atualiza relógio lógico ao receber mensagens remotas."""
    remote_val = 0
    if remote_clock is not None:
        try:
            remote_val = int(remote_clock)
        except Exception:
            remote_val = 0
    with _lock:
        state["lamport_clock"] = max(_clock_value(), remote_val) + 1
        return state["lamport_clock"]

# ============================================
# Funções de rede / eleição
# ============================================
ACTIVE_WINDOW_SEC = 12.0  # um nó é "ativo" se foi visto nos últimos X segundos
LEADER_FAILS_TO_ELECT = 3
PEER_FAILS_TO_REMOVE = 3
PEER_HEALTH_INTERVAL_SEC = 5.0
RECONNECT_INTERVAL_SEC = 10.0
RING_ENDPOINT = "/ring/election"

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

def _elect_leader_local(reason: str) -> None:
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
    with _lock:
        state["leader_url"] = winner_url
        _clock_send_event()
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
        with _lock:
            state["leader_url"] = self_url
            _mark_member(self_url, NODE_ID)
            _clock_send_event()
            _save_all()
        return

    # líder existe: só muda se cair
    if not _leader_reachable():
        with _lock:
            state["leader_url"] = None
            _clock_send_event()
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
        remote_clock = ledger.get("lamport_clock")
        # Mantém config local, mas atualiza ledger + leader + members
        with _lock:
            state["leader_url"] = ledger.get("leader_url", leader)
            state["usuarios"] = ledger.get("usuarios", {})
            state["txs"] = ledger.get("txs", [])
            state["last_updated"] = ledger.get("last_updated")
            if remote_clock is not None:
                _clock_receive_event(remote_clock)
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
    clock = _clock_send_event()
    _save_all()
    ok, fail = [], []
    payload = {
        "leader_url": state.get("leader_url"),
        "members": state.get("members", {}),
        "usuarios": state.get("usuarios", {}),
        "txs": state.get("txs", []),
        "last_updated": state.get("last_updated"),
        "lamport_clock": clock,
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
                _peer_failures.pop(p, None)
            else:
                fail.append(p)
                _handle_peer_failure(p)
        except Exception:
            fail.append(p)
            _handle_peer_failure(p)
    return {"ok": True, "broadcast": {"ok": ok, "fail": fail}}

def _merge_peers(new_peers: list[str]) -> None:
    peers = config.setdefault("peers", [])
    known = config.setdefault("known_peers", [])
    s = set(peers)
    for p in new_peers:
        try:
            p = normalizar_url(p)
        except Exception:
            continue
        if p not in s:
            peers.append(p)
            s.add(p)
        if p not in known:
            known.append(p)

def _remove_peer(url: str) -> None:
    try:
        url = normalizar_url(url)
    except Exception:
        return
    with _lock:
        peers = config.setdefault("peers", [])
        if url in peers:
            peers[:] = [p for p in peers if p != url]
            _peer_failures.pop(url, None)
            known = config.setdefault("known_peers", [])
            if url not in known:
                known.append(url)
            _save_all()
        members = state.setdefault("members", {})
        if url in members:
            members[url]["last_seen"] = 0.0

def _handle_peer_failure(url: str) -> None:
    """Incrementa contagem de falhas e remove peer quando necessário."""
    try:
        url = normalizar_url(url)
    except Exception:
        return
    fails = _peer_failures.get(url, 0) + 1
    _peer_failures[url] = fails
    if fails >= PEER_FAILS_TO_REMOVE:
        _remove_peer(url)

def _get_ring_nodes() -> list[str]:
    """Lista ordenada de nós conhecidos para o algoritmo em anel."""
    urls = set()
    for url in config.get("peers") or []:
        try:
            urls.add(normalizar_url(url))
        except Exception:
            continue
    for url in (state.get("members") or {}).keys():
        try:
            urls.add(normalizar_url(url))
        except Exception:
            continue
    self_url = _get_self_url()
    if self_url:
        urls.add(self_url)
    return sorted(urls)

def _next_ring_neighbor(current_url: str, nodes: Optional[list[str]] = None) -> Optional[str]:
    nodes = nodes or _get_ring_nodes()
    if not nodes:
        return None
    if current_url not in nodes:
        nodes = sorted(nodes + [current_url])
    if len(nodes) <= 1:
        return None
    try:
        idx = nodes.index(current_url)
    except ValueError:
        return None
    return nodes[(idx + 1) % len(nodes)]

def _send_ring_payload_with_failover(current_url: str, target_url: Optional[str], payload: Dict[str, Any]) -> bool:
    """Tenta enviar payload do anel ao próximo nó, pulando peers mortos."""
    if not target_url:
        return False
    attempts = 0
    tried: set[str] = set()
    while True:
        if not target_url or target_url == current_url or target_url in tried:
            return False
        payload["lamport_clock"] = _clock_send_event()
        _save_all()
        try:
            r = _http_post(target_url, RING_ENDPOINT, payload, timeout=2.5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        tried.add(target_url)
        _handle_peer_failure(target_url)
        nodes = _get_ring_nodes()
        if len(nodes) <= 1:
            return False
        target_url = _next_ring_neighbor(current_url, nodes)
        attempts += 1
        if attempts > len(nodes):
            return False

def _start_ring_election(reason: str) -> bool:
    """Inicia eleição em anel. Retorna True se conseguiu propagar."""
    self_url = _get_self_url()
    if not self_url:
        return False
    nodes = _get_ring_nodes()
    if len(nodes) <= 1:
        return False
    next_url = _next_ring_neighbor(self_url, nodes)
    if not next_url or next_url == self_url:
        return False
    payload = {
        "mode": "election",
        "initiator_url": self_url,
        "max_id": NODE_ID,
        "max_url": self_url,
        "reason": reason,
        "returning": False,
        "visited": [self_url],
        "hops": 0,
    }
    return _send_ring_payload_with_failover(self_url, next_url, payload)

def _start_ring_coordinator(leader_url: str, leader_id: int, reason: str, initiator_url: str) -> None:
    """Anuncia o líder eleito a todos os nós do anel."""
    nodes = _get_ring_nodes()
    if len(nodes) <= 1:
        if leader_url == _get_self_url():
            _broadcast_state(note=f"eleição em anel ({reason}) -> líder {leader_id}")
        else:
            _pull_state_from_leader()
        return
    next_url = _next_ring_neighbor(initiator_url, nodes)
    if not next_url or next_url == initiator_url:
        return
    payload = {
        "mode": "coordinator",
        "initiator_url": initiator_url,
        "leader_url": leader_url,
        "leader_id": leader_id,
        "reason": reason,
        "returning": False,
        "visited": [initiator_url],
    }
    if not _send_ring_payload_with_failover(initiator_url, next_url, payload):
        if leader_url == _get_self_url():
            _broadcast_state(note=f"eleição em anel ({reason}) -> líder {leader_id}")
        else:
            _pull_state_from_leader()

def _complete_ring_election(payload: Dict[str, Any]) -> None:
    """Define o vencedor e dispara anúncio."""
    winner_url = payload.get("max_url") or _get_self_url()
    try:
        winner_id = int(payload.get("max_id", NODE_ID))
    except Exception:
        winner_id = NODE_ID
    reason = payload.get("reason", "ring")
    initiator = payload.get("initiator_url") or _get_self_url()
    with _lock:
        state["leader_url"] = winner_url
        _clock_send_event()
        _save_all()
    _start_ring_coordinator(winner_url, winner_id, reason, initiator)
    if winner_url == _get_self_url():
        _broadcast_state(note=f"eleição em anel ({reason}) -> líder {winner_id}")
    else:
        _pull_state_from_leader()

def _elect_leader(reason: str) -> None:
    """Tenta eleição em anel antes de cair no modo local."""
    if _start_ring_election(reason):
        return
    _elect_leader_local(reason)

def _handle_ring_election_payload(self_url: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    initiator = payload.get("initiator_url")
    if not initiator:
        return {"ok": False, "msg": "initiator_url ausente"}, 400
    try:
        current_max = int(payload.get("max_id", -1))
    except Exception:
        current_max = -1
    if NODE_ID > current_max:
        payload["max_id"] = NODE_ID
        payload["max_url"] = self_url
    payload.setdefault("visited", [])
    if self_url not in payload["visited"]:
        payload["visited"].append(self_url)
    payload["hops"] = int(payload.get("hops", 0)) + 1

    if payload.get("returning") and self_url == initiator:
        _complete_ring_election(payload)
        return {"ok": True, "msg": "eleição em anel concluída no iniciador"}, 200

    nodes = _get_ring_nodes()
    target = _next_ring_neighbor(self_url, nodes)
    if not target or target == self_url:
        payload["returning"] = True
        if self_url == initiator:
            _complete_ring_election(payload)
            return {"ok": True, "msg": "eleição concluída (sem outros nós)"}, 200
        if _send_ring_payload_with_failover(self_url, initiator, payload):
            return {"ok": True, "msg": "retornando para o iniciador"}, 200
        _complete_ring_election(payload)
        return {"ok": True, "msg": "falha ao retornar, eleição concluída localmente"}, 200

    payload["returning"] = (target == initiator)
    if _send_ring_payload_with_failover(self_url, target, payload):
        return {"ok": True, "msg": "payload enviado ao próximo nó", "target": target}, 200

    if self_url == initiator:
        _complete_ring_election(payload)
        return {"ok": True, "msg": "eleição concluída após falha de envio"}, 200

    if _send_ring_payload_with_failover(self_url, initiator, payload):
        return {"ok": True, "msg": "falha no próximo, resposta enviada ao iniciador"}, 200

    _complete_ring_election(payload)
    return {"ok": True, "msg": "eleição concluída pelo nó atual"}, 200

def _handle_ring_coordinator_payload(self_url: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    initiator = payload.get("initiator_url")
    leader_url = payload.get("leader_url")
    reason = payload.get("reason", "ring")
    if leader_url:
        with _lock:
            state["leader_url"] = leader_url
            _clock_send_event()
            _save_all()
    if leader_url == self_url:
        try:
            leader_id = int(payload.get("leader_id", NODE_ID))
        except Exception:
            leader_id = NODE_ID
        _broadcast_state(note=f"eleição em anel ({reason}) -> líder {leader_id}")
    else:
        _pull_state_from_leader()

    payload.setdefault("visited", [])
    if self_url not in payload["visited"]:
        payload["visited"].append(self_url)

    if payload.get("returning") and initiator and self_url == initiator:
        return {"ok": True, "msg": "anúncio do líder concluído"}, 200

    nodes = _get_ring_nodes()
    target = _next_ring_neighbor(self_url, nodes)
    if not target or target == self_url:
        return {"ok": True, "msg": "anúncio encerrado (sem próximos nós)"}, 200

    payload["returning"] = (target == initiator)
    if _send_ring_payload_with_failover(self_url, target, payload):
        return {"ok": True, "msg": "anúncio enviado ao próximo nó", "target": target}, 200

    return {"ok": True, "msg": "anúncio encerrado devido a falha de envio"}, 200

def _connect_peer_flow(raw_peer_url: str, *, reason: str = "manual") -> Tuple[Dict[str, Any], int]:
    self_url = _get_self_url()
    if not self_url:
        return {"ok": False, "msg": "Defina primeiro o meu_url (self_url) na interface."}, 400
    try:
        peer_url = normalizar_url(raw_peer_url)
    except Exception as e:
        return {"ok": False, "msg": str(e)}, 400

    _ensure_leader_or_elect()

    _merge_peers([peer_url])
    _save_all()

    join_payload = {"url": self_url, "id": NODE_ID, "lamport_clock": _clock_value()}
    join_resp: Dict[str, Any] = {}
    try:
        r = _http_post(peer_url, "/p2p/join", join_payload, timeout=2.0)
        if r.headers.get("content-type", "").startswith("application/json"):
            join_resp = r.json()
        else:
            join_resp = {"raw": r.text}
    except Exception as e:
        _handle_peer_failure(peer_url)
        return {"ok": False, "msg": f"Falha ao conectar: {e}", "peer_url": peer_url}, 502

    with _lock:
        if join_resp.get("self"):
            _mark_member(join_resp["self"].get("url", peer_url), join_resp["self"].get("id"))
        else:
            _mark_member(peer_url)

        members = join_resp.get("members") or {}
        for url, info in members.items():
            state.setdefault("members", {})[url] = info

        _merge_peers(join_resp.get("peers") or [])

        if not state.get("leader_url") and join_resp.get("leader_url"):
            state["leader_url"] = join_resp.get("leader_url")

        ledger = join_resp.get("ledger")
        ledger_clock = None
        if isinstance(ledger, dict) and ledger:
            state["leader_url"] = join_resp.get("leader_url") or state.get("leader_url")
            state["usuarios"] = ledger.get("usuarios", state.get("usuarios", {}))
            state["txs"] = ledger.get("txs", state.get("txs", []))
            state["last_updated"] = ledger.get("last_updated", state.get("last_updated"))
            for url, info in (ledger.get("members") or {}).items():
                state.setdefault("members", {})[url] = info
            ledger_clock = ledger.get("lamport_clock")

        remote_clock = join_resp.get("lamport_clock")
        max_clock = None
        for candidate in (remote_clock, ledger_clock):
            if candidate is None:
                continue
            try:
                candidate = int(candidate)
            except Exception:
                continue
            max_clock = candidate if max_clock is None else max(max_clock, candidate)
        if max_clock is not None:
            _clock_receive_event(max_clock)

        _mark_member(self_url, NODE_ID)
        _save_all()

    if not _is_leader():
        _pull_state_from_leader()
    else:
        _broadcast_state(note=f"peer conectado ({reason})")

    return {
        "ok": True,
        "msg": "peer conectado",
        "peer_url": peer_url,
        "join": join_resp,
        "is_leader": _is_leader(),
        "leader_url": state.get("leader_url"),
        "peers": config.get("peers", []),
    }, 200

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
        "lamport_clock": _clock_value(),
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
            _clock_send_event()
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
    payload = request.get_json(silent=True) or {}
    resp, status = _connect_peer_flow(payload.get("peer_url") or "", reason="manual")
    return jsonify(resp), status

@app.post(RING_ENDPOINT)
def ring_endpoint():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "election")
    self_url = _get_self_url()
    if not self_url:
        return jsonify({"ok": False, "msg": "self_url indefinido para o nó atual"}), 400
    if not payload.get("initiator_url"):
        return jsonify({"ok": False, "msg": "initiator_url ausente"}), 400

    _clock_receive_event(payload.get("lamport_clock"))

    if mode == "coordinator":
        resp, status = _handle_ring_coordinator_payload(self_url, payload)
    else:
        resp, status = _handle_ring_election_payload(self_url, payload)
    return jsonify(resp), status

@app.post("/p2p/join")
def p2p_join():
    """Handshake recebido de outro nó."""
    payload = request.get_json(silent=True) or {}
    try:
        other_url = normalizar_url(payload.get("url") or "")
        other_id = int(payload.get("id"))
    except Exception:
        return jsonify({"ok": False, "msg": "payload inválido (url/id)"}), 400
    other_clock = payload.get("lamport_clock")
    _clock_receive_event(other_clock)

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
            clock = _clock_send_event()
            _save_all()
            _http_post(other_url, "/sync", {
                "leader_url": state.get("leader_url"),
                "members": state.get("members", {}),
                "usuarios": state.get("usuarios", {}),
                "txs": state.get("txs", []),
                "last_updated": state.get("last_updated"),
                "lamport_clock": clock,
                "note": "sync em join",
            }, timeout=2.0)
        except Exception:
            pass

    resp_clock = _clock_send_event()
    _save_all()

    resp = {
        "ok": True,
        "self": {"id": NODE_ID, "id_str": NODE_ID_STR, "url": self_url},
        "leader_url": state.get("leader_url"),
        "members": state.get("members", {}),
        "peers": config.get("peers", []),
        "lamport_clock": resp_clock,
    }
    if _is_leader():
        resp["ledger"] = {
            "leader_url": state.get("leader_url"),
            "members": state.get("members", {}),
            "usuarios": state.get("usuarios", {}),
            "txs": state.get("txs", []),
            "last_updated": state.get("last_updated"),
            "lamport_clock": resp_clock,
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
        _clock_receive_event(payload.get("lamport_clock"))

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
        _clock_send_event()
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
        _clock_send_event()
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
                    _clock_send_event()
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
                        _peer_failures.pop(p, None)
                except Exception:
                    # só deixa last_seen expirar
                    _handle_peer_failure(p)
        except Exception:
            pass

def _peer_health_loop():
    """Monitora peers (qualquer nó) e remove desconectados."""
    while True:
        try:
            time.sleep(PEER_HEALTH_INTERVAL_SEC)
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
                        _peer_failures.pop(p, None)
                        _save_all()
                    else:
                        _handle_peer_failure(p)
                except Exception:
                    _handle_peer_failure(p)
        except Exception:
            pass

def _auto_reconnect_loop():
    """Tenta reconectar automaticamente a peers conhecidos."""
    while True:
        try:
            time.sleep(RECONNECT_INTERVAL_SEC)
            self_url = _get_self_url()
            if not self_url:
                continue
            active = [p for p in (config.get("peers") or []) if p != self_url]
            if active:
                continue
            known = config.get("known_peers") or []
            candidates = [p for p in known if p not in active and p != self_url]
            random.shuffle(candidates)
            for peer_url in candidates:
                resp, status = _connect_peer_flow(peer_url, reason="auto")
                if status == 200:
                    break  # já reconectamos alguém
        except Exception:
            pass

threading.Thread(target=_leader_watchdog_loop, daemon=True).start()
threading.Thread(target=_leader_ping_peers_loop, daemon=True).start()
threading.Thread(target=_peer_health_loop, daemon=True).start()
threading.Thread(target=_auto_reconnect_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
