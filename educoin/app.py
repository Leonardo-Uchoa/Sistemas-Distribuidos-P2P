from __future__ import annotations

import os
import random
import threading
import time
from typing import Any, Dict, Tuple

import requests
from flask import Flask, jsonify, request, render_template

from storage import load_state, save_state, load_config, save_config
from funcoes import (
    criar_usuario,
    validar_e_aplicar_transferencia,
    broadcast_state,
    forward_to_leader,
)

app = Flask(__name__)

# =========================
# Configuração básica do nó
# =========================
PORT = int(os.getenv("PORT", "8000"))
STATE_PATH = os.getenv("STATE_PATH", "/data/state.json")
CONFIG_PATH = os.getenv("CONFIG_PATH", "/data/config.json")

# "Entrar no sistema" => ID aleatório do NÓ (não do usuário).
NODE_NUM_ID = int(os.getenv("NODE_NUM_ID", str(random.randint(0, 9999))))

HEARTBEAT_INTERVAL = float(os.getenv("HEARTBEAT_INTERVAL", "2.0"))
MEMBER_TTL = float(os.getenv("MEMBER_TTL", "8.0"))  # segundos sem ver o nó => removido


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    # remove barras no fim
    while url.endswith("/"):
        url = url[:-1]
    return url


def get_config() -> Dict[str, Any]:
    cfg = load_config(CONFIG_PATH)
    cfg["self_url"] = normalize_url(cfg.get("self_url", ""))

    peers = [normalize_url(p) for p in (cfg.get("peers", []) or []) if normalize_url(p)]

    # Seeds (opcional): útil para teste local com vários containers
    seed = os.getenv("SEED_PEERS", "")
    if seed:
        for p in seed.split(","):
            p = normalize_url(p)
            if p:
                peers.append(p)

    cfg["peers"] = sorted(set(peers))
    return cfg


def set_config(cfg: Dict[str, Any]) -> None:
    # normaliza
    cfg = dict(cfg or {})
    cfg["self_url"] = normalize_url(cfg.get("self_url", ""))
    cfg["peers"] = sorted(set(normalize_url(p) for p in (cfg.get("peers", []) or []) if normalize_url(p)))
    save_config(CONFIG_PATH, cfg)


def get_state() -> Dict[str, Any]:
    return load_state(STATE_PATH)


def set_state(state: Dict[str, Any]) -> None:
    save_state(STATE_PATH, state)


def guess_self_url_from_request() -> str:
    # request.host_url vem tipo "http://127.0.0.1:8000/"
    try:
        return normalize_url(request.host_url)
    except Exception:
        return ""


def get_self_url() -> str:
    cfg = get_config()
    if cfg.get("self_url"):
        return cfg["self_url"]
    # fallback: tenta inferir do request
    inferred = guess_self_url_from_request()
    if inferred:
        return inferred
    # fallback final: hostname do container
    host = os.getenv("HOSTNAME", "localhost")
    return normalize_url(f"http://{host}:{PORT}")


def ensure_member_self(state: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    self_url = get_self_url()
    members = state.get("members", {}) or {}
    members[self_url] = {"id": int(NODE_NUM_ID), "last_seen": now}
    state["members"] = members
    return state


def prune_members(state: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    members = state.get("members", {}) or {}
    for url, info in list(members.items()):
        last_seen = float(info.get("last_seen", 0.0))
        if now - last_seen > MEMBER_TTL:
            del members[url]
    state["members"] = members
    return state


def elect_leader_if_needed(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    NÃO-preemptivo (como você pediu):
    - Se há líder vivo: mantém.
    - Só elege quando o líder some/desconecta.
    """
    members = state.get("members", {}) or {}
    leader = normalize_url(state.get("leader_url") or "")

    leader_alive = leader and (leader in members)

    if leader_alive:
        state["leader_url"] = leader
        return state

    # Sem líder (ou líder caiu) => elege o MAIOR ID
    if not members:
        state["leader_url"] = get_self_url()
        return state

    leader_url = max(members.items(), key=lambda kv: int(kv[1].get("id", 0)))[0]
    state["leader_url"] = normalize_url(leader_url)
    return state


def current_leader() -> Tuple[str, bool]:
    state = prune_members(ensure_member_self(get_state()))
    state = elect_leader_if_needed(state)
    set_state(state)

    leader = normalize_url(state.get("leader_url") or "")
    self_url = get_self_url()
    return leader or self_url, (leader == self_url)


def ping_peer(peer_url: str, timeout_s: float = 1.5) -> Dict[str, Any] | None:
    peer_url = normalize_url(peer_url)
    if not peer_url:
        return None
    try:
        r = requests.get(peer_url + "/health", timeout=timeout_s)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def merge_peers_from_members(cfg: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    self_url = get_self_url()
    peers = set(cfg.get("peers", []) or [])
    for url in (state.get("members", {}) or {}).keys():
        url = normalize_url(url)
        if url and url != self_url:
            peers.add(url)
    cfg["peers"] = sorted(peers)
    return cfg


_last_broadcast_fingerprint = {"value": ""}


def maybe_broadcast_if_leader(state: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    leader, is_leader = current_leader()
    if not is_leader:
        return {"broadcast": {"ok": [], "fail": []}}

    # Broadcast só quando algo muda (para não ficar spamando)
    import json
    fingerprint = json.dumps(state, sort_keys=True)
    if fingerprint == _last_broadcast_fingerprint["value"]:
        return {"broadcast": {"ok": [], "fail": []}}

    _last_broadcast_fingerprint["value"] = fingerprint
    return {"broadcast": broadcast_state(cfg.get("peers", []), state)}


def cluster_loop() -> None:
    while True:
        try:
            cfg = get_config()
            state = get_state()
            state = ensure_member_self(state)

            # Ping nos peers conhecidos e atualiza members
            now = time.time()
            peers = cfg.get("peers", []) or []
            for p in list(peers):
                p = normalize_url(p)
                if not p or p == get_self_url():
                    continue
                info = ping_peer(p)
                if info and info.get("ok"):
                    peer_self_url = normalize_url(info.get("self_url") or p)
                    peer_id = int(info.get("node_num_id", 0))
                    state.setdefault("members", {})[peer_self_url] = {"id": peer_id, "last_seen": now}
                    # se o peer nos respondeu com um self_url diferente, substitui
                    if peer_self_url != p:
                        peers = [peer_self_url if x == p else x for x in peers]

            state = prune_members(state)
            state = elect_leader_if_needed(state)

            cfg["peers"] = sorted(set(normalize_url(p) for p in peers if normalize_url(p)))
            cfg = merge_peers_from_members(cfg, state)

            set_config(cfg)
            set_state(state)

            # líder propaga estado e cluster
            maybe_broadcast_if_leader(state, cfg)
        except Exception:
            pass

        time.sleep(HEARTBEAT_INTERVAL)


# Inicia loop do cluster
threading.Thread(target=cluster_loop, daemon=True).start()


# =========================
# Rotas
# =========================
@app.get("/health")
def health():
    leader, is_leader = current_leader()
    cfg = get_config()
    return jsonify({
        "ok": True,
        "node_num_id": NODE_NUM_ID,
        "self_url": get_self_url(),
        "is_leader": is_leader,
        "leader_url": leader,
        "peers": cfg.get("peers", []),
    })


# ===== Visual =====
@app.get("/")
@app.get("/dashboard")
def dashboard():
    leader, is_leader = current_leader()
    cfg = get_config()
    return render_template(
        "dashboard.html",
        node_id=str(NODE_NUM_ID).zfill(4),
        is_leader=is_leader,
        leader_url=leader,
        self_url=cfg.get("self_url", ""),
        peers=",".join(cfg.get("peers", [])),
    )


@app.get("/api/state")
def api_state():
    leader, is_leader = current_leader()
    cfg = get_config()
    state = get_state()
    return jsonify({
        "node": {
            "id": str(NODE_NUM_ID).zfill(4),
            "id_int": NODE_NUM_ID,
            "self_url": get_self_url(),
            "is_leader": is_leader,
            "leader_url": leader,
            "peers": cfg.get("peers", []),
        },
        "state": state,
        "config": cfg,
    })


@app.get("/api/cluster")
def api_cluster():
    leader, is_leader = current_leader()
    state = get_state()
    cfg = get_config()
    return jsonify({
        "ok": True,
        "self_url": get_self_url(),
        "node_num_id": NODE_NUM_ID,
        "leader_url": leader,
        "is_leader": is_leader,
        "members": state.get("members", {}),
        "peers": cfg.get("peers", []),
    })


# ===== Rede (configurável pela interface) =====
@app.post("/network/set_self_url")
def network_set_self_url():
    payload = request.get_json(force=True) or {}
    url = normalize_url(payload.get("self_url", ""))
    if not url:
        return jsonify({"ok": False, "error": "self_url vazio"}), 400

    cfg = get_config()
    cfg["self_url"] = url
    set_config(cfg)

    # atualiza members
    state = ensure_member_self(get_state())
    set_state(state)

    leader, is_leader = current_leader()
    return jsonify({"ok": True, "self_url": url, "leader_url": leader, "is_leader": is_leader})


@app.post("/network/add_peer")
def network_add_peer():
    payload = request.get_json(force=True) or {}
    peer = normalize_url(payload.get("peer_url", ""))
    if not peer:
        return jsonify({"ok": False, "error": "peer_url vazio"}), 400

    cfg = get_config()
    peers = set(cfg.get("peers", []) or [])
    peers.add(peer)
    cfg["peers"] = sorted(peers)
    set_config(cfg)

    # tenta "apresentar" este nó ao peer e puxar estado
    info = ping_peer(peer)
    joined = None
    pulled_state = False

    try:
        # se tiver self_url vazio, tenta inferir do request e avisa
        if not get_config().get("self_url"):
            inferred = guess_self_url_from_request()
            if inferred:
                cfg = get_config()
                cfg["self_url"] = inferred
                set_config(cfg)

        join_payload = {"url": get_self_url(), "id": NODE_NUM_ID}
        r = requests.post(peer + "/network/join", json=join_payload, timeout=3.0)
        joined = {"status": r.status_code, "json": (r.json() if r.headers.get("content-type", "").startswith("application/json") else None)}
    except Exception as e:
        joined = {"error": str(e)}

    # tenta puxar estado do líder conhecido (ou do próprio peer)
    try:
        leader_url = None
        if isinstance(joined, dict) and joined.get("json") and joined["json"].get("leader_url"):
            leader_url = normalize_url(joined["json"]["leader_url"])
        if not leader_url and info and info.get("leader_url"):
            leader_url = normalize_url(info["leader_url"])
        if not leader_url:
            leader_url = peer

        s = requests.get(leader_url + "/api/state", timeout=3.0).json()
        if "state" in s:
            set_state(s["state"])
            pulled_state = True
    except Exception:
        pulled_state = False

    leader, is_leader = current_leader()
    return jsonify({
        "ok": True,
        "peer_added": peer,
        "peer_health": info,
        "join": joined,
        "pulled_state": pulled_state,
        "leader_url": leader,
        "is_leader": is_leader,
    })


@app.post("/network/join")
def network_join():
    """
    Um nó remoto está pedindo para entrar na rede.
    Se este nó não for líder, encaminha ao líder.
    """
    payload = request.get_json(force=True) or {}
    url = normalize_url(payload.get("url", ""))
    nid = int(payload.get("id", 0))

    if not url:
        return jsonify({"ok": False, "error": "url vazio"}), 400
    if nid <= 0 and nid != 0:
        return jsonify({"ok": False, "error": "id inválido"}), 400

    leader, is_leader = current_leader()
    self_url = get_self_url()

    # Se não somos líder, encaminha o join pro líder
    if not is_leader and leader and leader != self_url:
        resp = forward_to_leader(leader, "/network/join", payload)
        return jsonify(resp), 200

    # Somos líder (ou líder desconhecido): adiciona membro e peer
    cfg = get_config()
    peers = set(cfg.get("peers", []) or [])
    if url != self_url:
        peers.add(url)
    cfg["peers"] = sorted(peers)
    set_config(cfg)

    state = get_state()
    now = time.time()
    state.setdefault("members", {})[url] = {"id": int(nid), "last_seen": now}
    state = ensure_member_self(state)
    state = elect_leader_if_needed(prune_members(state))
    set_state(state)

    # Propaga o estado atualizado
    b = maybe_broadcast_if_leader(state, get_config())

    return jsonify({
        "ok": True,
        "msg": "Nó registrado na rede.",
        "leader_url": state.get("leader_url"),
        "broadcast": b.get("broadcast"),
        "members": state.get("members", {}),
    })


# ===== Registro de usuário =====
@app.post("/register")
def register():
    payload = request.get_json(force=True) or {}

    leader, is_leader = current_leader()
    self_url = get_self_url()

    # Nó não-líder encaminha para o líder
    if not is_leader and leader and leader != self_url:
        try:
            resp = forward_to_leader(leader, "/register", payload)
            return jsonify(resp.get("json") or resp), 200
        except Exception:
            # se o líder caiu no meio, a thread de cluster vai eleger; devolve erro amigável
            return jsonify({"ok": False, "error": "líder indisponível (aguarde eleição automática)."}), 503

    # Líder cria usuário, salva e faz broadcast
    state = get_state()

    user, priv = criar_usuario(payload)
    users = state.get("users", {})

    if user.chave_pub in users:
        return jsonify({"ok": False, "error": "usuário já existe (mesma chave pública)"}), 409

    users[user.chave_pub] = user.to_dict()
    state["users"] = users
    state["last_updated"] = user.criado_em

    set_state(state)

    cfg = get_config()
    b = maybe_broadcast_if_leader(state, cfg)

    return jsonify({
        "ok": True,
        "msg": "Cadastro realizado com sucesso (estado propagado).",
        "user": user.to_dict(),
        "priv": priv,
        **b,
    })


# ===== Transferência =====
@app.post("/transfer")
def transfer():
    payload = request.get_json(force=True) or {}

    leader, is_leader = current_leader()
    self_url = get_self_url()

    if not is_leader and leader and leader != self_url:
        try:
            resp = forward_to_leader(leader, "/transfer", payload)
            return jsonify(resp.get("json") or resp), 200
        except Exception:
            return jsonify({"ok": False, "error": "líder indisponível (aguarde eleição automática)."}), 503

    # líder aplica a transação
    state = get_state()
    try:
        priv = str(payload.get("priv", ""))
        dest = str(payload.get("dest_pub", ""))
        quantia = int(payload.get("quantia", 0))
        tx = validar_e_aplicar_transferencia(state, priv, dest, quantia)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    set_state(state)

    cfg = get_config()
    b = maybe_broadcast_if_leader(state, cfg)

    return jsonify({
        "ok": True,
        "msg": "Transferência realizada com sucesso (estado propagado).",
        "tx": tx.to_dict(),
        **b,
    })


# ===== Sincronização (recebe do líder) =====
@app.post("/sync")
def sync():
    incoming = request.get_json(force=True) or {}
    set_state(incoming)
    return jsonify({"ok": True, "msg": "Estado sincronizado."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
