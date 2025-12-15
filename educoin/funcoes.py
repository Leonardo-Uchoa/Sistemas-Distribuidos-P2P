from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests

from models import Usuario, Aluno, Prof, Diretor, Transacao


# ========= Criptografia didática (hash) =========
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def gerar_chaves(frase: str) -> Tuple[str, str]:
    """Gera (pub, priv) a partir de uma frase.

    Requisito do trabalho:
    - chaves são hashes da frase e são diferentes entre si.

    Escolha didática:
    priv = sha256("PRIV:" + frase)
    pub  = sha256("PUB:"  + priv)

    Vantagem: qualquer nó consegue verificar que a 'priv' apresentada
    corresponde a uma 'pub' (porque pub = hash(priv)).
    """
    priv = sha256_hex("PRIV:" + frase)
    pub = sha256_hex("PUB:" + priv)
    return pub, priv


def pub_from_priv(priv: str) -> str:
    """Deriva a chave pública a partir da privada (para validação no nó)."""
    return sha256_hex("PUB:" + priv)


# ========= Regras de saldo inicial =========
def saldo_inicial_por_tipo(tipo: str) -> int:
    tipo = (tipo or "").lower()
    if tipo == "aluno":
        return 100
    if tipo == "prof":
        return 1000
    if tipo == "diretor":
        return 10000
    raise ValueError("tipo inválido (use: aluno, prof, diretor)")


# ========= Usuários =========
def criar_usuario(payload: Dict[str, Any]) -> Tuple[Usuario, str]:
    """Cria um usuário a partir do payload recebido do frontend/API.

    Retorna (usuario_obj, priv) — a priv não fica salva no estado distribuído.
    """
    tipo = (payload.get("tipo") or "").lower().strip()
    nome = (payload.get("nome") or "").strip()
    email = (payload.get("email") or "").strip()
    matricula = (payload.get("matricula") or "").strip()
    frase = (payload.get("frase") or "").strip()

    if not all([tipo, nome, email, matricula, frase]):
        raise ValueError("campos obrigatórios: tipo, nome, email, matricula, frase")

    pub, priv = gerar_chaves(frase)
    saldo = saldo_inicial_por_tipo(tipo)

    # Campos extras (opcionais)
    meta = payload.get("meta") or {}

    if tipo == "aluno":
        user = Aluno(
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=pub,
            saldo=saldo,
            nota=float(payload.get("nota", 0)),
            semestre=str(payload.get("semestre", "")),
            eh_bolsista=bool(payload.get("eh_bolsista", False)),
            meta=meta,
        )
    elif tipo == "prof":
        user = Prof(
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=pub,
            saldo=saldo,
            materias=payload.get("materias") or [],
            carga_horaria=int(payload.get("carga_horaria", 0)),
            tem_bolsista=bool(payload.get("tem_bolsista", False)),
            meta=meta,
        )
    elif tipo == "diretor":
        user = Diretor(
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=pub,
            saldo=saldo,
            mandato=str(payload.get("mandato", "")),
            meta=meta,
        )
    else:
        raise ValueError("tipo inválido (use: aluno, prof, diretor)")

    return user, priv


# ========= Transações =========
def assinar_transacao(priv: str, de_pub: str, para_pub: str, quantia: int, timestamp: str) -> str:
    """Assinatura didática: hash do conteúdo + priv."""
    base = f"{de_pub}|{para_pub}|{quantia}|{timestamp}"
    return sha256_hex("SIG:" + priv + "|" + base)


def gerar_txid(de_pub: str, para_pub: str, quantia: int, timestamp: str) -> str:
    return sha256_hex(f"TX:{de_pub}|{para_pub}|{quantia}|{timestamp}|{time.time_ns()}")


def validar_e_aplicar_transferencia(
    state: Dict[str, Any],
    priv_remetente: str,
    pub_destinatario: str,
    quantia: int,
) -> Transacao:
    """Valida e aplica a transferência no estado (apenas no líder)."""
    if quantia <= 0:
        raise ValueError("quantia deve ser > 0")

    pub_remetente = pub_from_priv(priv_remetente)

    users = state.get("users", {})
    if pub_remetente not in users:
        raise ValueError("remetente não existe (priv não corresponde a nenhum usuário)")
    if pub_destinatario not in users:
        raise ValueError("destinatário não existe (chave pública inválida)")

    saldo_rem = int(users[pub_remetente].get("saldo", 0))
    if saldo_rem < quantia:
        raise ValueError("saldo insuficiente")

    # Aplica débito/crédito
    users[pub_remetente]["saldo"] = saldo_rem - quantia
    users[pub_destinatario]["saldo"] = int(users[pub_destinatario].get("saldo", 0)) + quantia

    # Cria transação
    ts = datetime.now(timezone.utc).isoformat()
    assinatura = assinar_transacao(priv_remetente, pub_remetente, pub_destinatario, quantia, ts)
    txid = gerar_txid(pub_remetente, pub_destinatario, quantia, ts)
    tx = Transacao(
        txid=txid,
        de_chave_pub=pub_remetente,
        para_chave_pub=pub_destinatario,
        quantia=int(quantia),
        timestamp=ts,
        assinatura=assinatura,
    )

    state["users"] = users
    state.setdefault("txs", []).append(tx.to_dict())
    state["last_updated"] = ts
    return tx


# ========= Sincronização/Broadcast =========
def broadcast_state(peers: List[str], state: Dict[str, Any], timeout_s: float = 2.0) -> Dict[str, Any]:
    """Envia o estado atualizado para todos os peers (best-effort)."""
    ok, fail = [], []
    for peer in peers:
        try:
            r = requests.post(peer.rstrip("/") + "/sync", json=state, timeout=timeout_s)
            if r.status_code == 200:
                ok.append(peer)
            else:
                fail.append({"peer": peer, "status": r.status_code, "body": r.text[:200]})
        except Exception as e:
            fail.append({"peer": peer, "error": str(e)})
    return {"ok": ok, "fail": fail}


def forward_to_leader(leader_url: str, path: str, payload: Dict[str, Any], timeout_s: float = 4.0) -> Dict[str, Any]:
    """Encaminha uma operação para o líder (quando este nó não é líder)."""
    url = leader_url.rstrip("/") + path
    r = requests.post(url, json=payload, timeout=timeout_s)
    try:
        return {"status": r.status_code, "json": r.json()}
    except Exception:
        return {"status": r.status_code, "text": r.text}
