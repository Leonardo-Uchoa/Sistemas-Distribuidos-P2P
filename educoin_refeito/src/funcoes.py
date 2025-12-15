import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Optional

# -----------------------------
# Criptografia "didática"
# -----------------------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def gerar_chaves(frase: str) -> Tuple[str, str, str]:
    """
    Gera (pub, priv, priv_hash) a partir de uma frase.
    - pub e priv são hashes diferentes (requisito do trabalho).
    - priv_hash é o hash do priv (permite localizar o dono sem armazenar priv).
    """
    frase = (frase or "").strip()
    if not frase:
        raise ValueError("Frase-secreta vazia.")
    pub = sha256_hex("PUB:" + frase)
    priv = sha256_hex("PRIV:" + frase)
    priv_hash = sha256_hex("PRIVHASH:" + priv)
    return pub, priv, priv_hash

def saldo_inicial_por_tipo(tipo: str) -> int:
    t = (tipo or "").strip().lower()
    if t == "aluno":
        return 100
    if t == "professor":
        return 1000
    if t == "diretor":
        return 10000
    raise ValueError("Tipo inválido. Use: aluno, professor, diretor.")

def normalizar_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        raise ValueError("URL vazia.")
    if not (u.startswith("http://") or u.startswith("https://")):
        u = "http://" + u
    u = u.rstrip("/")
    return u

# -----------------------------
# Regras de negócio
# -----------------------------
def criar_usuario(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Cria um usuário no formato serializável.
    Retorna (user_dict, priv_para_mostrar_uma_vez).
    """
    tipo = (payload.get("tipo") or "").strip().lower()
    nome = (payload.get("nome") or "").strip()
    email = (payload.get("email") or "").strip()
    matricula = (payload.get("matricula") or "").strip()
    frase = (payload.get("frase") or "").strip()

    pub, priv, priv_hash = gerar_chaves(frase)

    user = {
        "tipo": tipo,
        "nome": nome,
        "email": email,
        "matricula": matricula,
        "chave_pub": pub,
        "priv_hash": priv_hash,
        "saldo": saldo_inicial_por_tipo(tipo),
        "criado_em": utc_now_iso(),  # sempre existe (fix do bug do 500)
    }
    return user, priv

def assinar_tx(priv: str, dest_pub: str, quantia: int, timestamp: str) -> str:
    # Assinatura didática (não é ECDSA/Ed25519).
    # Serve para mostrar integridade e rastreabilidade.
    base = f"{priv}|{dest_pub}|{quantia}|{timestamp}"
    return sha256_hex("SIG:" + base)

def criar_tx(de_pub: str, para_pub: str, quantia: int, assinatura: str, timestamp: str) -> Dict[str, Any]:
    txid = sha256_hex(f"TX:{de_pub}|{para_pub}|{quantia}|{timestamp}|{assinatura}")
    return {
        "txid": txid,
        "timestamp": timestamp,
        "de_chave_pub": de_pub,
        "para_chave_pub": para_pub,
        "quantia": quantia,
        "assinatura": assinatura,
    }

def encontrar_usuario_por_priv(users: Dict[str, Dict[str, Any]], priv: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Localiza o remetente sem guardar a chave privada.
    - Guarda-se apenas priv_hash no cadastro.
    """
    priv = (priv or "").strip()
    if not priv:
        return None, None
    priv_hash = sha256_hex("PRIVHASH:" + priv)
    for pub, u in users.items():
        if u.get("priv_hash") == priv_hash:
            return pub, u
    return None, None

def aplicar_transferencia(state: Dict[str, Any], priv: str, dest_pub: str, quantia: int) -> Dict[str, Any]:
    """
    Valida e aplica a transferência.
    - Debita saldo do remetente
    - Credita saldo do destinatário
    - Registra transação
    """
    users = state.setdefault("usuarios", {})
    txs = state.setdefault("txs", [])

    if not isinstance(quantia, int):
        raise ValueError("Quantia deve ser um inteiro.")
    if quantia <= 0:
        raise ValueError("Quantia deve ser > 0.")

    dest_pub = (dest_pub or "").strip()
    if dest_pub not in users:
        raise ValueError("Destinatário (chave pública) não existe.")

    sender_pub, sender = encontrar_usuario_por_priv(users, priv)
    if not sender_pub or not sender:
        raise ValueError("Chave privada inválida (remetente não encontrado).")

    if sender_pub == dest_pub:
        raise ValueError("Remetente e destinatário não podem ser o mesmo.")

    if sender.get("saldo", 0) < quantia:
        raise ValueError("Saldo insuficiente.")

    # aplica
    sender["saldo"] -= quantia
    users[dest_pub]["saldo"] += quantia

    ts = utc_now_iso()
    assinatura = assinar_tx(priv, dest_pub, quantia, ts)
    tx = criar_tx(sender_pub, dest_pub, quantia, assinatura, ts)

    txs.append(tx)
    state["last_updated"] = ts
    return tx
