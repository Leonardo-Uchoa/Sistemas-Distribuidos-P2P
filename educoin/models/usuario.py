from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


@dataclass
class Usuario:
    """Representa uma conta (carteira) dentro da rede EduCoin.

    Observação didática:
    - Guardamos só a chave pública no estado distribuído.
    - A chave privada é usada apenas no momento da transferência (o usuário apresenta).
    """

    tipo: str  # "aluno" | "prof" | "diretor"
    nome: str
    email: str
    matricula: str

    chave_pub: str
    saldo: int = 0

    # Campos opcionais para estender no futuro
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # normaliza None
        if d.get("meta") is None:
            d["meta"] = {}
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Usuario":
        return Usuario(
            tipo=d["tipo"],
            nome=d["nome"],
            email=d["email"],
            matricula=d["matricula"],
            chave_pub=d["chave_pub"],
            saldo=int(d.get("saldo", 0)),
            meta=d.get("meta") or {},
        )
