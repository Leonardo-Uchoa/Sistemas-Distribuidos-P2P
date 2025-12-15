from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class Transacao:
    """Transação de saldo (modelo account-based simplificado)."""

    txid: str
    de_chave_pub: str
    para_chave_pub: str
    quantia: int
    timestamp: str  # ISO8601
    assinatura: str

    def to_dict(self) -> Dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict) -> "Transacao":
        return Transacao(
            txid=d["txid"],
            de_chave_pub=d["de_chave_pub"],
            para_chave_pub=d["para_chave_pub"],
            quantia=int(d["quantia"]),
            timestamp=d["timestamp"],
            assinatura=d["assinatura"],
        )
