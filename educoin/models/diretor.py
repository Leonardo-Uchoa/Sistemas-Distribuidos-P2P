from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional
from .usuario import Usuario


@dataclass
class Diretor(Usuario):
    mandato: str = ""

    def __init__(
        self,
        nome: str,
        email: str,
        matricula: str,
        chave_pub: str,
        saldo: int,
        mandato: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            tipo="diretor",
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=chave_pub,
            saldo=saldo,
            meta=meta,
        )
        self.mandato = str(mandato)
