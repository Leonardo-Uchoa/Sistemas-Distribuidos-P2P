from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from .usuario import Usuario


@dataclass
class Prof(Usuario):
    materias: List[str] = None
    carga_horaria: int = 0
    tem_bolsista: bool = False

    def __init__(
        self,
        nome: str,
        email: str,
        matricula: str,
        chave_pub: str,
        saldo: int,
        materias: Optional[List[str]] = None,
        carga_horaria: int = 0,
        tem_bolsista: bool = False,
        meta: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            tipo="prof",
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=chave_pub,
            saldo=saldo,
            meta=meta,
        )
        self.materias = list(materias or [])
        self.carga_horaria = int(carga_horaria)
        self.tem_bolsista = bool(tem_bolsista)
