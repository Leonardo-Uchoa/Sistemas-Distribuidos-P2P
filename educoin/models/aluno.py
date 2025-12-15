from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional
from .usuario import Usuario


@dataclass
class Aluno(Usuario):
    nota: float = 0.0
    semestre: str = ""
    eh_bolsista: bool = False

    def __init__(
        self,
        nome: str,
        email: str,
        matricula: str,
        chave_pub: str,
        saldo: int,
        nota: float = 0.0,
        semestre: str = "",
        eh_bolsista: bool = False,
        meta: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            tipo="aluno",
            nome=nome,
            email=email,
            matricula=matricula,
            chave_pub=chave_pub,
            saldo=saldo,
            meta=meta,
        )
        self.nota = float(nota)
        self.semestre = str(semestre)
        self.eh_bolsista = bool(eh_bolsista)
