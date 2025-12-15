from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class UserAccount:
    id: str
    name: str
    cpf: str
    email: str
    category: str
    password_hash: str
    public_key: str
    private_key_hash: str
    balance: float
    created_at: float


@dataclass
class Transaction:
    id: str
    from_account: str
    to_account: str
    amount: float
    timestamp: float


@dataclass
class Block:
    index: int
    timestamp: float
    previous_hash: str
    hash: str
    transactions: List[Transaction]
    creator: str
