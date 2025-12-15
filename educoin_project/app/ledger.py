from __future__ import annotations

import csv
import json
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Tuple

from .auth import AuthManager
from .blockchain import Blockchain
from .models import Transaction, UserAccount
from .storage import LedgerStore


class Ledger:
    """In-memory representation of users, accounts, blocks and transactions."""

    def __init__(self, store: LedgerStore, export_dir: str = "./data/exports", log_dir: str = "./data/logs"):
        self.store = store
        self.export_dir = Path(export_dir)
        self.log_dir = Path(log_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        data = store.load()
        self.accounts: Dict[str, UserAccount] = {
            acc["id"]: UserAccount(**acc) for acc in data.get("accounts", [])
        }
        self.transactions: List[Transaction] = [
            Transaction(**tx) for tx in data.get("transactions", [])
        ]
        self.blockchain = Blockchain()
        self.blockchain.load(data.get("blocks", []))
        if not self.blockchain.chain and self.transactions:
            for tx in self.transactions:
                self.blockchain.add_block([tx], creator="genesis")
        self.auth = AuthManager()

    @staticmethod
    def _hash_secret(raw: str) -> str:
        return AuthManager.hash_secret(raw)

    @staticmethod
    def _generate_key() -> str:
        return secrets.token_hex(24)

    def _persist(self):
        payload = {
            "accounts": [acc.__dict__ for acc in self.accounts.values()],
            "transactions": [tx.__dict__ for tx in self.transactions],
            "blocks": self.blockchain.dump(),
        }
        self.store.save(payload)

    def _write_log(self, account_id: str, row: List[str]) -> None:
        path = self.log_dir / f"{account_id}.csv"
        new_file = not path.exists()
        with path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if new_file:
                writer.writerow(["timestamp", "action", "details"])
            writer.writerow(row)

    def _export_keys(self, account: UserAccount, private_key: str) -> Path:
        payload = {
            "account": account.__dict__,
            "private_key": private_key,
        }
        path = self.export_dir / f"{account.id}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return path

    def create_account(self, *, name: str, cpf: str, email: str, password: str, category: str) -> Tuple[UserAccount, str, str]:
        if category not in {"professor", "diretor", "aluno"}:
            raise ValueError("Categoria inválida")
        private_key = self._generate_key()
        account = UserAccount(
            id=str(uuid.uuid4()),
            name=name.strip(),
            cpf=cpf.strip(),
            email=email.strip().lower(),
            category=category,
            password_hash=self._hash_secret(password),
            public_key=self._generate_key(),
            private_key_hash=self._hash_secret(private_key),
            balance=0.0,
            created_at=time.time(),
        )
        with self._lock:
            if any(acc.cpf == account.cpf for acc in self.accounts.values()):
                raise ValueError("CPF já cadastrado")
            self.accounts[account.id] = account
            self._persist()
        self._write_log(account.id, [str(time.time()), "create_account", json.dumps({"name": account.name})])
        export_file = self._export_keys(account, private_key)
        return account, private_key, str(export_file)

    def authenticate(self, cpf: str, password: str) -> Tuple[str, UserAccount]:
        with self._lock:
            account = next((acc for acc in self.accounts.values() if acc.cpf == cpf.strip()), None)
            if not account:
                raise ValueError("Usuário não encontrado")
            if account.password_hash != self._hash_secret(password):
                raise ValueError("Senha inválida")
        token = self.auth.issue(account.id, account.category)
        return token, account

    def transfer(self, *, from_id: str, private_key: str, to_id: str, amount: float, node_id: str) -> Transaction:
        if amount <= 0:
            raise ValueError("Valor deve ser positivo")
        with self._lock:
            if from_id not in self.accounts or to_id not in self.accounts:
                raise ValueError("Conta origem ou destino inexistente")
            source = self.accounts[from_id]
            target = self.accounts[to_id]
            if source.private_key_hash != self._hash_secret(private_key):
                raise ValueError("Private key inválida")
            if source.balance < amount:
                raise ValueError("Saldo insuficiente")
            source.balance -= amount
            target.balance += amount
            tx = Transaction(
                id=str(uuid.uuid4()),
                from_account=source.id,
                to_account=target.id,
                amount=round(amount, 2),
                timestamp=time.time(),
            )
            self.transactions.append(tx)
            block = self.blockchain.add_block([tx], creator=node_id)
            self._persist()
        log_payload = {
            "tx": tx.__dict__,
            "block": block.hash,
        }
        ts = str(time.time())
        self._write_log(source.id, [ts, "send", json.dumps(log_payload)])
        self._write_log(target.id, [ts, "receive", json.dumps(log_payload)])
        return tx

    def get_snapshot(self) -> Dict[str, List[Dict]]:
        with self._lock:
            return {
                "accounts": [acc.__dict__ for acc in self.accounts.values()],
                "transactions": [tx.__dict__ for tx in self.transactions],
                "blocks": self.blockchain.dump(),
            }

    def replace_snapshot(self, snapshot: Dict[str, List[Dict]]) -> None:
        with self._lock:
            self.accounts = {acc["id"]: UserAccount(**acc) for acc in snapshot.get("accounts", [])}
            self.transactions = [
                Transaction(**tx) for tx in snapshot.get("transactions", [])
            ]
            self.blockchain.load(snapshot.get("blocks", []))
            self._persist()

    def export_account(self, account_id: str) -> str:
        with self._lock:
            if account_id not in self.accounts:
                raise ValueError("Conta não encontrada")
            dummy_private = "***"
            payload = {
                "account": self.accounts[account_id].__dict__,
                "private_key": dummy_private,
            }
        path = self.export_dir / f"{account_id}_public.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return str(path)

    def get_log(self, account_id: str) -> str:
        path = self.log_dir / f"{account_id}.csv"
        if not path.exists():
            raise ValueError("Log não encontrado")
        with path.open("r", encoding="utf-8") as f:
            return f.read()

    def set_balance(self, account_id: str, amount: float) -> None:
        with self._lock:
            if account_id not in self.accounts:
                raise ValueError("Conta não encontrada")
            self.accounts[account_id].balance = amount
            self._persist()
