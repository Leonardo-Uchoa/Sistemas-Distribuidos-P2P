from __future__ import annotations

import secrets
import time
from hashlib import sha256
from typing import Dict, Optional


class AuthManager:
    def __init__(self):
        self.tokens: Dict[str, Dict] = {}

    @staticmethod
    def hash_secret(raw: str) -> str:
        return sha256(raw.encode("utf-8")).hexdigest()

    def issue(self, account_id: str, category: str) -> str:
        token = secrets.token_hex(24)
        self.tokens[token] = {
            "account_id": account_id,
            "category": category,
            "created_at": time.time(),
        }
        return token

    def get(self, token: str) -> Optional[Dict]:
        return self.tokens.get(token)

    def revoke(self, token: str) -> None:
        self.tokens.pop(token, None)
