from __future__ import annotations

import json
import time
from hashlib import sha256
from typing import List

from .models import Block, Transaction


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []

    @staticmethod
    def _hash_block(index: int, timestamp: float, previous_hash: str, txs: List[Transaction], creator: str) -> str:
        tx_payload = [tx.__dict__ for tx in txs]
        payload = json.dumps({
            "index": index,
            "timestamp": timestamp,
            "previous_hash": previous_hash,
            "transactions": tx_payload,
            "creator": creator,
        }, sort_keys=True).encode("utf-8")
        return sha256(payload).hexdigest()

    def add_block(self, transactions: List[Transaction], creator: str) -> Block:
        previous_hash = self.chain[-1].hash if self.chain else "GENESIS"
        index = len(self.chain)
        timestamp = time.time()
        block_hash = self._hash_block(index, timestamp, previous_hash, transactions, creator)
        block = Block(
            index=index,
            timestamp=timestamp,
            previous_hash=previous_hash,
            hash=block_hash,
            transactions=transactions,
            creator=creator,
        )
        self.chain.append(block)
        return block

    def load(self, blocks: List[dict]) -> None:
        self.chain = [
            Block(
                index=b["index"],
                timestamp=b["timestamp"],
                previous_hash=b["previous_hash"],
                hash=b["hash"],
                transactions=[Transaction(**tx) for tx in b.get("transactions", [])],
                creator=b.get("creator", "unknown"),
            )
            for b in blocks
        ]

    def dump(self) -> List[dict]:
        return [
            {
                "index": block.index,
                "timestamp": block.timestamp,
                "previous_hash": block.previous_hash,
                "hash": block.hash,
                "creator": block.creator,
                "transactions": [tx.__dict__ for tx in block.transactions],
            }
            for block in self.chain
        ]
