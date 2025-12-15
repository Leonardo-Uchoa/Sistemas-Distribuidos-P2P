from __future__ import annotations

import logging
from typing import Dict, List, Optional

import httpx


class PeerSync:
    def __init__(self, node_id: str, peers: List[str], leader_token: str):
        self.node_id = node_id
        self.peers = [p.strip() for p in peers if p.strip()]
        self.leader_token = leader_token
        self.session = httpx.Client(timeout=10)

    def broadcast_snapshot(self, snapshot: Dict) -> None:
        if not self.peers:
            return
        headers = {"x-leader-token": self.leader_token}
        for peer in self.peers:
            try:
                url = f"{peer}/replicate"
                self.session.post(url, json=snapshot, headers=headers)
                logging.info("Snapshot enviado para %s", peer)
            except httpx.HTTPError as exc:
                logging.warning("Falha ao replicar para %s: %s", peer, exc)


class LeaderProxy:
    def __init__(self, leader_url: Optional[str]):
        self.leader_url = leader_url.rstrip("/") if leader_url else None
        self.session = httpx.Client(timeout=10)

    def forward(self, method: str, path: str, payload: Optional[Dict] = None) -> Dict:
        if not self.leader_url:
            raise RuntimeError("Leader URL não configurada")
        url = f"{self.leader_url}{path}"
        response = self.session.request(method, url, json=payload)
        response.raise_for_status()
        return response.json()
