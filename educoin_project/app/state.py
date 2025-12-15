from __future__ import annotations

import threading
from typing import List, Optional


class LeaderState:
    """Holds leader configuration shared across the FastAPI app."""

    def __init__(
        self,
        node_id: str,
        initial_is_leader: bool,
        leader_url: Optional[str],
        peer_nodes: Optional[List[str]] = None,
    ):
        self.node_id = node_id
        self._is_leader = initial_is_leader
        self._leader_id = node_id if initial_is_leader else None
        self._leader_url = leader_url.rstrip("/") if leader_url else None
        self.peer_nodes = peer_nodes or []
        self._lock = threading.Lock()

    def is_leader(self) -> bool:
        with self._lock:
            return self._is_leader

    def leader_url(self) -> Optional[str]:
        with self._lock:
            return self._leader_url

    def leader_id(self) -> Optional[str]:
        with self._lock:
            return self._leader_id

    def update_leader(self, leader_id: str, leader_url: str) -> bool:
        """Returns True if this node became leader after the update."""
        leader_url = leader_url.rstrip("/") if leader_url else None
        with self._lock:
            self._leader_id = leader_id
            self._leader_url = leader_url
            self._is_leader = leader_id == self.node_id
            return self._is_leader

