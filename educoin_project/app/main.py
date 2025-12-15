from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .ledger import Ledger
from .p2p import LeaderProxy, PeerSync
from .state import LeaderState
from .storage import LedgerStore

DATA_PATH = os.environ.get("EDUCOIN_DATA_PATH", "./data/ledger.json")
NODE_ID = os.environ.get("NODE_ID", "node-1")
IS_LEADER_ENV = os.environ.get("IS_LEADER", "false").lower() == "true"
LEADER_URL = os.environ.get("LEADER_URL")
PEER_NODES = [node for node in os.environ.get("PEER_NODES", "").split(",") if node.strip()]
LEADER_TOKEN = os.environ.get("LEADER_TOKEN", "educoin-secret")
RING_TOKEN = os.environ.get("RING_TOKEN", "ring-secret")
RING_ENTRYPOINT = os.environ.get("RING_ENTRYPOINT")

store = LedgerStore(DATA_PATH)
ledger = Ledger(store)
state = LeaderState(NODE_ID, IS_LEADER_ENV, LEADER_URL, PEER_NODES)
peer_sync: Optional[PeerSync] = None
auth_scheme = HTTPBearer(auto_error=False)


def refresh_role():
    global peer_sync
    if state.is_leader():
        peer_sync = PeerSync(NODE_ID, state.peer_nodes, LEADER_TOKEN)
    else:
        peer_sync = None


refresh_role()

app = FastAPI(title="Educoin P2P")

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class AccountCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    cpf: str = Field(..., min_length=11)
    email: str
    password: str = Field(..., min_length=4)
    category: str


class TransferBody(BaseModel):
    from_account: str
    to_account: str
    private_key: str
    amount: float = Field(..., gt=0)


class ReplicateBody(BaseModel):
    accounts: list
    transactions: list
    blocks: list


class AccountResponse(BaseModel):
    account: Dict
    private_key: Optional[str]
    export_file: Optional[str]


class LoginBody(BaseModel):
    cpf: str
    password: str


class TransactionResponse(BaseModel):
    transaction: Dict


class SnapshotResponse(BaseModel):
    accounts: list
    transactions: list
    blocks: list


class LeaderAnnouncement(BaseModel):
    leader_id: str
    leader_url: str


def is_leader() -> bool:
    return state.is_leader()


def forward_to_leader(method: str, path: str, payload: Optional[Dict] = None):
    leader_url = state.leader_url()
    if not leader_url:
        raise HTTPException(status_code=503, detail="Líder desconhecido no momento")
    proxy = LeaderProxy(leader_url)
    try:
        return proxy.forward(method, path, payload)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


def forward_transaction_via_ring(payload: Dict, token: str) -> Dict:
    if not RING_ENTRYPOINT:
        raise HTTPException(status_code=503, detail="Ring não configurado para este nó")
    url = RING_ENTRYPOINT.rstrip("/") + "/txn_event"
    try:
        resp = httpx.post(
            url,
            json={
                "transaction": payload,
                "token": token,
                "origin_node": NODE_ID,
            },
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Ring indisponível: {exc}") from exc
    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=data.get("detail", data))
    return data


def require_auth(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Token requerido")
    token = credentials.credentials
    payload = ledger.auth.get(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    ctx = dict(payload)
    ctx["_token"] = token
    return ctx


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    snapshot = ledger.get_snapshot()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "node_id": NODE_ID,
            "is_leader": is_leader(),
            "leader_url": state.leader_url(),
            "accounts": snapshot["accounts"],
            "transactions": snapshot["transactions"],
            "blocks": snapshot["blocks"],
        },
    )


@app.get("/status")
async def status():
    snapshot = ledger.get_snapshot()
    return {
        "node_id": NODE_ID,
        "is_leader": is_leader(),
        "leader_url": state.leader_url(),
        "leader_id": state.leader_id(),
        "peers": PEER_NODES,
        "accounts": len(snapshot["accounts"]),
        "transactions": len(snapshot["transactions"]),
        "blocks": len(snapshot["blocks"]),
    }


@app.post("/accounts", response_model=AccountResponse)
async def create_account(body: AccountCreate):
    if not is_leader():
        return forward_to_leader("POST", "/accounts", body.dict())

    try:
        account, private_key, export_file = ledger.create_account(**body.dict())
        snapshot = ledger.get_snapshot()
        if peer_sync:
            peer_sync.broadcast_snapshot(snapshot)
        return {"account": account.__dict__, "private_key": private_key, "export_file": export_file}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/accounts", response_model=SnapshotResponse)
async def list_accounts():
    return ledger.get_snapshot()


@app.post("/login")
async def login(body: LoginBody):
    try:
        token, account = ledger.authenticate(body.cpf, body.password)
        return {"token": token, "account": account.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.post("/transactions", response_model=TransactionResponse)
async def create_transaction(body: TransferBody, auth=Depends(require_auth)):
    requester = auth["account_id"]
    token = auth["_token"]
    if requester != body.from_account:
        raise HTTPException(status_code=403, detail="Não pode movimentar outra conta")

    if not is_leader():
        return forward_transaction_via_ring(body.dict(), token)

    try:
        tx = ledger.transfer(
            from_id=body.from_account,
            private_key=body.private_key,
            to_id=body.to_account,
            amount=body.amount,
            node_id=NODE_ID,
        )
        snapshot = ledger.get_snapshot()
        if peer_sync:
            peer_sync.broadcast_snapshot(snapshot)
        return {"transaction": tx.__dict__}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/accounts/{account_id}/log")
async def download_log(account_id: str, auth=Depends(require_auth)):
    if auth["account_id"] != account_id:
        raise HTTPException(status_code=403, detail="Acesse apenas seu log")
    try:
        content = ledger.get_log(account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    path = Path(ledger.log_dir / f"{account_id}_download.csv")
    path.write_text(content, encoding="utf-8")
    return FileResponse(path, filename=f"log-{account_id}.csv")


@app.get("/accounts/{account_id}/export")
async def download_export(account_id: str, auth=Depends(require_auth)):
    if auth["account_id"] != account_id and auth["category"] != "diretor":
        raise HTTPException(status_code=403, detail="Sem permissão")
    try:
        path = ledger.export_account(account_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return FileResponse(path, filename=f"account-{account_id}.json")


@app.get("/blockchain")
async def blockchain():
    return {"blocks": ledger.blockchain.dump()}


@app.post("/election/leader")
async def election_leader(body: LeaderAnnouncement, request: Request):
    if request.headers.get("x-ring-token") != RING_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido para eleição")
    state.update_leader(body.leader_id, body.leader_url)
    refresh_role()
    return {
        "node_id": NODE_ID,
        "is_leader": state.is_leader(),
        "leader_url": state.leader_url(),
        "leader_id": state.leader_id(),
    }


@app.post("/replicate")
async def replicate(body: ReplicateBody, request: Request):
    if request.headers.get("x-leader-token") != LEADER_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido")
    ledger.replace_snapshot(body.dict())
    return {"ok": True}


@app.get("/sync", response_model=SnapshotResponse)
async def sync():
    return ledger.get_snapshot()


@app.post("/bootstrap")
async def bootstrap(request: Request):
    if is_leader():
        return {"message": "Líder não precisa sincronizar"}
    leader_url = state.leader_url()
    if not leader_url:
        raise HTTPException(status_code=400, detail="Leader URL não configurada")
    snapshot = forward_to_leader("GET", "/accounts")
    ledger.replace_snapshot(snapshot)
    return {"message": "Ledger sincronizado"}
