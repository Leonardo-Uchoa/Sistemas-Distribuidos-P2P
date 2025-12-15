import importlib
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def reload_app(tmp_path: Path):
    os.environ["EDUCOIN_DATA_PATH"] = str(tmp_path / "ledger.json")
    os.environ["NODE_ID"] = "test-leader"
    os.environ["IS_LEADER"] = "true"
    os.environ["LEADER_TOKEN"] = "test-token"
    os.environ["RING_TOKEN"] = "ring-test"
    os.environ["RING_ENTRYPOINT"] = ""
    os.environ["LEADER_URL"] = ""
    os.environ["PEER_NODES"] = ""
    import educoin_project.app.main as main
    importlib.reload(main)
    return main


def test_full_transfer_flow(tmp_path):
    main = reload_app(tmp_path)
    client = TestClient(main.app)

    payload1 = {
        "name": "Alice",
        "cpf": "00011122233",
        "email": "alice@example.com",
        "password": "senha",
        "category": "diretor",
    }
    payload2 = {
        "name": "Bob",
        "cpf": "99988877766",
        "email": "bob@example.com",
        "password": "senha",
        "category": "aluno",
    }

    resp1 = client.post("/accounts", json=payload1)
    assert resp1.status_code == 200
    acc1 = resp1.json()["account"]
    priv1 = resp1.json()["private_key"]

    resp2 = client.post("/accounts", json=payload2)
    assert resp2.status_code == 200
    acc2 = resp2.json()["account"]

    main.ledger.set_balance(acc1["id"], 100)

    login = client.post("/login", json={"cpf": payload1["cpf"], "password": payload1["password"]})
    assert login.status_code == 200
    token = login.json()["token"]

    tx_resp = client.post(
        "/transactions",
        json={
            "from_account": acc1["id"],
            "to_account": acc2["id"],
            "private_key": priv1,
            "amount": 25,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert tx_resp.status_code == 200
    tx = tx_resp.json()["transaction"]
    assert tx["amount"] == 25

    snapshot = client.get("/accounts").json()
    acc1_data = next(acc for acc in snapshot["accounts"] if acc["id"] == acc1["id"])
    acc2_data = next(acc for acc in snapshot["accounts"] if acc["id"] == acc2["id"])
    assert acc1_data["balance"] == 75
    assert acc2_data["balance"] == 25

    log_resp = client.get(f"/accounts/{acc1['id']}/log", headers={"Authorization": f"Bearer {token}"})
    assert log_resp.status_code == 200
