import time
import sqlite3
from client import register, login, logout, send_tx

DB_PATH = 'pai1.db'

def test_logout_invalidates_session():
    _ = register("test_logout_user", "secretpw")
    resp = login("test_logout_user", "secretpw")
    assert resp.get("status") == "ok", f"login failed: {resp}"
    session_id = resp.get("session_id")
    session_key = resp.get("session_key")
    assert session_id and session_key

    resp2 = logout(session_id)
    assert resp2.get("status") == "ok", f"logout failed: {resp2}"

    tx_resp = send_tx(session_id, session_key, from_acc="acc1", to_acc="acc2", amount=1.23)
    assert tx_resp.get("status") == "error"
    assert tx_resp.get("reason") in ("invalid_session", "session_expired"), f"unexpected reason: {tx_resp}"


if __name__ == "__main__":
    test_logout_invalidates_session()

