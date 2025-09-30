import time
import sqlite3
from client import register, login, send_tx

DB_PATH = 'pai1.db'

def test_session_expiry():
    _ = register("test_expiry_user", "pw12345")
    resp = login("test_expiry_user", "pw12345")
    assert resp.get("status") == "ok", resp
    session_id = resp.get("session_id")
    session_key = resp.get("session_key")
    assert session_id and session_key

    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE sessions SET expires=? WHERE session_id=?", (now - 10, session_id))
    conn.commit()
    conn.close()

    tx_resp = send_tx(session_id, session_key, from_acc="a", to_acc="b", amount=5.0)
    assert tx_resp.get("status") == "error"
    assert tx_resp.get("reason") in ("session_expired", "invalid_session"), f"unexpected: {tx_resp}"


if __name__ == "__main__":
    test_session_expiry()

