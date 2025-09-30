# tests/test_valid.py
"""
Test: register, login, send a valid transaction.
Handles preexisting users.
"""
from client import register, login, send_tx
import sys, time

USE_INSECURE_TESTING = True  # <- poner False en entornos reales

def run():
    u = "alice"
    p = "password123"

    # Try register, but skip if it already exists
    res = register(u, p)
    if res.get("status") == "error" and res.get("reason") == "user_exists":
        print(f"User {u} already exists, skipping registration.")
    else:
        print("Registering user:", u, res)

    # Login
    print("Logging in:")
    res = login(u, p)
    print(res)
    if res.get("status") != "ok":
        print("Login failed:", res)
        return 1

    session_id = res["session_id"]
    session_key = res["session_key"]

    # Send valid transaction
    print("Sending valid transaction...")
    r2 = send_tx(session_id, session_key, "ACC1", "ACC2", 42.5)
    print("Server response:", r2)
    if r2.get("status") != "ok":
        print("Transaction rejected:", r2)
        return 2

    return 0

if __name__ == "__main__":
    sys.exit(run())
