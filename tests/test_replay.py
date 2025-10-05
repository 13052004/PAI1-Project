#!/usr/bin/env python3
"""
Test: enviar dos veces la misma transacción (replay).
La primera debe aceptarse, la segunda debe rechazarse con reason == "replay_detected".
Funciona tanto en TCP como en TLS (usa la configuración de client.py).
"""

import sys
import time
import binascii

from client import register, login, send_tx
from security_utils import gen_nonce_hex

def run():
    username = "carla"
    password = "secret"

    print("Registering user:", username)
    print(register(username, password))

    print("Logging in:")
    res = login(username, password)
    print(res)
    if res.get("status") != "ok":
        print("Login failed:", res)
        return 1

    session_id = res["session_id"]
    session_key = res["session_key"]

    # Genera nonce y timestamp fijos para ambos envíos
    nonce = gen_nonce_hex()
    ts = int(time.time())

    print("Sending first tx (should succeed)")
    resp1 = send_tx(session_id, session_key, "ACC1", "ACC2", 5.0, nonce=nonce, ts=ts)
    print("First tx response:", resp1)
    if resp1.get("status") != "ok":
        print("First TX failed unexpectedly; aborting test.")
        return 2

    # Espera para evitar colisiones 
    time.sleep(0.1)

    print("Replaying same tx (same nonce and ts) — should be rejected")
    resp2 = send_tx(session_id, session_key, "ACC1", "ACC2", 5.0, nonce=nonce, ts=ts)
    print("Second tx response (expected error):", resp2)

    # Comprobación
    if resp2.get("status") == "error" and resp2.get("reason") == "replay_detected":
        print("Replay correctly detected.")
        return 0
    else:
        print("Replay NOT detected correctly! (unexpected response)")
        return 3

if __name__ == "__main__":
    sys.exit(run())
