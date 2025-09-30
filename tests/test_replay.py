#!/usr/bin/env python3
import socket, ssl, json, time, binascii
from client import register, login, send_tx, USE_INSECURE_TESTING
from security_utils import payload_bytes, compute_hmac_hex

HOST = "127.0.0.1"
PORT = 9000

def run():
    username = "carla"
    password = "secret"

    print(f"Registering user: {username}")
    print(register(username, password))

    login_resp = login(username, password)
    print("Login:", login_resp)

    if login_resp.get("status") != "ok":
        print("Login failed, aborting.")
        return

    session_id = login_resp["session_id"]
    session_key = login_resp["session_key"]

    # Send valid transaction
    print("Sending first tx (should succeed)")
    resp1 = send_tx(session_id, session_key, "acc1", "acc2", 10.0)
    print("Response:", resp1)

    # Try reusing the same playload (same nonce) 
    payload = {
        "from": "acc1",
        "to": "acc2",
        "amount": 10.0,
        "nonce": resp1.get("txid", "fixednonce"),  # For simplicity, may also reuse nonce manually
        "ts": int(time.time())
    }

    
    key = binascii.unhexlify(session_key)
    mac = compute_hmac_hex(key, payload_bytes(
        payload["from"], payload["to"], payload["amount"], payload["nonce"], payload["ts"]
    ))

    msg = {
        "type": "tx",
        "session_id": session_id,
        "payload": payload,
        "mac": mac
    }

    print("Replaying tx (should fail with replay_detected)")
    if USE_INSECURE_TESTING:
        with socket.create_connection((HOST, PORT)) as s:
            s.sendall((json.dumps(msg) + "\n").encode())
            data = s.recv(4096)
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((HOST, PORT)) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as s:
                s.sendall((json.dumps(msg) + "\n").encode())
                data = s.recv(4096)

    print("Server response to replayed tx:", data.decode().strip())


if __name__ == "__main__":
    run()
