#!/usr/bin/env python3
import socket, ssl, json, time, binascii, sys
from client import register, login, send_tx
from security_utils import payload_bytes, compute_hmac_hex
# Usa el mismo flag que en client.py
from client import USE_INSECURE_TESTING

HOST = "127.0.0.1"
PORT = 9000



def run():
    username = "bob"
    password = "mypassword"

    print(f"Registering user: {username}")
    print(register(username, password))

    login_resp = login(username, password)
    print("Login:", login_resp)

    if login_resp.get("status") != "ok":
        print("Login failed, aborting.")
        return

    session_id = login_resp["session_id"]
    session_key = login_resp["session_key"]

    # Normal payload 
    payload = {
        "from": "acc1",
        "to": "acc2",
        "amount": 100.0,
        "nonce": "deadbeef",
        "ts": int(time.time())
    }

    # correct HMAC 
    key = binascii.unhexlify(session_key)
    mac = compute_hmac_hex(key, payload_bytes(
        payload["from"], payload["to"], payload["amount"], payload["nonce"], payload["ts"]
    ))

    # Manipulated message: we changed the destination without recalculating the MAC
    tampered_payload = dict(payload)
    tampered_payload["to"] = "mallory"

    msg = {
        "type": "tx",
        "session_id": session_id,
        "payload": tampered_payload,
        "mac": mac
    }

    # ==== DIRECT POST WITHOUT USING client.py ====
    if USE_INSECURE_TESTING:
        # TCP 
        with socket.create_connection((HOST, PORT)) as s:
            s.sendall((json.dumps(msg) + "\n").encode())
            data = s.recv(4096)
    else:
        # TLS
        context = ssl.create_default_context()
        # If you use a self-signed certificate, you can disable verification:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((HOST, PORT)) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as s:
                s.sendall((json.dumps(msg) + "\n").encode())
                data = s.recv(4096)

    print("Server response to tampered tx:", data.decode().strip())


if __name__ == "__main__":
    run()
