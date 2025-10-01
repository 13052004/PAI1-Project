#!/usr/bin/env python3
"""Simple client to interact with the PAI-1 server.
Usage examples (from command-line):
  python3 client.py register alice password123
  python3 client.py login alice password123
  python3 client.py send_tx session_id session_key from_acc to_acc amount
"""
import ssl
import socket, json, sys, time, binascii
from security_utils import gen_nonce_hex, payload_bytes, compute_hmac_hex

HOST = '127.0.0.1'
PORT = 9000

# Toggle: if True, use plain TCP (for local testing without TLS)
USE_INSECURE_TESTING = True #Now using TLS
# socket timeouts (seconds)
CONNECT_TIMEOUT = 5.0
RECV_TIMEOUT = 5.0

def _recv_line(sock):
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None, 'recv_timeout'
        if not chunk:
            return None, 'connection_closed'
        data += chunk
        if b'\n' in data:
            line, _ = data.split(b'\n', 1)
            try:
                return json.loads(line.decode()), None
            except Exception as e:
                return None, f'invalid_json_resp: {e}'

def send_and_recv(msg):
    """Send msg (json object) and return the first JSON line response.
    Uses TLS if USE_INSECURE_TESTING is False; otherwise uses plain TCP.
    Returns a dict on success or a dict {'status':'error', 'reason':... } on failure.
    """
    if USE_INSECURE_TESTING:
        try:
            with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as s:
                s.settimeout(RECV_TIMEOUT)
                s.sendall((json.dumps(msg) + "\n").encode())
                resp, err = _recv_line(s)
                if err:
                    return {"status":"error","reason":err}
                return resp
        except ConnectionRefusedError as e:
            return {"status":"error","reason":"connection_refused","detail":str(e)}
        except socket.timeout as e:
            return {"status":"error","reason":"connect_timeout","detail":str(e)}
        except Exception as e:
            return {"status":"error","reason":"client_exception","detail":str(e)}
    else:
        context = ssl.create_default_context()
        # For local testing with SELF-SIGNED CERTS you might disable verification:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=HOST) as s:
                    s.settimeout(RECV_TIMEOUT)
                    s.sendall((json.dumps(msg) + "\n").encode())
                    resp, err = _recv_line(s)
                    if err:
                        return {"status":"error","reason":err}
                    return resp
        except ConnectionRefusedError as e:
            return {"status":"error","reason":"connection_refused","detail":str(e)}
        except socket.timeout as e:
            return {"status":"error","reason":"connect_timeout","detail":str(e)}
        except Exception as e:
            return {"status":"error","reason":"client_exception","detail":str(e)}

def register(username, password):
    msg = {"type":"register", "username": username, "password": password}
    return send_and_recv(msg)

def login(username, password):
    msg = {"type":"login", "username": username, "password": password}
    return send_and_recv(msg)

def send_tx(session_id, session_key_hex, from_acc, to_acc, amount, nonce=None, ts=None):
    if nonce is None:
        nonce = gen_nonce_hex()
    if ts is None:
        ts = int(time.time())
    payload = {"from": from_acc, "to": to_acc, "amount": float(amount), "nonce": nonce, "ts": ts}
    key = binascii.unhexlify(session_key_hex)
    msg_bytes = payload_bytes(payload["from"], payload["to"], payload["amount"], payload["nonce"], payload["ts"])
    mac = compute_hmac_hex(key, msg_bytes)
    msg = {"type":"tx", "session_id": session_id, "payload": payload, "mac": mac}
    return send_and_recv(msg)

def logout(session_id):
    msg = {"type":"logout", "session_id": session_id}
    return send_and_recv(msg)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: client.py [register|login|send_tx|logout] args...")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "register" and len(sys.argv)>=4:
        _, _, username, password = sys.argv
        print(register(username, password))
    elif cmd == "login" and len(sys.argv)>=4:
        _, _, username, password = sys.argv
        print(login(username, password))
    elif cmd == "send_tx" and len(sys.argv)>=7:
        _, _, session_id, session_key, from_acc, to_acc, amount = sys.argv
        print(send_tx(session_id, session_key, from_acc, to_acc, float(amount)))
    elif cmd == "logout" and len(sys.argv)>=3:
        _, _, session_id = sys.argv
        print(logout(session_id))
    else:
        print("unknown or malformed command")