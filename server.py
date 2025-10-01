#!/usr/bin/env python3
import ssl
import socket, threading, json, time, binascii, hmac, os, sqlite3, logging
from security_utils import init_db, gen_salt, pbkdf2_hash, save_user, get_user, set_failed, create_session, get_session, persist_nonce, persist_tx, gen_nonce_hex
from security_utils import compute_hmac_hex, verify_hmac_hex, payload_bytes

DB_PATH = 'pai1.db'
HOST = '127.0.0.1'
PORT = 9000

# basic logging config (also prints to stdout)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('pai1-server')

db = init_db(DB_PATH)

def handle_client(conn, addr):
    logger.info(f"Accepted connection from {addr}")
    with conn:
        data = b''
        while True:
            try:
                chunk = conn.recv(4096)
            except Exception as e:
                logger.warning(f"Recv error from {addr}: {e}")
                break
            if not chunk:
                logger.info(f"Connection closed by {addr}")
                break
            data += chunk
            # process newline-delimited JSON messages
            while b'\n' in data:
                line, data = data.split(b'\n', 1)
                try:
                    msg = json.loads(line.decode())
                except Exception as e:
                    resp = {"status":"error","reason":"invalid_json"}
                    try:
                        conn.sendall((json.dumps(resp)+"\n").encode())
                    except Exception:
                        pass
                    continue
                logger.info(f"Received message from {addr}: {msg}")
                try:
                    resp = process_message(msg)
                except Exception as e:
                    logger.exception(f"Error processing message {msg}: {e}")
                    resp = {"status":"error","reason":"internal_error","detail":str(e)}
                try:
                    conn.sendall((json.dumps(resp)+"\n").encode())
                except Exception as e:
                    logger.warning(f"Send error to {addr}: {e}")
                    break

def process_message(msg):
    typ = msg.get("type")
    if typ == "register":
        return handle_register(msg)
    if typ == "login":
        return handle_login(msg)
    if typ == "tx":
        return handle_tx(msg)
    if typ == "logout":
        return handle_logout(msg)
    return {"status":"error","reason":"unknown_type"}

# Registration: expects {"type":"register","username":"u","password":"p"}
def handle_register(msg):
    username = msg.get("username")
    password = msg.get("password")
    if not username or not password:
        return {"status":"error","reason":"missing_fields"}
    if get_user(db, username) is not None:
        return {"status":"error","reason":"user_exists"}
    salt = gen_salt()
    pwd_hash = pbkdf2_hash(password, salt)
    save_user(db, username, salt, pwd_hash)
    logger.info(f"User registered: {username}")
    return {"status":"ok","msg":"user_registered"}

# Login: {"type":"login","username":"u","password":"p"}
def handle_login(msg):
    username = msg.get("username")
    password = msg.get("password")
    rec = get_user(db, username)
    if rec is None:
        return {"status":"error","reason":"invalid_credentials"}
    _, salt, pwd_hash, failed, lock_until = rec
    now = int(time.time())
    if lock_until and now < lock_until:
        return {"status":"error","reason":"locked"}
    calc = pbkdf2_hash(password, salt)
    if not hmac.compare_digest(calc, pwd_hash):
        failed = (failed or 0) + 1
        if failed >= 5:
            lock_until = now + 300  # 5 minutes lock
        set_failed(db, username, failed, lock_until)
        logger.warning(f"Invalid login attempt for {username}")
        return {"status":"error","reason":"invalid_credentials"}
    set_failed(db, username, 0, 0)
    session_key = binascii.hexlify(os.urandom(32)).decode()
    session_id, expires = create_session(db, username, session_key, ttl=3600)
    logger.info(f"User logged in: {username}, session_id={session_id}")
    return {"status":"ok","session_id":session_id, "session_key": session_key, "expires": expires}

# Logout
def handle_logout(msg):
    session_id = msg.get("session_id")
    if not session_id:
        return {"status": "error", "reason": "missing_fields"}
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        conn.close()
        logger.info(f"Session logged out: {session_id}")
        return {"status": "ok", "msg": "logged_out"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"status": "error", "reason": "server_exception"}

# Transaction: expects JSON with fields:
# type: "tx", session_id, payload {from,to,amount,nonce,ts}, mac
def handle_tx(msg):
    session_id = msg.get("session_id")
    payload = msg.get("payload")
    mac = msg.get("mac")
    if not session_id or not payload or not mac:
        return {"status":"error","reason":"missing_fields"}
    sess = get_session(db, session_id)
    if not sess:
        return {"status":"error","reason":"invalid_session"}
    _, username, session_key_hex, expires = sess
    if int(time.time()) > expires:
        return {"status":"error","reason":"session_expired"}
    try:
        from_ac = payload["from"]
        to_ac = payload["to"]
        amount = payload["amount"]
        nonce = payload["nonce"]
        ts = payload.get("ts", int(time.time()))
    except Exception:
        return {"status":"error","reason":"bad_payload"}
    msg_bytes = payload_bytes(from_ac, to_ac, amount, nonce, ts)
    try:
        key = binascii.unhexlify(session_key_hex)
    except Exception:
        return {"status":"error","reason":"bad_session_key"}
    if not verify_hmac_hex(key, msg_bytes, mac):
        return {"status":"error","reason":"bad_mac"}
    ok = persist_nonce(db, nonce, username)
    if not ok:
        return {"status":"error","reason":"replay_detected"}
    txid = persist_tx(db, username, from_ac, to_ac, amount)
    logger.info(f"Persisted tx {txid} for user {username}")
    return {"status":"ok","txid":txid}

def run_server(host=HOST, port=PORT):
    logger.info(f"Starting server on {host}:{port} (DB: {DB_PATH})")
    # Create TLS context
    #context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #Load certificate and key 
    #context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        #Wrap socket in server mode: it'll accept TLS conections
        #with context.wrap_socket(s, server_side=True) as tls_sock: #Comment this line to use TCP
            #logger.info("Server listening with TLS") #Comment this line to use TCP
        while True:
            conn, addr = s.accept()  #tls_sock.accept() 
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    run_server()
