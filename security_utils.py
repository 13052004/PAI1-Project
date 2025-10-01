import os, hmac, hashlib, json, time, sqlite3, binascii, uuid
from typing import Tuple

# --- Hashing for passwords (PBKDF2-HMAC-SHA256) ---
def gen_salt(n=16) -> str:
    return binascii.hexlify(os.urandom(n)).decode()

def pbkdf2_hash(password: str, salt: str, iterations=200_000) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return binascii.hexlify(dk).decode()

# --- HMAC helpers ---
def compute_hmac_hex(key: bytes, msg_bytes: bytes) -> str:
    return hmac.new(key, msg_bytes, hashlib.sha256).hexdigest()

def verify_hmac_hex(key: bytes, msg_bytes: bytes, recv_hex: str) -> bool:
    calc = compute_hmac_hex(key, msg_bytes)
    return hmac.compare_digest(calc, recv_hex)

# --- Nonce generation ---
def gen_nonce_hex(n=16) -> str:
    return binascii.hexlify(os.urandom(n)).decode()

# --- Canonical payload bytes ---
def payload_bytes(from_ac, to_ac, amount, nonce, ts):
    j = json.dumps({
        "from": from_ac,
        "to": to_ac,
        "amount": float(amount),
        "nonce": nonce,
        "ts": int(ts)
    }, separators=(',', ':'), sort_keys=True)
    return j.encode()

def seed_initial_users(db):
    #Initial users: Alice, Bob, Carla
    initial = [("alice", "password123"), ("bob", "hunter2"), ("carla", "mypwd")]
    for username, password in initial:
        if get_user(db, username) is None:
            salt = gen_salt()
            pwd_hash = pbkdf2_hash(password, salt)
            save_user(db, username, salt, pwd_hash)

# --- DB helpers (SQLite) ---
def init_db(path='pai1.db'):
    db = sqlite3.connect(path, check_same_thread=False)
    c = db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
                  username TEXT PRIMARY KEY,
                  salt TEXT,
                  pwd_hash TEXT,
                  failed INT DEFAULT 0,
                  lock_until INT DEFAULT 0
               )""")
    c.execute("""CREATE TABLE IF NOT EXISTS sessions(
                  session_id TEXT PRIMARY KEY,
                  username TEXT,
                  session_key TEXT,
                  expires INT
               )""")
    c.execute("""CREATE TABLE IF NOT EXISTS used_nonces(
                  nonce TEXT PRIMARY KEY,
                  username TEXT,
                  ts INT
               )""")
    c.execute("""CREATE TABLE IF NOT EXISTS txs(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  from_acc TEXT,
                  to_acc TEXT,
                  amount REAL,
                  ts INT,
                  tx_mac TEXT
               )""")
    db.commit()
    #Initializes DB with existing user as requested 
    #seed_initial_users(db) 
    return db

def save_user(db, username, salt, pwd_hash):
    c = db.cursor()
    c.execute("INSERT INTO users(username, salt, pwd_hash) VALUES (?,?,?)", (username, salt, pwd_hash))
    db.commit()

def get_user(db, username):
    c = db.cursor()
    c.execute("SELECT username, salt, pwd_hash, failed, lock_until FROM users WHERE username=?", (username,))
    return c.fetchone()

def set_failed(db, username, failed, lock_until):
    c = db.cursor()
    c.execute("UPDATE users SET failed=?, lock_until=? WHERE username=?", (failed, lock_until, username))
    db.commit()

def create_session(db, username, session_key_hex, ttl=3600):
    session_id = str(uuid.uuid4())
    expires = int(time.time()) + ttl
    c = db.cursor()
    c.execute("INSERT INTO sessions(session_id, username, session_key, expires) VALUES (?,?,?,?)",
              (session_id, username, session_key_hex, expires))
    db.commit()
    return session_id, expires

def get_session(db, session_id):
    c = db.cursor()
    c.execute("SELECT session_id, username, session_key, expires FROM sessions WHERE session_id=?", (session_id,))
    return c.fetchone()

def persist_nonce(db, nonce, username):
    c = db.cursor()
    try:
        c.execute("INSERT INTO used_nonces(nonce, username, ts) VALUES (?,?,?)", (nonce, username, int(time.time())))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    
MASTER_KEY = b'supersecretmasterkey1234567890123456'

def persist_tx(db, username, from_acc, to_acc, amount):
    ts = int(time.time())
    tx_body = f"{username}|{from_acc}|{to_acc}|{amount}|{ts}"
    tx_mac = hmac.new(MASTER_KEY, tx_body.encode(), hashlib.sha256).hexdigest()
    c = db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS txs(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT, from_acc TEXT, to_acc TEXT,
                  amount REAL, ts INT, tx_mac TEXT)""")
    c.execute("INSERT INTO txs(username, from_acc, to_acc, amount, ts, tx_mac) VALUES (?,?,?,?,?,?)",
              (username, from_acc, to_acc, float(amount), ts, tx_mac))
    db.commit()
    return c.lastrowid

"""def create_session(db, username, session_key_hex, ttl=3600):
    session_id = str(uuid.uuid4())
    expires = int(time.time()) + ttl

    protected_key = hmac.new(MASTER_KEY, session_key_hex.encode(), hashlib.sha256).hexdigest()
    c = db.cursor()
    c.execute("INSERT INTO sessions(session_id, username, session_key, expires) VALUES (?,?,?,?)",
             (session_id, username, protected_key, expires))
    db.commit()
    return session_id, expires"""


