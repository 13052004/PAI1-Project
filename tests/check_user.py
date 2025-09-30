#!/usr/bin/env python3
import sqlite3, time, sys

DB = "pai1.db"
USER = "test_bruteforce_user"

try:
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username, failed, lock_until FROM users WHERE username = ?", (USER,))
    row = c.fetchone()
    if not row:
        print("Usuario no encontrado:", USER)
        sys.exit(0)
    username, failed, lock_until = row
    print("username:", username)
    print("failed:", failed)
    print("lock_until:", lock_until)
    # Show human interpretation of lock_until
    try:
        lu = int(lock_until or 0)
    except:
        lu = 0
    if lu and lu > int(time.time()):
        print("-> LA CUENTA DEBE ESTAR BLOQUEADA hasta timestamp:", lu, " (", time.ctime(lu), ")")
    else:
        print("-> La cuenta NO está bloqueada (lock_until <= now)")
finally:
    try:
        conn.close()
    except:
        pass
