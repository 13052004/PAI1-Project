import time
from client import register, login

def test_bruteforce_lockout():
    username = "test_bruteforce_user"
    password = "correcthorsebatterystaple"
    _ = register(username, password)

    for i in range(5):
        resp = login(username, "wrongpassword")
        assert resp.get("status") == "error"
        assert resp.get("reason") in ("invalid_credentials", "locked")

    resp_ok = login(username, password)
    assert resp_ok.get("status") == "error"
    assert resp_ok.get("reason") in ("locked", "invalid_credentials")


if __name__ == "__main__":
    test_bruteforce_lockout()

