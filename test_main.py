# test ทั้งหมด รัน: pytest -v
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    # ล้างข้อมูลก่อนทุก test จะได้ไม่ปนกัน
    main.seed_users()
    main.BOOKINGS.clear()
    main.FAILED_LOGINS.clear()
    main.LOGIN_ATTEMPTS_BY_IP.clear()
    main._next_booking_id = 1
    client.cookies.clear()  # cookie ค้างจาก test ก่อนหน้าทำให้ 401 กลายเป็น 200 ได้
    yield


def login(username, password):
    return client.post("/login", json={"username": username, "password": password})


def token_of(username, password):
    return login(username, password).json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- Authentication ----------

def test_login_success():
    res = login("alice", "alice123")
    assert res.status_code == 200
    body = res.json()
    assert body["is_admin"] is False
    assert body["token"]


def test_login_wrong_password():
    assert login("alice", "wrong").status_code == 401


def test_login_unknown_user():
    assert login("nobody", "x").status_code == 401


def test_bookings_require_token():
    assert client.get("/bookings").status_code == 401
    assert client.post("/bookings", json={"slot": "10am-11am"}).status_code == 401


def test_invalid_token_rejected():
    assert client.get("/bookings", headers=auth("fake-token")).status_code == 401


def test_expired_token_rejected():
    # สร้าง token ที่หมดอายุไปแล้วด้วย key จริง
    t = jwt.encode({"sub": "alice", "is_admin": False, "exp": int(time.time()) - 1},
                   main.JWT_SECRET, algorithm=main.JWT_ALGO)
    assert client.get("/bookings", headers=auth(t)).status_code == 401


def test_tampered_token_rejected():
    # token ที่เซ็นด้วย key ปลอม ต้องโดนปัด
    t = jwt.encode({"sub": "admin", "is_admin": True, "exp": int(time.time()) + 999},
                   "wrong-secret", algorithm=main.JWT_ALGO)
    assert client.get("/bookings", headers=auth(t)).status_code == 401


def test_lockout_after_failed_logins():
    for _ in range(main.MAX_FAILED_LOGINS):
        assert login("alice", "wrong").status_code == 401
    # โดนล็อกแล้ว ใส่รหัสถูกก็ไม่ให้เข้า
    assert login("alice", "alice123").status_code == 429


def test_successful_login_resets_failed_count():
    for _ in range(main.MAX_FAILED_LOGINS - 1):
        login("alice", "wrong")
    assert login("alice", "alice123").status_code == 200
    # login ผ่านแล้ว counter ต้อง reset
    assert login("alice", "wrong").status_code == 401
    assert login("alice", "alice123").status_code == 200


def test_passwords_not_stored_in_plaintext():
    stored = main.USERS["alice"]
    assert b"alice123" not in stored["password_hash"]
    assert stored["password_hash"] != "alice123"


# ---------- Booking ----------

def test_create_booking():
    t = token_of("alice", "alice123")
    res = client.post("/bookings", json={"slot": "10am-11am"}, headers=auth(t))
    assert res.status_code == 201
    assert res.json() == {"id": 1, "username": "alice", "slot": "10am-11am"}


def test_empty_slot_rejected():
    t = token_of("alice", "alice123")
    res = client.post("/bookings", json={"slot": "  "}, headers=auth(t))
    assert res.status_code == 422


def test_double_booking_rejected():
    t_alice = token_of("alice", "alice123")
    t_bob = token_of("bob", "bob123")
    assert client.post("/bookings", json={"slot": "10am-11am"}, headers=auth(t_alice)).status_code == 201
    # slot เดิมโดนจองแล้ว ต้อง 409
    assert client.post("/bookings", json={"slot": "10AM-11AM"}, headers=auth(t_bob)).status_code == 409


# ---------- Authorization ----------

def test_user_sees_only_own_bookings():
    t_alice = token_of("alice", "alice123")
    t_bob = token_of("bob", "bob123")
    client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice))
    client.post("/bookings", json={"slot": "1pm-2pm"}, headers=auth(t_bob))

    seen = client.get("/bookings", headers=auth(t_alice)).json()
    assert [b["username"] for b in seen] == ["alice"]


def test_admin_sees_all_bookings():
    t_alice = token_of("alice", "alice123")
    t_admin = token_of("admin", "admin123")
    client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice))

    seen = client.get("/bookings", headers=auth(t_admin)).json()
    assert len(seen) == 1
    assert seen[0]["username"] == "alice"


def test_user_cannot_delete_others_booking():
    t_alice = token_of("alice", "alice123")
    t_bob = token_of("bob", "bob123")
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t_bob)).status_code == 403


def test_user_deletes_own_booking():
    t = token_of("alice", "alice123")
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t)).status_code == 204
    assert client.get("/bookings", headers=auth(t)).json() == []


def test_admin_can_delete_any_booking():
    t_alice = token_of("alice", "alice123")
    t_admin = token_of("admin", "admin123")
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t_admin)).status_code == 204


def test_delete_missing_booking_404():
    t = token_of("alice", "alice123")
    assert client.delete("/bookings/999", headers=auth(t)).status_code == 404


# ---------- Hardening ----------

def test_security_headers_present():
    res = client.get("/")
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in res.headers


def test_login_sets_httponly_cookie():
    res = login("alice", "alice123")
    set_cookie = res.headers["set-cookie"].lower()
    assert "access_token=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie


def test_cookie_alone_authenticates():
    login("alice", "alice123")  # TestClient เก็บ cookie ให้เอง
    # ไม่ส่ง Authorization header เลย ใช้ cookie ล้วนๆ
    assert client.get("/bookings").status_code == 200


def test_logout_clears_cookie():
    login("alice", "alice123")
    client.post("/logout")
    assert client.get("/bookings").status_code == 401


def test_ip_rate_limit():
    # ยิง /login รัวๆ สลับ username ไปเรื่อยๆ (หนี lockout ราย user)
    for i in range(main.LOGIN_RATE_LIMIT):
        login(f"spray{i}", "x")
    # ครั้งถัดไปโดน 429 เพราะ IP เดิมยิงเกินโควต้า
    assert login("spray-final", "x").status_code == 429
