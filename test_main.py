"""Tests for the Appointment Booking API. Run: pytest -v"""
import pytest
from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    """Fresh data store for every test."""
    main.seed_users()
    main.BOOKINGS.clear()
    main.TOKENS.clear()
    main._next_booking_id = 1
    yield


def login(username, password):
    return client.post("/login", json={"username": username, "password": password})


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


# ---------- Booking ----------

def test_create_booking():
    token = login("alice", "alice123").json()["token"]
    res = client.post("/bookings", json={"slot": "10am-11am"}, headers=auth(token))
    assert res.status_code == 201
    assert res.json() == {"id": 1, "username": "alice", "slot": "10am-11am"}


def test_empty_slot_rejected():
    token = login("alice", "alice123").json()["token"]
    res = client.post("/bookings", json={"slot": "  "}, headers=auth(token))
    assert res.status_code == 422


# ---------- Authorization ----------

def test_user_sees_only_own_bookings():
    t_alice = login("alice", "alice123").json()["token"]
    t_bob = login("bob", "bob123").json()["token"]
    client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice))
    client.post("/bookings", json={"slot": "1pm-2pm"}, headers=auth(t_bob))

    seen = client.get("/bookings", headers=auth(t_alice)).json()
    assert [b["username"] for b in seen] == ["alice"]


def test_admin_sees_all_bookings():
    t_alice = login("alice", "alice123").json()["token"]
    t_admin = login("admin", "admin123").json()["token"]
    client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice))

    seen = client.get("/bookings", headers=auth(t_admin)).json()
    assert len(seen) == 1
    assert seen[0]["username"] == "alice"


def test_user_cannot_delete_others_booking():
    t_alice = login("alice", "alice123").json()["token"]
    t_bob = login("bob", "bob123").json()["token"]
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t_bob)).status_code == 403


def test_user_deletes_own_booking():
    t = login("alice", "alice123").json()["token"]
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t)).status_code == 204
    assert client.get("/bookings", headers=auth(t)).json() == []


def test_admin_can_delete_any_booking():
    t_alice = login("alice", "alice123").json()["token"]
    t_admin = login("admin", "admin123").json()["token"]
    bid = client.post("/bookings", json={"slot": "9am-10am"}, headers=auth(t_alice)).json()["id"]

    assert client.delete(f"/bookings/{bid}", headers=auth(t_admin)).status_code == 204


def test_delete_missing_booking_404():
    t = login("alice", "alice123").json()["token"]
    assert client.delete("/bookings/999", headers=auth(t)).status_code == 404
