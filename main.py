"""
BBL Python Developer Assessment
Appointment Booking API - FastAPI

Run:  uvicorn main:app --reload
Open: http://127.0.0.1:8000/  (login page)
Docs: http://127.0.0.1:8000/docs
"""
import hashlib
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Appointment Booking API")

# =========================================================
# In-memory data stores (per assignment instructions)
# =========================================================
USERS = {}     # username -> {"password_hash": str, "is_admin": bool}
BOOKINGS = []  # list of {"id": int, "username": str, "slot": str}
TOKENS = {}    # token -> username
_next_booking_id = 1


# =========================================================
# Request models
# =========================================================
class LoginRequest(BaseModel):
    username: str
    password: str


class BookingRequest(BaseModel):
    slot: str  # e.g. "10am-11am"


# =========================================================
# Password hashing + seed users
# =========================================================
def hash_password(password: str) -> str:
    """Never store raw passwords - store a one-way hash instead."""
    return hashlib.sha256(password.encode()).hexdigest()


def seed_users():
    USERS.clear()
    USERS["admin"] = {"password_hash": hash_password("admin123"), "is_admin": True}
    USERS["alice"] = {"password_hash": hash_password("alice123"), "is_admin": False}
    USERS["bob"] = {"password_hash": hash_password("bob123"), "is_admin": False}


seed_users()


# =========================================================
# Authentication: login -> issue token
# =========================================================
@app.post("/login")
def login(body: LoginRequest):
    user = USERS.get(body.username)
    if user is None or user["password_hash"] != hash_password(body.password):
        # Same error for "no such user" and "wrong password"
        # so attackers can't probe which usernames exist.
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_hex(16)
    TOKENS[token] = body.username
    return {"token": token, "username": body.username, "is_admin": user["is_admin"]}


# =========================================================
# Authentication dependency: "who is calling?"
# =========================================================
def get_current_user(authorization: str = Header(default="")) -> dict:
    """Reads 'Authorization: Bearer <token>' and returns the user.

    401 = we don't know who you are (missing/invalid token).
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ")
    username = TOKENS.get(token)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = USERS[username]
    return {"username": username, "is_admin": user["is_admin"]}


# =========================================================
# Booking endpoints (authorization happens here)
# =========================================================
@app.post("/bookings", status_code=201)
def create_booking(body: BookingRequest, user: dict = Depends(get_current_user)):
    """Any logged-in user can create a booking for themselves."""
    global _next_booking_id
    slot = body.slot.strip()
    if not slot:
        raise HTTPException(status_code=422, detail="Slot must not be empty")
    booking = {"id": _next_booking_id, "username": user["username"], "slot": slot}
    _next_booking_id += 1
    BOOKINGS.append(booking)
    return booking


@app.get("/bookings")
def list_bookings(user: dict = Depends(get_current_user)):
    """Admin sees ALL bookings; a normal user sees only their own."""
    if user["is_admin"]:
        return BOOKINGS
    return [b for b in BOOKINGS if b["username"] == user["username"]]


@app.delete("/bookings/{booking_id}", status_code=204)
def delete_booking(booking_id: int, user: dict = Depends(get_current_user)):
    """Users may delete only their own bookings (admin may delete any).

    403 = we know who you are, but you may not touch this resource.
    """
    for i, b in enumerate(BOOKINGS):
        if b["id"] == booking_id:
            if b["username"] != user["username"] and not user["is_admin"]:
                raise HTTPException(status_code=403, detail="Not your booking")
            BOOKINGS.pop(i)
            return
    raise HTTPException(status_code=404, detail="Booking not found")


# =========================================================
# Frontend: serve static pages
# =========================================================
@app.get("/", include_in_schema=False)
def index():
    return FileResponse("static/login.html")


app.mount("/static", StaticFiles(directory="static"), name="static")
