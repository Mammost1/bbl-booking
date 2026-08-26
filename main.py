"""
BBL Python Developer Assessment
Appointment Booking API - FastAPI

Run:  uvicorn main:app --reload
Open: http://127.0.0.1:8000/  (login page)
Docs: http://127.0.0.1:8000/docs

Security measures (standard library only):
- Passwords hashed with PBKDF2-HMAC-SHA256 + per-user random salt
- Constant-time hash comparison (hmac.compare_digest)
- Opaque session tokens with 30-minute expiry
- Account lockout after 5 failed logins (15 minutes)
- Identical error for wrong user / wrong password (no user enumeration)
"""
import hashlib
import hmac
import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Appointment Booking API")

# =========================================================
# Security parameters
# =========================================================
PBKDF2_ITERATIONS = 200_000       # deliberately slow to resist brute force
TOKEN_TTL_SECONDS = 30 * 60       # session token lifetime
MAX_FAILED_LOGINS = 5             # lockout threshold
LOCKOUT_SECONDS = 15 * 60         # lockout duration

# =========================================================
# In-memory data stores (per assignment instructions)
# =========================================================
USERS = {}          # username -> {"salt": bytes, "password_hash": bytes, "is_admin": bool}
BOOKINGS = []       # list of {"id": int, "username": str, "slot": str}
TOKENS = {}         # token -> {"username": str, "expires_at": float}
FAILED_LOGINS = {}  # username -> {"count": int, "locked_until": float}
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
def hash_password(password: str, salt: bytes) -> bytes:
    """PBKDF2: a deliberately slow, salted, one-way hash.

    - salt (random per user) defeats precomputed rainbow tables
    - high iteration count makes mass guessing expensive
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def make_user(password: str, is_admin: bool) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": salt, "password_hash": hash_password(password, salt), "is_admin": is_admin}


def seed_users():
    USERS.clear()
    USERS["admin"] = make_user("admin123", is_admin=True)
    USERS["alice"] = make_user("alice123", is_admin=False)
    USERS["bob"] = make_user("bob123", is_admin=False)


seed_users()


# =========================================================
# Authentication: login -> issue expiring token
# =========================================================
@app.post("/login")
def login(body: LoginRequest):
    now = time.time()

    # Account lockout: too many failed attempts -> refuse even correct passwords
    attempts = FAILED_LOGINS.get(body.username)
    if attempts and attempts["locked_until"] > now:
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Account locked temporarily.",
        )

    user = USERS.get(body.username)
    # Compute a hash even for unknown users so response time doesn't
    # reveal whether the username exists (timing side channel).
    salt = user["salt"] if user else b"x" * 16
    candidate = hash_password(body.password, salt)

    if user is None or not hmac.compare_digest(candidate, user["password_hash"]):
        rec = FAILED_LOGINS.setdefault(body.username, {"count": 0, "locked_until": 0.0})
        rec["count"] += 1
        if rec["count"] >= MAX_FAILED_LOGINS:
            rec["locked_until"] = now + LOCKOUT_SECONDS
            rec["count"] = 0
        # Same error for "no such user" and "wrong password"
        # so attackers can't probe which usernames exist.
        raise HTTPException(status_code=401, detail="Invalid username or password")

    FAILED_LOGINS.pop(body.username, None)
    token = secrets.token_hex(32)
    TOKENS[token] = {"username": body.username, "expires_at": now + TOKEN_TTL_SECONDS}
    return {"token": token, "username": body.username, "is_admin": user["is_admin"]}


# =========================================================
# Authentication dependency: "who is calling?"
# =========================================================
def get_current_user(authorization: str = Header(default="")) -> dict:
    """Reads 'Authorization: Bearer <token>' and returns the user.

    401 = we don't know who you are (missing/invalid/expired token).
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ")
    session = TOKENS.get(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session["expires_at"] < time.time():
        TOKENS.pop(token, None)
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    user = USERS[session["username"]]
    return {"username": session["username"], "is_admin": user["is_admin"]}


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
    # Double-booking guard: the same slot cannot be taken twice
    if any(b["slot"].lower() == slot.lower() for b in BOOKINGS):
        raise HTTPException(status_code=409, detail=f"Slot '{slot}' is already booked")
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
