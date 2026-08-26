# BBL assessment - appointment booking API
# run: uvicorn main:app --reload  ->  http://127.0.0.1:8000
import hashlib
import hmac
import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Appointment Booking API")

PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SECONDS = 30 * 60       # token อยู่ได้ 30 นาที
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60         # ล็อก 15 นาทีถ้าใส่รหัสผิดเกิน

# เก็บใน memory ตามโจทย์ restart แล้วหายหมด
USERS = {}          # username -> {salt, password_hash, is_admin}
BOOKINGS = []       # {id, username, slot}
TOKENS = {}         # token -> {username, expires_at}
FAILED_LOGINS = {}  # นับ login พลาด กันโดน brute force
_next_booking_id = 1


class LoginRequest(BaseModel):
    username: str
    password: str


class BookingRequest(BaseModel):
    slot: str  # เช่น "10am-11am"


def hash_password(password: str, salt: bytes) -> bytes:
    # pbkdf2 ช้ากว่า sha256 เปล่าๆ เยอะ = เดารหัสยากขึ้น, salt กัน rainbow table
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def make_user(password: str, is_admin: bool) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": salt, "password_hash": hash_password(password, salt), "is_admin": is_admin}


def seed_users():
    # user ทดสอบ 3 คน
    USERS.clear()
    USERS["admin"] = make_user("admin123", is_admin=True)
    USERS["alice"] = make_user("alice123", is_admin=False)
    USERS["bob"] = make_user("bob123", is_admin=False)


seed_users()


@app.post("/login")
def login(body: LoginRequest):
    now = time.time()

    # โดนล็อกอยู่ก็ไม่ต้องเช็ครหัสต่อ
    attempts = FAILED_LOGINS.get(body.username)
    if attempts and attempts["locked_until"] > now:
        raise HTTPException(429, "Too many failed attempts. Account locked temporarily.")

    user = USERS.get(body.username)
    # user ไม่มีจริงก็ hash ทิ้งรอบนึงอยู่ดี ให้เวลาตอบพอๆ กัน จะได้เดา username ไม่ได้
    salt = user["salt"] if user else b"x" * 16
    candidate = hash_password(body.password, salt)

    if user is None or not hmac.compare_digest(candidate, user["password_hash"]):
        rec = FAILED_LOGINS.setdefault(body.username, {"count": 0, "locked_until": 0.0})
        rec["count"] += 1
        if rec["count"] >= MAX_FAILED_LOGINS:
            rec["locked_until"] = now + LOCKOUT_SECONDS
            rec["count"] = 0
        # ตอบ error เดียวกันทั้ง user ผิด/รหัสผิด
        raise HTTPException(401, "Invalid username or password")

    FAILED_LOGINS.pop(body.username, None)
    token = secrets.token_hex(32)
    TOKENS[token] = {"username": body.username, "expires_at": now + TOKEN_TTL_SECONDS}
    return {"token": token, "username": body.username, "is_admin": user["is_admin"]}


def get_current_user(authorization: str = Header(default="")) -> dict:
    # แกะ token จาก header: Authorization: Bearer xxx
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ")
    session = TOKENS.get(token)
    if session is None:
        raise HTTPException(401, "Invalid token")
    if session["expires_at"] < time.time():
        TOKENS.pop(token, None)  # หมดอายุแล้ว เคลียร์ทิ้ง
        raise HTTPException(401, "Token expired, please log in again")
    user = USERS[session["username"]]
    return {"username": session["username"], "is_admin": user["is_admin"]}


@app.post("/bookings", status_code=201)
def create_booking(body: BookingRequest, user: dict = Depends(get_current_user)):
    global _next_booking_id
    slot = body.slot.strip()
    if not slot:
        raise HTTPException(422, "Slot must not be empty")
    # slot ซ้ำไม่ให้จอง (ไม่สน case)
    if any(b["slot"].lower() == slot.lower() for b in BOOKINGS):
        raise HTTPException(409, f"Slot '{slot}' is already booked")
    booking = {"id": _next_booking_id, "username": user["username"], "slot": slot}
    _next_booking_id += 1
    BOOKINGS.append(booking)
    return booking


@app.get("/bookings")
def list_bookings(user: dict = Depends(get_current_user)):
    # admin เห็นหมด user ธรรมดาเห็นแค่ของตัวเอง
    if user["is_admin"]:
        return BOOKINGS
    return [b for b in BOOKINGS if b["username"] == user["username"]]


@app.delete("/bookings/{booking_id}", status_code=204)
def delete_booking(booking_id: int, user: dict = Depends(get_current_user)):
    for i, b in enumerate(BOOKINGS):
        if b["id"] == booking_id:
            # ลบของคนอื่นไม่ได้ ยกเว้น admin -> 403 ไม่ใช่ 401 เพราะรู้แล้วว่าเป็นใคร
            if b["username"] != user["username"] and not user["is_admin"]:
                raise HTTPException(403, "Not your booking")
            BOOKINGS.pop(i)
            return
    raise HTTPException(404, "Booking not found")


# เสิร์ฟหน้าเว็บจาก static/ เลย จะได้ไม่ต้องยุ่งกับ CORS
@app.get("/", include_in_schema=False)
def index():
    return FileResponse("static/login.html")


app.mount("/static", StaticFiles(directory="static"), name="static")
