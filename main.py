# BBL assessment - appointment booking API
# run: uvicorn main:app --reload  ->  http://127.0.0.1:8000
import hashlib
import hmac
import logging
import secrets
import time

import jwt
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Appointment Booking API")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("booking")  # audit log: ใครทำอะไร เมื่อไหร่

PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SECONDS = 30 * 60       # token อยู่ได้ 30 นาที
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60         # ล็อก 15 นาทีถ้าใส่รหัสผิดเกิน
LOGIN_RATE_LIMIT = 10             # /login ได้กี่ครั้ง/นาที/IP กัน password spraying
LOGIN_RATE_WINDOW = 60

# key ไว้เซ็น JWT - สุ่มใหม่ทุกครั้งที่ start (ระบบจริงต้องอ่านจาก env var)
JWT_SECRET = secrets.token_hex(32)
JWT_ALGO = "HS256"

# เก็บใน memory ตามโจทย์ restart แล้วหายหมด
USERS = {}                 # username -> {salt, password_hash, is_admin}
BOOKINGS = []              # {id, username, slot}
FAILED_LOGINS = {}         # นับ login พลาดราย username
LOGIN_ATTEMPTS_BY_IP = {}  # ip -> [เวลาที่ยิง /login] กันสลับ username หนี lockout
_next_booking_id = 1


class LoginRequest(BaseModel):
    username: str
    password: str


class BookingRequest(BaseModel):
    slot: str  # เช่น "10am-11am"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"            # กันโดนฝังใน iframe (clickjacking)
    resp.headers["X-Content-Type-Options"] = "nosniff"  # กัน browser เดา content type เอง
    resp.headers["Referrer-Policy"] = "same-origin"
    # unsafe-inline เพราะหน้า html เราเขียน script/style inline อยู่ ถ้าแยกไฟล์แล้วค่อยเอาออก
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    )
    return resp


def hash_password(password: str, salt: bytes) -> bytes:
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
def login(request: Request, body: LoginRequest, response: Response):
    now = time.time()
    ip = request.client.host if request.client else "unknown"

    # กันยิงรัวราย IP ก่อนเลย (สลับ username ก็หนีไม่พ้น)
    stamps = [t for t in LOGIN_ATTEMPTS_BY_IP.get(ip, []) if t > now - LOGIN_RATE_WINDOW]
    if len(stamps) >= LOGIN_RATE_LIMIT:
        logger.warning("rate limit: ip=%s", ip)
        raise HTTPException(429, "Too many login attempts, slow down")
    stamps.append(now)
    LOGIN_ATTEMPTS_BY_IP[ip] = stamps

    # โดนล็อกอยู่ก็ไม่ต้องเช็ครหัสต่อ
    attempts = FAILED_LOGINS.get(body.username)
    if attempts and attempts["locked_until"] > now:
        logger.warning("login blocked (locked): user=%s ip=%s", body.username, ip)
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
            logger.warning("account locked: user=%s ip=%s", body.username, ip)
        else:
            logger.warning("login failed: user=%s ip=%s", body.username, ip)
        # ตอบ error เดียวกันทั้ง user ผิด/รหัสผิด
        raise HTTPException(401, "Invalid username or password")

    FAILED_LOGINS.pop(body.username, None)
    token = jwt.encode(
        {"sub": body.username, "is_admin": user["is_admin"], "exp": int(now + TOKEN_TTL_SECONDS)},
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )
    # เก็บ token ใน HttpOnly cookie - JS อ่านไม่ได้ ต่อให้โดน XSS ก็ขโมย token ไม่ได้
    response.set_cookie(
        "access_token", token,
        httponly=True, samesite="strict", max_age=TOKEN_TTL_SECONDS,
    )
    logger.info("login ok: user=%s ip=%s", body.username, ip)
    # คืน token ใน body ด้วย เผื่อเทสผ่าน curl/Swagger ที่ไม่ใช้ cookie
    return {"token": token, "username": body.username, "is_admin": user["is_admin"]}


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"detail": "Logged out"}


def get_current_user(
    authorization: str = Header(default=""),
    access_token: str | None = Cookie(default=None),
) -> dict:
    # รับได้ 2 ทาง: Authorization header (curl/Swagger) หรือ cookie (หน้าเว็บ)
    if authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")
    elif access_token:
        token = access_token
    else:
        raise HTTPException(401, "Missing bearer token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    return {"username": payload["sub"], "is_admin": payload["is_admin"]}


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
    logger.info("booking created: id=%s user=%s slot=%s", booking["id"], user["username"], slot)
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
                logger.warning("delete denied: id=%s by=%s owner=%s", booking_id, user["username"], b["username"])
                raise HTTPException(403, "Not your booking")
            BOOKINGS.pop(i)
            logger.info("booking deleted: id=%s by=%s", booking_id, user["username"])
            return
    raise HTTPException(404, "Booking not found")


# เสิร์ฟหน้าเว็บจาก static/ เลย จะได้ไม่ต้องยุ่งกับ CORS
@app.get("/", include_in_schema=False)
def index():
    return FileResponse("static/login.html")


app.mount("/static", StaticFiles(directory="static"), name="static")
