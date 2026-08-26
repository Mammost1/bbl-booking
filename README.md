# Appointment Booking App

Python Developer Assessment — a small appointment-booking web app with
login (authentication), role-based access (authorization), and an HTML/JS frontend.

**Stack:** Python 3 + FastAPI (backend), plain HTML/CSS/JS (frontend), in-memory data store.

## Setup & Run

```bash
# 1. create & activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 2. install dependencies
pip install -r requirements.txt

# 3. start the server
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000/** for the login page.
Interactive API docs: **http://127.0.0.1:8000/docs**

## Test Users (seeded in memory)

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | alice123  | user  |
| bob      | bob123    | user  |

## Rules

- Anyone must log in to get a bearer token (`POST /login`, wrong credentials → 401).
- All booking endpoints require `Authorization: Bearer <token>` (missing/invalid → 401).
- A user can create bookings and see/delete **only their own** (someone else's → 403).
- An **admin** can view all bookings and delete any booking.

## API

| Method | Path              | Auth   | Description                              |
|--------|-------------------|--------|------------------------------------------|
| POST   | `/login`          | —      | Log in, sets auth cookie + returns token |
| POST   | `/logout`         | —      | Clears the auth cookie                   |
| POST   | `/bookings`       | Bearer | Book a slot, e.g. `{"slot": "10am-11am"}`|
| GET    | `/bookings`       | Bearer | Own bookings (admin: all bookings)       |
| DELETE | `/bookings/{id}`  | Bearer | Delete own booking (admin: any)          |

## Run Tests

```bash
pytest -v
```

24 tests cover login success/failure, missing/invalid/expired/tampered tokens (401),
account lockout (429), double-booking (409), per-user visibility,
admin visibility, and forbidden deletes (403).

## Security

- Passwords hashed with **PBKDF2-HMAC-SHA256 + per-user random salt**
  (200,000 iterations) — never stored in plaintext.
- Constant-time hash comparison (`hmac.compare_digest`) against timing attacks.
- **JWT (HS256)** access tokens signed with a server secret key, **30-minute expiry** —
  tamper-proof and stateless (no server-side session table).
- Token delivered in an **HttpOnly, SameSite=Strict cookie** — JavaScript cannot
  read it (XSS-resistant); the API also accepts a Bearer header for curl/Swagger.
- **IP rate limiting** on /login (10/min) against password spraying, on top of
  the per-account lockout.
- **Security headers** on every response (X-Frame-Options, nosniff, CSP).
- **Audit log** of logins, failures, lockouts, and booking changes.
- **Account lockout**: 5 failed logins lock the account for 15 minutes (429).
- Identical error for wrong username / wrong password (no user enumeration).
- Double-booking a taken slot is rejected with **409 Conflict**.

## Notes / Trade-offs

- Data lives in Python dicts (per the assignment) — restart clears everything.
- JWT signing key is generated at startup (in-memory app, so old tokens dying on
  restart is fine). Trade-off: a JWT can't be revoked before it expires —
  a real system would add a refresh-token flow or a revocation list.
- Frontend is served by the same FastAPI app to avoid CORS configuration.
