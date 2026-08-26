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
| POST   | `/login`          | —      | Log in, returns `{token, is_admin}`      |
| POST   | `/bookings`       | Bearer | Book a slot, e.g. `{"slot": "10am-11am"}`|
| GET    | `/bookings`       | Bearer | Own bookings (admin: all bookings)       |
| DELETE | `/bookings/{id}`  | Bearer | Delete own booking (admin: any)          |

## Run Tests

```bash
pytest -v
```

13 tests cover login success/failure, missing/invalid tokens (401),
per-user visibility, admin visibility, and forbidden deletes (403).

## Notes / Trade-offs

- Data lives in Python dicts (per the assignment) — restart clears everything.
- Passwords are stored as SHA-256 hashes, never plaintext. Real systems should
  use a salted, slow hash (bcrypt/argon2) and JWT or server sessions with expiry.
- Frontend is served by the same FastAPI app to avoid CORS configuration.
