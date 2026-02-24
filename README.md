   # 🛡 QRShield — Full-Stack Secure Attendance System

## Quick Start

### 1. Install dependencies
```bash
cd backend
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env and set strong secrets!
```

### 3. Run
```bash
npm run dev    # development (auto-reload)
npm start      # production
```

### 4. Open
```
http://localhost:3000
```

---

## Default Credentials
| Role    | Email               | Password    |
|---------|---------------------|-------------|
| Teacher | teacher@demo.com    | teacher123  |

To add more teachers, call:
```
POST /api/auth/register
Body: { "name": "...", "email": "...", "password": "...", "adminKey": "admin123" }
```
Set `ADMIN_KEY` in .env to change the admin key.

---

## How It Works (Security Flow)

```
Teacher starts session
  → Server creates sessionId

Every 7 seconds:
  → Frontend calls GET /api/sessions/:id/qr
  → Server generates token = base64({ sessionId, timestamp, nonce, sig })
    where sig = HMAC-SHA256(SECRET_KEY, "sessionId|timestamp|nonce")
  → SECRET KEY NEVER LEAVES THE SERVER
  → Server generates QR image with URL: http://yoursite.com/scan?t=TOKEN
  → QR shown on projector

Student scans QR with phone:
  → Opens http://yoursite.com/scan?t=TOKEN
  → Enters name + student ID
  → Frontend POSTs { token, studentName, studentId } to /api/attendance/scan

Server verifies (4 checks):
  1. Token parseable + all fields present
  2. HMAC signature valid (timing-safe comparison)
  3. Token age < 7 seconds
  4. Token not in usedTokens set

If all pass:
  → Mark tokenId as used
  → Save attendance record
  → Return 200 OK

If any fail:
  → Log to fraudLog with reason
  → Return 401
```

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/login | None | Teacher login |
| POST | /api/auth/register | Admin key | Create teacher |
| GET | /api/classes | Teacher JWT | List classes |
| POST | /api/classes | Teacher JWT | Create class |
| DELETE | /api/classes/:id | Teacher JWT | Delete class |
| POST | /api/sessions/start | Teacher JWT | Start session |
| POST | /api/sessions/:id/stop | Teacher JWT | Stop session |
| GET | /api/sessions/:id/qr | Teacher JWT | Get fresh QR |
| GET | /api/sessions/:id/attendees | Teacher JWT | Live attendees |
| POST | /api/attendance/scan | None + Rate limit | Mark attendance |
| GET | /api/attendance/report | Teacher JWT | Full report |
| GET | /api/attendance/fraud | Teacher JWT | Fraud log |

---

## Attack Results

| Attack | Result |
|--------|--------|
| Forward QR link to friend | ❌ Token expired in 7s |
| Screenshot QR | ❌ Expired before they can open it |
| Google Lens the QR | ❌ Expired |
| Reuse a token | ❌ TOKEN_ALREADY_USED |
| Modify token manually | ❌ INVALID_SIGNATURE |
| Rapid spam scanning | ❌ RATE_LIMITED (3 per 5s) |
| Steal token from URL | ❌ Still expired / already used |
| Sniff secret key from browser | ❌ Key never sent to client |

---

## Production Checklist

- [ ] Set strong `HMAC_SECRET` (64+ random chars) in .env
- [ ] Set strong `JWT_SECRET` in .env
- [ ] Set `ADMIN_KEY` to something secret
- [ ] Switch in-memory DB to MongoDB/PostgreSQL
- [ ] Add Redis for usedTokens (survives restarts)
- [ ] Set `APP_URL` to your real domain
- [ ] Enable HTTPS (tokens over HTTP = bad)
- [ ] Set `CORS_ORIGIN` to your frontend domain
- [ ] Add PM2 or Docker for process management

---

## Folder Structure

```
qrshield/
├── backend/
│   ├── server.js          ← Express app entry point
│   ├── db.js              ← In-memory DB (swap for real DB)
│   ├── crypto.js          ← HMAC token engine (THE CORE)
│   ├── middleware.js       ← Auth, rate limiting, logging
│   ├── routes/
│   │   ├── auth.js        ← Teacher login/register
│   │   ├── classes.js     ← Class CRUD
│   │   ├── sessions.js    ← Session + QR generation
│   │   └── attendance.js  ← Scan verification + reports
│   ├── .env.example
│   └── package.json
└── frontend/
    └── index.html         ← Single-page app (teacher dash + student scan)
```
