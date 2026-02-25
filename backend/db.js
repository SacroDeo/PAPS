// ─────────────────────────────────────────────────────────────────
// db.js — In-memory database (drop-in replace with MongoDB/PostgreSQL)
// ─────────────────────────────────────────────────────────────────
// All data lives here during runtime. On restart data resets.
// To persist: swap each Map/Array with real DB calls (see comments).

const teachers = new Map();
// Schema: email → { id, name, email, passwordHash }

const classes = new Map();
// Schema: classId → { id, name, teacherId, createdAt, sessionCount }

const sessions = new Map();
// Schema: sessionId → { id, classId, className, teacherId, active, startedAt, endedAt }

const attendanceRecords = [];
// Schema: { id, sessionId, classId, className, studentName, studentId, markedAt, tokenId }

const usedTokens = new Set();
// Schema: Set of tokenId strings (sessionId|timestamp|nonce)
// In production: use Redis with TTL or a DB table with expiry cleanup

const claimedTokens = new Map();
// Schema: tokenId → { deviceId, ip, claimedAt }
// Prevents sharing the URL — if device B opens a link already claimed by device A, rejected.

const ipSessions = new Map();
// Schema: `${ip}:${sessionId}` → true
// Secondary guard: same IP cannot mark attendance twice for the same session.
// Catches students who clear localStorage or use incognito on the same network connection.

const ipDeviceClaims = new Map();
// Schema: ip → Set<deviceId>
// Detects IP claiming tokens under many different deviceIds (emulator / spoof farm detection).

const deviceSessions = new Map();
// Schema: `${deviceId}:${sessionId}` → true
// Prevents the same physical device from submitting attendance twice for the same session.

const fraudLogs = [];
// Schema: { time, reason, tokenSnippet, ip, sessionId }

module.exports = { teachers, classes, sessions, attendanceRecords, usedTokens, claimedTokens, deviceSessions, ipSessions, ipDeviceClaims, fraudLogs };
