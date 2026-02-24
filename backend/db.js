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

const fraudLogs = [];
// Schema: { time, reason, tokenSnippet, ip, sessionId }

module.exports = { teachers, classes, sessions, attendanceRecords, usedTokens, fraudLogs };
