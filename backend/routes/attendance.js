const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { sessions, attendanceRecords, usedTokens, fraudLogs } = require('../db');
const { requireTeacher, rateLimitScans } = require('../middleware');
const { verifyToken } = require('../crypto');
const router = express.Router();

// POST /api/attendance/scan — student marks attendance
// No auth required — students don't have accounts
// Security is entirely in the token
router.post('/scan', rateLimitScans, async (req, res) => {
  const { token, studentName, studentId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!token) return res.status(400).json({ error: 'Token required' });
  if (!studentName || !studentName.trim()) return res.status(400).json({ error: 'Student name required' });
  if (!studentId || !studentId.trim()) return res.status(400).json({ error: 'Student ID required' });

  // ── SECURITY CHECK 1, 2, 3: signature + expiry (via verifyToken)
  const result = verifyToken(token);
  if (!result.valid) {
    fraudLogs.push({
      time: new Date().toISOString(),
      reason: result.reason,
      tokenSnippet: token.substring(0, 40) + '...',
      ip,
      studentName,
      studentId
    });
    console.log(`\x1b[31m[FRAUD]\x1b[0m ${result.reason} from IP ${ip} — ${studentName}`);
    return res.status(401).json({ error: result.reason, message: 'Token rejected' });
  }

  // ── SECURITY CHECK 4: one-time use
  if (usedTokens.has(result.tokenId)) {
    fraudLogs.push({
      time: new Date().toISOString(),
      reason: 'TOKEN_REPLAY_ATTACK',
      tokenSnippet: token.substring(0, 40) + '...',
      ip,
      studentName,
      studentId
    });
    console.log(`\x1b[31m[FRAUD]\x1b[0m REPLAY ATTACK from IP ${ip} — ${studentName}`);
    return res.status(401).json({ error: 'TOKEN_ALREADY_USED', message: 'This token has already been used' });
  }

  // ── SECURITY CHECK 5: session active
  const session = sessions.get(result.sessionId);
  if (!session || !session.active) {
    return res.status(400).json({ error: 'SESSION_INACTIVE', message: 'This session is no longer active' });
  }

  // ── ABUSE CHECK: duplicate student in same session
  const duplicate = attendanceRecords.find(
    a => a.sessionId === result.sessionId && a.studentId === studentId.trim()
  );
  if (duplicate) {
    fraudLogs.push({
      time: new Date().toISOString(),
      reason: 'DUPLICATE_STUDENT',
      tokenSnippet: token.substring(0, 40) + '...',
      ip,
      studentName,
      studentId
    });
    return res.status(409).json({ error: 'ALREADY_MARKED', message: 'You already marked attendance for this session' });
  }

  // ── ALL CHECKS PASSED — mark token as used and record attendance
  usedTokens.add(result.tokenId);

  const record = {
    id: `att_${uuidv4().slice(0, 8)}`,
    sessionId: result.sessionId,
    classId: session.classId,
    className: session.className,
    studentName: studentName.trim(),
    studentId: studentId.trim(),
    markedAt: new Date().toISOString(),
    ip
  };
  attendanceRecords.push(record);

  console.log(`\x1b[32m[ATTENDANCE]\x1b[0m ${studentName} (${studentId}) marked present in "${session.className}"`);
  res.json({ success: true, message: `Attendance marked for ${session.className}`, record });
});

// GET /api/attendance/report — full report (teacher only)
router.get('/report', requireTeacher, (req, res) => {
  const { classId, sessionId } = req.query;
  let records = attendanceRecords;
  if (classId) records = records.filter(r => r.classId === classId);
  if (sessionId) records = records.filter(r => r.sessionId === sessionId);
  res.json({ records, count: records.length });
});

// GET /api/attendance/fraud — fraud log (teacher only)
router.get('/fraud', requireTeacher, (req, res) => {
  res.json({ logs: [...fraudLogs].reverse(), count: fraudLogs.length });
});

module.exports = router;
