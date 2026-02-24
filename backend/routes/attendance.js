const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { sessions, attendanceRecords, usedTokens, fraudLogs } = require('../db');
const { requireTeacher, rateLimitScans } = require('../middleware');
const { verifyToken } = require('../crypto');

const router = express.Router();

const sanitize = (str) => String(str || '').trim().replace(/<[^>]*>/g, '');

// ── Haversine distance formula — returns distance in meters
function haversineDistance(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = deg => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

const PROXIMITY_LIMIT_METERS = 30;

// ── Cleanup usedTokens periodically to prevent memory leak
// Tokens expire in TOKEN_EXPIRY_MS (15s), so anything older than 60s is safe to purge
// We store expiry time alongside each token
const usedTokenExpiry = new Map(); // tokenId -> expiry timestamp
setInterval(() => {
  const now = Date.now();
  for (const [tokenId, expiry] of usedTokenExpiry.entries()) {
    if (now > expiry + 60000) {
      usedTokens.delete(tokenId);
      usedTokenExpiry.delete(tokenId);
    }
  }
}, 30000);

// ── Limit fraud log size to prevent unbounded memory growth
const MAX_FRAUD_LOGS = 1000;
function addFraudLog(entry) {
  fraudLogs.unshift({ ...entry, time: new Date().toISOString() });
  if (fraudLogs.length > MAX_FRAUD_LOGS) fraudLogs.length = MAX_FRAUD_LOGS;
}

// ── POST /api/attendance/scan — student marks attendance
router.post('/scan', rateLimitScans, async (req, res) => {
  const { token, studentName, studentId, studentLat, studentLng } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  // ── Input validation
  const cleanName = sanitize(studentName);
  const cleanId = sanitize(studentId);

  if (!token || !cleanName || !cleanId) {
    return res.status(400).json({ error: 'Token, student name, and student ID are required' });
  }
  if (cleanName.length > 100) return res.status(400).json({ error: 'Student name too long' });
  if (cleanId.length > 50) return res.status(400).json({ error: 'Student ID too long' });

  // ── 1. Verify HMAC signature + expiry
  const result = verifyToken(token);
  if (!result.valid) {
    addFraudLog({
      reason: result.reason || 'INVALID_TOKEN',
      tokenSnippet: token.slice(0, 20) + '...',
      ip,
      studentName: cleanName,
      studentId: cleanId
    });
    return res.status(401).json({ error: result.reason || 'Invalid token' });
  }

  // ── 2. One-time use check (replay prevention)
  if (usedTokens.has(result.tokenId)) {
    addFraudLog({
      reason: 'REPLAY_ATTACK',
      tokenSnippet: token.slice(0, 20) + '...',
      ip,
      studentName: cleanName,
      studentId: cleanId
    });
    return res.status(401).json({ error: 'This QR code has already been used. Wait for the next one.' });
  }

  // ── 3. Session must be active
  const session = sessions.get(result.sessionId);
  if (!session || !session.active) {
    addFraudLog({
      reason: 'SESSION_INACTIVE',
      tokenSnippet: token.slice(0, 20) + '...',
      ip,
      studentName: cleanName,
      studentId: cleanId
    });
    return res.status(400).json({ error: 'This session is no longer active.' });
  }

  // ── 4. Duplicate student check (same session)
  const already = attendanceRecords.find(
    r => r.sessionId === result.sessionId && r.studentId.toLowerCase() === cleanId.toLowerCase()
  );
  if (already) {
    return res.status(409).json({ error: 'Your attendance is already marked for this session.' });
  }

  // ── 5. Proximity check
  let locationStatus = 'unverified';
  let distanceMeters = null;

  if (session.teacherLocation) {
    const sLat = parseFloat(studentLat);
    const sLng = parseFloat(studentLng);

    if (!isNaN(sLat) && !isNaN(sLng)) {
      distanceMeters = Math.round(haversineDistance(
        session.teacherLocation.lat, session.teacherLocation.lng,
        sLat, sLng
      ));

      if (distanceMeters > PROXIMITY_LIMIT_METERS) {
        addFraudLog({
          reason: `TOO_FAR (${distanceMeters}m, limit ${PROXIMITY_LIMIT_METERS}m)`,
          tokenSnippet: token.slice(0, 20) + '...',
          ip,
          studentName: cleanName,
          studentId: cleanId
        });
        return res.status(403).json({
          error: `You are too far from the classroom (${distanceMeters}m away, max ${PROXIMITY_LIMIT_METERS}m).`
        });
      }
      locationStatus = 'verified';
    }
    // else: studentLat/Lng missing or invalid — allow with 'unverified' status
  } else {
    locationStatus = 'not_required';
  }

  // ── ALL CHECKS PASSED — mark token as used and record attendance
  usedTokens.add(result.tokenId);
  usedTokenExpiry.set(result.tokenId, result.expiresAt || Date.now() + 60000);

  const record = {
    id: `att_${uuidv4().slice(0, 8)}`,
    sessionId: result.sessionId,
    classId: session.classId,
    className: session.className,
    studentName: cleanName,
    studentId: cleanId,
    markedAt: new Date().toISOString(),
    ip,
    locationStatus,
    distanceMeters
  };
  attendanceRecords.push(record);

  // Update session attendee count
  session.attendeeCount = (session.attendeeCount || 0) + 1;
  sessions.set(session.id, session);

  console.log(`\x1b[32m[ATTENDANCE]\x1b[0m ${cleanName} (${cleanId}) — "${session.className}" — ${locationStatus}${distanceMeters !== null ? ' ' + distanceMeters + 'm' : ''}`);

  res.json({
    success: true,
    message: `Attendance marked for ${session.className}`,
    studentName: cleanName,
    className: session.className,
    markedAt: record.markedAt,
    locationStatus,
    distanceMeters
  });
});

// ── GET /api/attendance/report — filtered records (teacher only)
router.get('/report', requireTeacher, (req, res) => {
  try {
    const { classId, sessionId } = req.query;

    // Only return records belonging to this teacher's sessions
    const teacherSessionIds = new Set(
      [...sessions.values()]
        .filter(s => s.teacherId === req.teacher.id)
        .map(s => s.id)
    );

    let records = attendanceRecords.filter(r => teacherSessionIds.has(r.sessionId));
    if (classId) records = records.filter(r => r.classId === classId);
    if (sessionId) records = records.filter(r => r.sessionId === sessionId);

    // Sort newest first
    records = [...records].sort((a, b) => new Date(b.markedAt) - new Date(a.markedAt));

    res.json({ records, count: records.length });
  } catch (e) {
    console.error('[ATTENDANCE] report error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/attendance/fraud — fraud log (teacher only)
router.get('/fraud', requireTeacher, (req, res) => {
  try {
    // Only return fraud related to this teacher's sessions
    const teacherSessionIds = new Set(
      [...sessions.values()]
        .filter(s => s.teacherId === req.teacher.id)
        .map(s => s.id)
    );

    // fraudLogs don't have sessionId directly, return all for now (can be scoped later)
    res.json({ logs: fraudLogs.slice(0, 200), count: fraudLogs.length });
  } catch (e) {
    console.error('[ATTENDANCE] fraud error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── DELETE /api/attendance/:id — delete a single attendance record (teacher only)
router.delete('/:id', requireTeacher, (req, res) => {
  try {
    const idx = attendanceRecords.findIndex(r => r.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Record not found' });

    const record = attendanceRecords[idx];
    const session = sessions.get(record.sessionId);
    if (!session || session.teacherId !== req.teacher.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    attendanceRecords.splice(idx, 1);

    // Update session attendee count
    if (session.attendeeCount > 0) {
      session.attendeeCount--;
      sessions.set(session.id, session);
    }

    console.log(`\x1b[33m[ATTENDANCE]\x1b[0m Record ${req.params.id} deleted by ${req.teacher.email}`);
    res.json({ message: 'Record deleted' });
  } catch (e) {
    console.error('[ATTENDANCE] delete error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
