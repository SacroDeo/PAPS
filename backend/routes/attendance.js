const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { sessions, attendanceRecords, usedTokens, claimedTokens, deviceSessions, ipSessions, ipDeviceClaims, fraudLogs } = require('../db');
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

// ── Cleanup usedTokens + claimedTokens periodically to prevent memory leak
// Tokens expire in TOKEN_EXPIRY_MS (30s), so anything older than 120s is safe to purge
const usedTokenExpiry = new Map(); // tokenId -> expiry timestamp
setInterval(() => {
  const now = Date.now();
  for (const [tokenId, expiry] of usedTokenExpiry.entries()) {
    if (now > expiry + 120000) {
      usedTokens.delete(tokenId);
      claimedTokens.delete(tokenId);
      usedTokenExpiry.delete(tokenId);
    }
  }
}, 60000);

// ── Cleanup ipDeviceClaims every 10 minutes (reset spoof-farm counters per IP)
// This allows the same IP to legitimately use the app again after the window passes.
setInterval(() => {
  ipDeviceClaims.clear();
}, 10 * 60 * 1000);

// ── Limit fraud log size to prevent unbounded memory growth
const MAX_FRAUD_LOGS = 1000;
function addFraudLog(entry) {
  fraudLogs.unshift({ ...entry, time: new Date().toISOString() });
  if (fraudLogs.length > MAX_FRAUD_LOGS) fraudLogs.length = MAX_FRAUD_LOGS;
}

// ── deviceId validation — must be a non-empty string, reasonable length, no funny business
function isValidDeviceId(id) {
  return typeof id === 'string' && id.length >= 8 && id.length <= 128 && /^[a-zA-Z0-9_\-]+$/.test(id);
}

// ── POST /api/attendance/claim — device claims a token the moment they open the QR link
// This binds the token to the first device that opens it, making shared links invalid.
router.post('/claim', rateLimitScans, (req, res) => {
  const { token, deviceId } = req.body;
  if (!token || !deviceId) return res.status(400).json({ error: 'token and deviceId are required' });

  // ── Validate deviceId format — reject spoofed/garbage values
  if (!isValidDeviceId(deviceId)) {
    return res.status(400).json({ error: 'Invalid device identifier.' });
  }

  const ip = req.ip || req.connection.remoteAddress;

  const result = verifyToken(token);
  if (!result.valid) {
    return res.status(401).json({ error: result.reason || 'Invalid or expired token' });
  }

  // ── Spoof farm detection: one IP should not claim tokens under many different deviceIds
  if (!ipDeviceClaims.has(ip)) ipDeviceClaims.set(ip, new Set());
  const devicesForIp = ipDeviceClaims.get(ip);
  devicesForIp.add(deviceId);
  if (devicesForIp.size > 5) {
    addFraudLog({
      reason: 'SPOOF_FARM_DETECTED',
      tokenSnippet: token.slice(0, 20) + '...',
      ip,
      studentName: '(unknown)',
      studentId: '(unknown)'
    });
    console.warn(`\x1b[31m[FRAUD]\x1b[0m Spoof farm detected — IP ${ip} has claimed tokens under ${devicesForIp.size} different deviceIds`);
    return res.status(403).json({ error: 'Suspicious activity detected. Please scan the QR code directly.' });
  }

  // ── If already claimed by a different device → shared link, reject
  if (claimedTokens.has(result.tokenId)) {
    const claim = claimedTokens.get(result.tokenId);
    if (claim.deviceId !== deviceId) {
      addFraudLog({
        reason: 'SHARED_LINK',
        tokenSnippet: token.slice(0, 20) + '...',
        ip,
        studentName: '(unknown)',
        studentId: '(unknown)'
      });
      return res.status(403).json({ error: 'This QR link has already been opened on another device. Please scan the QR code directly.' });
    }
    // Same device re-claiming — idempotent, fine
    return res.json({ claimed: true });
  }

  // ── First claim — bind token to this device + IP
  claimedTokens.set(result.tokenId, { deviceId, ip, claimedAt: Date.now() });
  usedTokenExpiry.set(result.tokenId, result.expiresAt || Date.now() + 120000);
  res.json({ claimed: true });
});

// ── POST /api/attendance/scan — student marks attendance
router.post('/scan', rateLimitScans, async (req, res) => {
  const { token, studentName, studentId, studentLat, studentLng, deviceId } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  // ── Input validation
  const cleanName = sanitize(studentName);
  const cleanId = sanitize(studentId);

  if (!token || !cleanName || !cleanId) {
    return res.status(400).json({ error: 'Token, student name, and student ID are required' });
  }
  if (cleanName.length > 100) return res.status(400).json({ error: 'Student name too long' });
  if (cleanId.length > 50) return res.status(400).json({ error: 'Student ID too long' });

  // ── Validate deviceId format if provided
  if (deviceId && !isValidDeviceId(deviceId)) {
    addFraudLog({ reason: 'INVALID_DEVICE_ID', tokenSnippet: token.slice(0, 20) + '...', ip, studentName: cleanName, studentId: cleanId });
    return res.status(400).json({ error: 'Invalid device identifier.' });
  }

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

  // ── 2a. Shared-link check — token must be claimed by this device
  if (deviceId) {
    const claim = claimedTokens.get(result.tokenId);
    if (claim && claim.deviceId !== deviceId) {
      addFraudLog({
        reason: 'SHARED_LINK_SCAN',
        tokenSnippet: token.slice(0, 20) + '...',
        ip,
        studentName: cleanName,
        studentId: cleanId
      });
      return res.status(403).json({ error: 'This QR link was opened on a different device. Please scan the QR code directly from the screen.' });
    }
  }

  // ── 2b. One device per session check
  if (deviceId) {
    const deviceSessionKey = `${deviceId}:${result.sessionId}`;
    if (deviceSessions.has(deviceSessionKey)) {
      addFraudLog({
        reason: 'DUPLICATE_DEVICE',
        tokenSnippet: token.slice(0, 20) + '...',
        ip,
        studentName: cleanName,
        studentId: cleanId
      });
      return res.status(409).json({ error: 'Attendance has already been marked from this device for this session.' });
    }
  }

  // ── 2c. One IP per session check (catches localStorage-clear / incognito tricks)
  const ipSessionKey = `${ip}:${result.sessionId}`;
  if (ipSessions.has(ipSessionKey)) {
    addFraudLog({
      reason: 'DUPLICATE_IP',
      tokenSnippet: token.slice(0, 20) + '...',
      ip,
      studentName: cleanName,
      studentId: cleanId
    });
    return res.status(409).json({ error: 'Attendance has already been marked from this network connection for this session.' });
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

  // ── ALL CHECKS PASSED — mark token as used, bind device + IP, record attendance
  usedTokens.add(result.tokenId);
  usedTokenExpiry.set(result.tokenId, result.expiresAt || Date.now() + 120000);
  if (deviceId) {
    deviceSessions.set(`${deviceId}:${result.sessionId}`, true);
  }
  ipSessions.set(`${ip}:${result.sessionId}`, true);

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
    res.json({ logs: fraudLogs.slice(0, 200), count: fraudLogs.length });
  } catch (e) {
    console.error('[ATTENDANCE] fraud error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── DELETE /api/attendance/fraud/all — clear entire fraud log (teacher only)
router.delete('/fraud/all', requireTeacher, (req, res) => {
  try {
    const count = fraudLogs.length;
    fraudLogs.length = 0;
    console.log(`\x1b[33m[FRAUD]\x1b[0m All ${count} fraud logs cleared by ${req.teacher.email}`);
    res.json({ message: 'All fraud logs cleared', count });
  } catch (e) {
    console.error('[ATTENDANCE] fraud clear all error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── DELETE /api/attendance/fraud/:index — clear single fraud entry (teacher only)
router.delete('/fraud/:index', requireTeacher, (req, res) => {
  try {
    const idx = parseInt(req.params.index);
    if (isNaN(idx) || idx < 0 || idx >= fraudLogs.length) {
      return res.status(404).json({ error: 'Fraud log entry not found' });
    }
    fraudLogs.splice(idx, 1);
    console.log(`\x1b[33m[FRAUD]\x1b[0m Entry ${idx} deleted by ${req.teacher.email}`);
    res.json({ message: 'Fraud log entry deleted' });
  } catch (e) {
    console.error('[ATTENDANCE] fraud delete error:', e);
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
