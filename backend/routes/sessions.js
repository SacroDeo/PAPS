const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const { classes, sessions, attendanceRecords, fraudLogs } = require('../db');
const { requireTeacher } = require('../middleware');
const { generateToken, TOKEN_EXPIRY_MS } = require('../crypto');

const router = express.Router();

// Track QR refresh intervals server-side (cleared on stop)
const qrIntervals = new Map();

// ── POST /api/sessions/start
router.post('/start', requireTeacher, (req, res) => {
  try {
    const { classId, teacherLat, teacherLng } = req.body;
    if (!classId) return res.status(400).json({ error: 'classId is required' });

    const cls = classes.get(classId);
    if (!cls) return res.status(404).json({ error: 'Class not found' });
    if (cls.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });

    // Enforce one active session per class
    const alreadyActive = [...sessions.values()].find(
      s => s.classId === classId && s.active
    );
    if (alreadyActive) {
      return res.status(409).json({ error: 'A session is already active for this class', sessionId: alreadyActive.id });
    }

    // Build location object
    const teacherLocation =
      teacherLat != null && teacherLng != null
        ? { lat: parseFloat(teacherLat), lng: parseFloat(teacherLng) }
        : null;

    const session = {
      id: `sess_${uuidv4().slice(0, 8)}`,
      classId,
      className: cls.name,
      teacherId: req.teacher.id,
      teacherName: req.teacher.name,
      active: true,
      startedAt: new Date().toISOString(),
      endedAt: null,
      teacherLocation,
      attendeeCount: 0
    };
    sessions.set(session.id, session);

    // Increment session count on class
    cls.sessionCount = (cls.sessionCount || 0) + 1;
    classes.set(classId, cls);

    const locationStr = teacherLocation
      ? `with location (${teacherLocation.lat.toFixed(4)}, ${teacherLocation.lng.toFixed(4)})`
      : 'without location';
    console.log(`\x1b[32m[SESSION]\x1b[0m Started: "${cls.name}" ${locationStr} by ${req.teacher.email}`);

    res.status(201).json({
      sessionId: session.id,
      className: cls.name,
      teacherLocation,
      startedAt: session.startedAt
    });
  } catch (e) {
    console.error('[SESSIONS] start error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/sessions/:id/stop
router.post('/:id/stop', requireTeacher, (req, res) => {
  try {
    const session = sessions.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });
    if (!session.active) return res.status(400).json({ error: 'Session already stopped' });

    session.active = false;
    session.endedAt = new Date().toISOString();
    sessions.set(session.id, session);

    // Clear any server-side QR interval if tracked
    if (qrIntervals.has(req.params.id)) {
      clearInterval(qrIntervals.get(req.params.id));
      qrIntervals.delete(req.params.id);
    }

    const attendees = attendanceRecords.filter(r => r.sessionId === req.params.id).length;
    console.log(`\x1b[33m[SESSION]\x1b[0m Stopped: "${session.className}" — ${attendees} attendees`);

    res.json({
      message: 'Session stopped',
      sessionId: session.id,
      attendees,
      duration: Math.round((new Date(session.endedAt) - new Date(session.startedAt)) / 1000 / 60) + ' min'
    });
  } catch (e) {
    console.error('[SESSIONS] stop error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/sessions/:id/qr — generate fresh HMAC token + QR code
router.get('/:id/qr', requireTeacher, async (req, res) => {
  try {
    const session = sessions.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });
    if (!session.active) return res.status(400).json({ error: 'Session is not active' });

    const { token, tokenId } = generateToken(session.id);

    // Build scan URL — use the request origin or HOST header
    const host = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const scanUrl = `${host}/?t=${encodeURIComponent(token)}`;

    const qrDataUrl = await QRCode.toDataURL(scanUrl, {
      errorCorrectionLevel: 'H',
      width: 300,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' }
    });

    res.json({
      qr: qrDataUrl,
      token,
      tokenId,
      expiresIn: TOKEN_EXPIRY_MS,
      sessionId: session.id,
      className: session.className
    });
  } catch (e) {
    console.error('[SESSIONS] QR error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/sessions/:id/attendees — live attendee list
router.get('/:id/attendees', requireTeacher, (req, res) => {
  try {
    const session = sessions.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });

    const attendees = attendanceRecords
      .filter(r => r.sessionId === req.params.id)
      .map(r => ({
        id: r.id,
        studentName: r.studentName,
        studentId: r.studentId,
        markedAt: r.markedAt,
        locationStatus: r.locationStatus,
        distanceMeters: r.distanceMeters
      }));

    res.json({
      attendees,
      count: attendees.length,
      sessionActive: session.active,
      className: session.className
    });
  } catch (e) {
    console.error('[SESSIONS] attendees error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/sessions — all sessions for teacher (paginated)
router.get('/', requireTeacher, (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const classId = req.query.classId;

    let teacherSessions = [...sessions.values()]
      .filter(s => s.teacherId === req.teacher.id)
      .filter(s => !classId || s.classId === classId)
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

    const total = teacherSessions.length;
    const paginated = teacherSessions.slice((page - 1) * limit, page * limit);

    res.json({
      sessions: paginated,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (e) {
    console.error('[SESSIONS] list error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
