const express = require('express');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const { classes, sessions, attendanceRecords, fraudLogs } = require('../db');
const { requireTeacher } = require('../middleware');
const { generateToken, TOKEN_EXPIRY_MS } = require('../crypto');
const router = express.Router();

// Active QR generation intervals per session
const qrIntervals = new Map(); // sessionId → intervalId

// POST /api/sessions/start — start a session for a class
router.post('/start', requireTeacher, (req, res) => {
  const { classId } = req.body;
  const cls = classes.get(classId);
  if (!cls) return res.status(404).json({ error: 'Class not found' });
  if (cls.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });

  // Check no active session for this class
  const existing = [...sessions.values()].find(s => s.classId === classId && s.active);
  if (existing) return res.status(409).json({ error: 'Session already active for this class', sessionId: existing.id });

  const sessionId = `sess_${uuidv4().slice(0,12)}`;
  const session = {
    id: sessionId,
    classId,
    className: cls.name,
    teacherId: req.teacher.id,
    active: true,
    startedAt: new Date().toISOString(),
    endedAt: null
  };
  sessions.set(sessionId, session);
  cls.sessionCount = (cls.sessionCount || 0) + 1;

  console.log(`\x1b[32m[SESSION]\x1b[0m Started: ${sessionId} for class "${cls.name}"`);
  res.status(201).json({ sessionId, className: cls.name, message: 'Session started' });
});

// POST /api/sessions/:id/stop
router.post('/:id/stop', requireTeacher, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });
  session.active = false;
  session.endedAt = new Date().toISOString();
  clearInterval(qrIntervals.get(req.params.id));
  qrIntervals.delete(req.params.id);
  console.log(`\x1b[33m[SESSION]\x1b[0m Stopped: ${req.params.id}`);
  res.json({ message: 'Session stopped', session });
});

// GET /api/sessions/:id/qr — generate fresh QR (called every TOKEN_EXPIRY_MS by frontend)
router.get('/:id/qr', requireTeacher, async (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (!session.active) return res.status(400).json({ error: 'Session not active' });
  if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });

  const { token, expiresAt } = generateToken(session.id);
  const url = `${process.env.APP_URL || 'http://localhost:3000'}/scan?t=${token}`;

  // Generate QR as base64 PNG
  const qrDataUrl = await QRCode.toDataURL(url, {
    width: 280,
    margin: 2,
    color: { dark: '#000000', light: '#ffffff' }
  });

  res.json({ token, url, qrDataUrl, expiresAt, sessionId: session.id, className: session.className });
});

// GET /api/sessions/:id/attendees — live attendee list
router.get('/:id/attendees', requireTeacher, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (session.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });
  const attendees = attendanceRecords.filter(a => a.sessionId === req.params.id);
  res.json({ attendees, count: attendees.length });
});

// GET /api/sessions — all sessions for teacher
router.get('/', requireTeacher, (req, res) => {
  const mySessions = [...sessions.values()].filter(s => s.teacherId === req.teacher.id);
  res.json(mySessions);
});

module.exports = router;
