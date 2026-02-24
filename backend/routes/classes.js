const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { classes, attendanceRecords, sessions } = require('../db');
const { requireTeacher } = require('../middleware');

const router = express.Router();

const sanitize = (str) => String(str || '').trim().replace(/<[^>]*>/g, '');

// ── GET /api/classes — list teacher's classes with stats
router.get('/', requireTeacher, (req, res) => {
  try {
    const teacherClasses = [...classes.values()]
      .filter(c => c.teacherId === req.teacher.id)
      .map(c => {
        const totalAttendance = attendanceRecords.filter(r => r.classId === c.id).length;
        const activeSessions = [...sessions.values()].filter(
          s => s.classId === c.id && s.active
        ).length;
        return { ...c, totalAttendance, activeSessions };
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({ classes: teacherClasses });
  } catch (e) {
    console.error('[CLASSES] GET error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/classes — create a class
router.post('/', requireTeacher, (req, res) => {
  try {
    const name = sanitize(req.body.name);
    if (!name) return res.status(400).json({ error: 'Class name is required' });
    if (name.length > 100) return res.status(400).json({ error: 'Class name too long (max 100 chars)' });

    // Prevent duplicate class names for same teacher
    const exists = [...classes.values()].some(
      c => c.teacherId === req.teacher.id && c.name.toLowerCase() === name.toLowerCase()
    );
    if (exists) return res.status(409).json({ error: 'You already have a class with this name' });

    const cls = {
      id: `cls_${uuidv4().slice(0, 8)}`,
      name,
      teacherId: req.teacher.id,
      teacherName: req.teacher.name,
      createdAt: new Date().toISOString(),
      sessionCount: 0
    };
    classes.set(cls.id, cls);
    console.log(`\x1b[36m[CLASSES]\x1b[0m Created: "${name}" by ${req.teacher.email}`);
    res.status(201).json({ class: cls });
  } catch (e) {
    console.error('[CLASSES] POST error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── DELETE /api/classes/:id — delete a class and all its data
router.delete('/:id', requireTeacher, (req, res) => {
  try {
    const cls = classes.get(req.params.id);
    if (!cls) return res.status(404).json({ error: 'Class not found' });
    if (cls.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });

    // Check for active sessions
    const hasActive = [...sessions.values()].some(s => s.classId === cls.id && s.active);
    if (hasActive) return res.status(400).json({ error: 'Stop the active session before deleting this class' });

    // Remove class and all related records
    classes.delete(req.params.id);
    const removed = attendanceRecords.filter(r => r.classId === req.params.id).length;
    const toKeep = attendanceRecords.filter(r => r.classId !== req.params.id);
    attendanceRecords.length = 0;
    toKeep.forEach(r => attendanceRecords.push(r));

    console.log(`\x1b[33m[CLASSES]\x1b[0m Deleted: "${cls.name}" — ${removed} attendance records removed`);
    res.json({ message: 'Class deleted', recordsRemoved: removed });
  } catch (e) {
    console.error('[CLASSES] DELETE error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
