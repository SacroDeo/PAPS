const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { classes, attendanceRecords } = require('../db');
const { requireTeacher } = require('../middleware');
const router = express.Router();

// GET /api/classes — list teacher's classes
router.get('/', requireTeacher, (req, res) => {
  const myClasses = [...classes.values()].filter(c => c.teacherId === req.teacher.id);
  const withStats = myClasses.map(cls => {
    const totalAttendance = attendanceRecords.filter(a => a.classId === cls.id).length;
    return { ...cls, totalAttendance };
  });
  res.json(withStats);
});

// POST /api/classes — create class
router.post('/', requireTeacher, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Class name required' });
  const cls = {
    id: `cls_${uuidv4().slice(0,8)}`,
    name: name.trim(),
    teacherId: req.teacher.id,
    createdAt: new Date().toISOString(),
    sessionCount: 0
  };
  classes.set(cls.id, cls);
  res.status(201).json(cls);
});

// DELETE /api/classes/:id
router.delete('/:id', requireTeacher, (req, res) => {
  const cls = classes.get(req.params.id);
  if (!cls) return res.status(404).json({ error: 'Class not found' });
  if (cls.teacherId !== req.teacher.id) return res.status(403).json({ error: 'Forbidden' });
  classes.delete(req.params.id);
  res.json({ message: 'Class deleted' });
});

module.exports = router;
