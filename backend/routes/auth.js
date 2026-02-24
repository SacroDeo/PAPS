const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { teachers } = require('../db');
const { JWT_SECRET } = require('../middleware');
const router = express.Router();

async function seedDemoTeacher() {
  if (!teachers.has('teacher@demo.com')) {
    const passwordHash = await bcrypt.hash('teacher123', 12);
    teachers.set('teacher@demo.com', {
      id: 'teacher_demo',
      name: 'Prof. Demo',
      email: 'teacher@demo.com',
      passwordHash
    });
    console.log('\x1b[33m[SEED]\x1b[0m Demo teacher: teacher@demo.com / teacher123');
  }
}
seedDemoTeacher();

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const teacher = teachers.get(email.toLowerCase().trim());
  if (!teacher) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, teacher.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: teacher.id, email: teacher.email, name: teacher.name }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, teacher: { id: teacher.id, name: teacher.name, email: teacher.email } });
});

// POST /api/auth/register (requires adminKey)
router.post('/register', async (req, res) => {
  const { name, email, password, adminKey } = req.body;
  if (adminKey !== (process.env.ADMIN_KEY || 'admin123')) return res.status(403).json({ error: 'Invalid admin key' });
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (teachers.has(email.toLowerCase())) return res.status(409).json({ error: 'Teacher already exists' });
  if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });
  const passwordHash = await bcrypt.hash(password, 12);
  const teacher = { id: `teacher_${uuidv4().slice(0,8)}`, name, email: email.toLowerCase(), passwordHash };
  teachers.set(teacher.email, teacher);
  res.status(201).json({ message: 'Teacher created', teacher: { id: teacher.id, name, email } });
});

module.exports = router;
