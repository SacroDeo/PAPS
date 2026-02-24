const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { teachers } = require('../db');
const { JWT_SECRET, requireTeacher } = require('../middleware');

const router = express.Router();

// ── Input sanitizer — strip HTML/script tags
const sanitize = (str) => String(str || '').trim().replace(/<[^>]*>/g, '');

// ── Seed demo teacher on startup
(async () => {
  const demoEmail = 'teacher@demo.com';
  if (!teachers.has(demoEmail)) {
    const passwordHash = await bcrypt.hash('teacher123', 12);
    teachers.set(demoEmail, {
      id: `teacher_${uuidv4().slice(0, 8)}`,
      name: 'Demo Teacher',
      email: demoEmail,
      passwordHash,
      createdAt: new Date().toISOString()
    });
    console.log('\x1b[36m[AUTH]\x1b[0m Demo teacher seeded: teacher@demo.com / teacher123');
  }
})();

// ── POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const email = sanitize(req.body.email).toLowerCase();
    const password = sanitize(req.body.password);

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const teacher = teachers.get(email);
    if (!teacher) {
      // Constant-time response to prevent user enumeration
      await bcrypt.compare('dummy', '$2a$12$dummyhashtopreventtiming000000000000000000000');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, teacher.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: teacher.id, email: teacher.email, name: teacher.name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    console.log(`\x1b[36m[AUTH]\x1b[0m Login: ${teacher.email}`);
    res.json({
      token,
      teacher: { id: teacher.id, name: teacher.name, email: teacher.email },
      expiresIn: 8 * 60 * 60 * 1000 // ms, for frontend auto-logout
    });
  } catch (e) {
    console.error('[AUTH] Login error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── POST /api/auth/register (protected by admin key)
router.post('/register', async (req, res) => {
  try {
    const adminKey = sanitize(req.body.adminKey);
    const expectedKey = process.env.ADMIN_KEY || 'admin123';

    if (adminKey !== expectedKey) {
      return res.status(403).json({ error: 'Invalid admin key' });
    }

    const name = sanitize(req.body.name);
    const email = sanitize(req.body.email).toLowerCase();
    const password = sanitize(req.body.password);

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (teachers.has(email)) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const teacher = {
      id: `teacher_${uuidv4().slice(0, 8)}`,
      name,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };
    teachers.set(email, teacher);

    console.log(`\x1b[36m[AUTH]\x1b[0m Registered new teacher: ${email}`);
    res.status(201).json({ message: 'Teacher registered', teacher: { id: teacher.id, name, email } });
  } catch (e) {
    console.error('[AUTH] Register error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── GET /api/auth/me — verify token and return current teacher info
router.get('/me', requireTeacher, (req, res) => {
  res.json({ teacher: req.teacher });
});

module.exports = router;
