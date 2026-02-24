// ─────────────────────────────────────────────────────────────────
// middleware.js — Auth, Rate Limiting, Request Logging
// ─────────────────────────────────────────────────────────────────
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production';

// Simple in-memory rate limiter per IP
// In production: use Redis-based rate limiter (e.g. rate-limiter-flexible)
const scanAttempts = new Map(); // ip → [timestamps]
const SCAN_WINDOW_MS = 5000;   // 5 seconds
const SCAN_MAX_ATTEMPTS = 3;   // max 3 scans per 5 seconds

function requireTeacher(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.teacher = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function rateLimitScans(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();

  if (!scanAttempts.has(ip)) scanAttempts.set(ip, []);
  const attempts = scanAttempts.get(ip).filter(t => now - t < SCAN_WINDOW_MS);

  if (attempts.length >= SCAN_MAX_ATTEMPTS) {
    return res.status(429).json({
      error: 'RATE_LIMITED',
      message: `Too many scan attempts. Max ${SCAN_MAX_ATTEMPTS} per ${SCAN_WINDOW_MS / 1000}s.`
    });
  }

  attempts.push(now);
  scanAttempts.set(ip, attempts);
  next();
}

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const color = res.statusCode >= 400 ? '\x1b[31m' : '\x1b[32m';
    console.log(`${color}[${res.statusCode}]\x1b[0m ${req.method} ${req.path} - ${ms}ms`);
  });
  next();
}

module.exports = { requireTeacher, rateLimitScans, requestLogger, JWT_SECRET };
