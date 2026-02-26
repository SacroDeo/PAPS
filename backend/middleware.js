const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production';

// ── requireTeacher — verifies Bearer JWT, attaches req.teacher
function requireTeacher(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = auth.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.teacher = decoded;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── rateLimitScans — in-memory per-IP: max 30 requests per 10 seconds
const scanAttempts = new Map();
const SCAN_WINDOW_MS = 10000;
const SCAN_MAX = 30;

// Cleanup old entries every 60 seconds to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of scanAttempts.entries()) {
    if (now - data.start > SCAN_WINDOW_MS * 2) scanAttempts.delete(ip);
  }
}, 60000);

function rateLimitScans(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const entry = scanAttempts.get(ip);

  if (!entry || now - entry.start > SCAN_WINDOW_MS) {
    scanAttempts.set(ip, { count: 1, start: now });
    return next();
  }

  entry.count++;
  if (entry.count > SCAN_MAX) {
    console.warn(`\x1b[31m[RATE-LIMIT]\x1b[0m ${ip} exceeded ${SCAN_MAX} scan attempts in ${SCAN_WINDOW_MS / 1000}s`);
    return res.status(429).json({ error: 'Too many attempts. Please wait and try again.' });
  }
  next();
}

// ── requestLogger — logs [statusCode] METHOD path - Xms
function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const code = res.statusCode;
    const color = code >= 500 ? '\x1b[31m' : code >= 400 ? '\x1b[33m' : '\x1b[32m';
    console.log(`${color}[${code}]\x1b[0m ${req.method} ${req.path} - ${ms}ms`);
  });
  next();
}

module.exports = { requireTeacher, rateLimitScans, requestLogger, JWT_SECRET };
