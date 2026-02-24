require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { requestLogger } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY HEADERS
app.use(helmet({
  contentSecurityPolicy: false, // disabled so inline scripts in the SPA work
  crossOriginEmbedderPolicy: false
}));

// ── CORS
const allowedOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({ origin: allowedOrigin }));

// ── BODY LIMITS (prevent large payload attacks)
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ── GLOBAL RATE LIMIT (all API routes): 200 req / 15 min per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' }
});
app.use('/api/', globalLimiter);

// ── LOGIN RATE LIMIT: 10 attempts / 15 min per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});
app.use('/api/auth/login', loginLimiter);

// ── REQUEST LOGGER
app.use(requestLogger);

// ── SERVE FRONTEND
app.use(express.static(path.join(__dirname, '../frontend')));

// ── API ROUTES
app.use('/api/auth',       require('./routes/auth'));
app.use('/api/classes',    require('./routes/classes'));
app.use('/api/sessions',   require('./routes/sessions'));
app.use('/api/attendance', require('./routes/attendance'));

// ── SPA FALLBACK
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ── GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('\x1b[31m[ERROR]\x1b[0m', err.stack || err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── GRACEFUL SHUTDOWN
const server = app.listen(PORT, () => {
  console.log('\x1b[32m[QRShield]\x1b[0m Server running on port', PORT);
  console.log('\x1b[36m[QRShield]\x1b[0m Environment:', process.env.NODE_ENV || 'development');
});

process.on('SIGTERM', () => {
  console.log('[QRShield] SIGTERM received — shutting down gracefully');
  server.close(() => {
    console.log('[QRShield] Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\n[QRShield] SIGINT received — shutting down');
  server.close(() => process.exit(0));
});

// ── UNHANDLED REJECTION GUARD
process.on('unhandledRejection', (reason) => {
  console.error('\x1b[31m[UNHANDLED REJECTION]\x1b[0m', reason);
});
