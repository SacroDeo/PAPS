// ═══════════════════════════════════════════════════════════════════
// QRShield — Secure Attendance System
// Backend: Node.js + Express
// ═══════════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { requestLogger } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(requestLogger);

// ── SERVE FRONTEND ────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));

// ── API ROUTES ────────────────────────────────────────────────────
app.use('/api/auth',       require('./routes/auth'));
app.use('/api/classes',    require('./routes/classes'));
app.use('/api/sessions',   require('./routes/sessions'));
app.use('/api/attendance', require('./routes/attendance'));

// ── SCAN PAGE (student opens this from QR) ────────────────────────
// Serve frontend for any non-API route (SPA style)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ── GLOBAL ERROR HANDLER ──────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('\x1b[31m[ERROR]\x1b[0m', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n\x1b[36m╔══════════════════════════════════════╗');
  console.log('║        QRShield Server Ready         ║');
  console.log(`║   http://localhost:${PORT}              ║`);
  console.log('╚══════════════════════════════════════╝\x1b[0m\n');
  console.log('\x1b[33mSecret key loaded:\x1b[0m', process.env.HMAC_SECRET ? '✅ From .env' : '⚠️  Using dev default (set HMAC_SECRET in .env!)');
});
