const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const DB_FILE = path.join(__dirname, 'keys.db.json');
function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8') || '{}'); }
  catch { return { codes: [], activations: [] }; }
}
function saveDb(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { valid: false, reason: "too_many_requests" }
});

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Nacer_Nacer_22";
const JWT_SECRET = process.env.JWT_SECRET || 'Nacer_x_Rida_fixed_secret_2026';

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (!password || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
});

function adminAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: "No token" });
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: "Invalid token" });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Expired" });
        req.user = decoded;
        next();
    });
}

function norm(code) {
  return String(code || '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[^A-Za-z0-9]/g, '')
    .toUpperCase();
}

app.post('/api/check', verifyLimiter, (req, res) => {
    const code = norm(req.body.code);
    if (!code) return res.json({ valid: false, reason: "missing_params" });
    if (!/^NACER[A-F0-9]{12,16}$/.test(code)) return res.json({ valid: false, reason: "invalid_format" });
    const db = loadDb();
    const row = db.codes.find(c => norm(c.code) === code);
    if (!row) return res.json({ valid: false, reason: "code_not_found" });
    if (!row.is_active) return res.json({ valid: false, reason: "code_disabled" });
    if (row.expires_at && new Date(row.expires_at) < new Date()) return res.json({ valid: false, reason: "code_expired" });
    res.json({ valid: true, expires_at: row.expires_at, max_devices: row.max_devices, code: row.code });
});

app.post('/api/verify', verifyLimiter, (req, res) => {
    const code = norm(req.body.code);
    const device_id = String(req.body.device_id || '').trim();
    if (!code || !device_id) return res.json({ valid: false, reason: "missing_params" });
    if (!/^NACER[A-F0-9]{12,16}$/.test(code)) return res.json({ valid: false, reason: "invalid_format" });
    const db = loadDb();
    const row = db.codes.find(c => norm(c.code) === code);
    if (!row) return res.json({ valid: false, reason: "code_not_found" });
    if (!row.is_active) return res.json({ valid: false, reason: "code_disabled" });
    if (row.expires_at && new Date(row.expires_at) < new Date()) return res.json({ valid: false, reason: "code_expired" });
    const act = db.activations.find(a => a.code_id === row.id && a.device_id === device_id);
    if (act) {
      if (new Date(act.expires_at) < new Date()) return res.json({ valid: false, reason: "expired" });
      return res.json({ valid: true, expires_at: act.expires_at });
    }
    const count = db.activations.filter(a => a.code_id === row.id).length;
    if (count >= row.max_devices) return res.json({ valid: false, reason: "max_devices_reached" });
    const expiresAt = row.duration_hours === 0 ? new Date('9999-12-31').toISOString() : new Date(Date.now() + row.duration_hours * 3600 * 1000).toISOString();
    const act2 = { id: 'a' + Date.now() + Math.random().toString(36).slice(2,6), code_id: row.id, device_id, expires_at: expiresAt };
    db.activations.push(act2);
    saveDb(db);
    res.json({ valid: true, expires_at: expiresAt });
});

app.post('/api/admin/codes', adminAuth, (req, res) => {
    const { duration_hours, max_devices = 100, count = 1, note = "" } = req.body;
    const codes = [];
    const db = loadDb();
    for (let i = 0; i < count; i++) {
      const code = `Nacer-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
      const c = { id: 'c' + Date.now() + Math.random().toString(36).slice(2,6), code, duration_hours: Number(duration_hours)||0, max_devices: Number(max_devices)||100, is_active: 1, note, expires_at: duration_hours === 0 ? null : new Date(Date.now() + Number(duration_hours) * 3600 * 1000).toISOString() };
      db.codes.push(c);
      codes.push(code);
    }
    saveDb(db);
    res.json({ created: codes });
});

app.get('/api/admin/codes', adminAuth, (req, res) => {
    const db = loadDb();
    const rows = db.codes.map(c => ({...c, used: db.activations.filter(a => a.code_id === c.id).length}));
    rows.sort((a,b) => b.id.localeCompare(a.id));
    res.json(rows);
});

app.delete('/api/admin/codes/:id', adminAuth, (req, res) => {
    const db = loadDb();
    db.activations = db.activations.filter(a => a.code_id !== req.params.id);
    db.codes = db.codes.filter(c => c.id !== req.params.id);
    saveDb(db);
    res.json({ ok: true });
});

app.delete('/api/admin/codes/:id/reset', adminAuth, (req, res) => {
    const db = loadDb();
    db.activations = db.activations.filter(a => a.code_id !== req.params.id);
    saveDb(db);
    res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Key Server on port ${PORT}`));
