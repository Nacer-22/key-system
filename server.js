const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors'); // تمت إضافة هذه المكتبة
const app = express();
const db = new Database('keys.db');

app.use(cors()); // تم تفعيل السماح بالاتصال من المتصفحات
app.use(express.json());
app.use(express.static('.')); 

// --- إعداد قاعدة البيانات ---
db.exec(`
CREATE TABLE IF NOT EXISTS codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    duration_hours INTEGER NOT NULL,
    max_devices INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    note TEXT
);
CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_id INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY(code_id) REFERENCES codes(id)
);
`);

// الرمز السري للوحة التحكم
const ADMIN_TOKEN = "Nacer_Nacer_22"; 

function adminAuth(req, res, next) {
    if (req.headers['x-admin-token'] !== ADMIN_TOKEN)
        return res.status(403).json({ error: "Unauthorized" });
    next();
}

// توليد الكود بالبادئة Nacer
function generateCode(prefix = "Nacer") {
    const part = () => crypto.randomBytes(2).toString('hex').toUpperCase();
    return `${prefix}-${part()}-${part()}-${part()}`;
}

// ========== API للعميل (التطبيق) ==========
app.post('/api/verify', (req, res) => {
    const { code, device_id } = req.body;
    if (!code || !device_id) return res.json({ valid: false, reason: "missing_params" });

    const row = db.prepare("SELECT * FROM codes WHERE code = ?").get(code);
    if (!row) return res.json({ valid: false, reason: "code_not_found" });
    if (!row.is_active) return res.json({ valid: false, reason: "code_disabled" });
    if (row.expires_at && new Date(row.expires_at) < new Date())
        return res.json({ valid: false, reason: "code_expired" });

    let act = db.prepare("SELECT * FROM activations WHERE code_id = ? AND device_id = ?").get(row.id, device_id);
    if (act) {
        if (new Date(act.expires_at) < new Date())
            return res.json({ valid: false, reason: "expired" });
        return res.json({ valid: true, expires_at: act.expires_at });
    }

    const count = db.prepare("SELECT COUNT(*) AS c FROM activations WHERE code_id = ?").get(row.id).c;
    if (count >= row.max_devices) return res.json({ valid: false, reason: "max_devices_reached" });

    const expiresAt = row.duration_hours === 0
        ? new Date('9999-12-31').toISOString()
        : new Date(Date.now() + row.duration_hours * 3600 * 1000).toISOString();

    db.prepare("INSERT INTO activations (code_id, device_id, expires_at) VALUES (?, ?, ?)").run(row.id, device_id, expiresAt);
    res.json({ valid: true, expires_at: expiresAt });
});

// ========== API للوحة التحكم ==========
app.post('/api/admin/codes', adminAuth, (req, res) => {
    const { duration_hours, max_devices = 1, count = 1, note = "" } = req.body;
    const codes = [];
    const stmt = db.prepare(`INSERT INTO codes (code, duration_hours, max_devices, note) VALUES (?, ?, ?, ?)`);
    for (let i = 0; i < count; i++) {
        const code = generateCode();
        stmt.run(code, duration_hours, max_devices, note);
        codes.push(code);
    }
    res.json({ created: codes });
});

app.get('/api/admin/codes', adminAuth, (req, res) => {
    const rows = db.prepare(`
        SELECT c.*, (SELECT COUNT(*) FROM activations a WHERE a.code_id = c.id) AS used
        FROM codes c ORDER BY c.id DESC
    `).all();
    res.json(rows);
});

app.delete('/api/admin/codes/:id', adminAuth, (req, res) => {
    db.prepare("DELETE FROM activations WHERE code_id = ?").run(req.params.id);
    db.prepare("DELETE FROM codes WHERE id = ?").run(req.params.id);
    res.json({ ok: true });
});

app.patch('/api/admin/codes/:id', adminAuth, (req, res) => {
    db.prepare("UPDATE codes SET is_active = ? WHERE id = ?").run(req.body.is_active ? 1 : 0, req.params.id);
    res.json({ ok: true });
});

// --- مسار جديد لإعادة تعيين المفتاح (حذف الأجهزة المرتبطة) ---
app.delete('/api/admin/codes/:id/reset', adminAuth, (req, res) => {
    db.prepare("DELETE FROM activations WHERE code_id = ?").run(req.params.id);
    res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on port ${PORT}`));
