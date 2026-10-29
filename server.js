const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken'); // إضافة جديدة
const app = express();
const db = new Database('keys.db');

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// --- إعداد الحماية (Rate Limiting) ---
const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { valid: false, reason: "too_many_requests" }
});

// --- إعداد قاعدة البيانات ---
db.exec(`
CREATE TABLE IF NOT EXISTS codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    duration_hours REAL NOT NULL,
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

// --- إعدادات المصادقة الآمنة ---
// سيتم قراءتها من Environment Variables على Render
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

if (!ADMIN_PASSWORD) {
    console.warn("⚠️ تحذير: لم يتم تعيين كلمة مرور الإدارة في متغيرات البيئة (ADMIN_PASSWORD).");
}

// مسار تسجيل الدخول (يتحقق من كلمة المرور ويعطي توكن)
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
    if (!password || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: "Unauthorized", message: "كلمة المرور غير صحيحة" });
    }
    
    // إنشاء توكن صالح لمدة ساعة
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// دالة حماية المسارات الإدارية
function adminAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: "No token provided" });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: "Invalid token format" });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Unauthorized", message: "انتهت الجلسة" });
        req.user = decoded;
        next();
    });
}

// ========== API للعميل (لا يحتاج توكن) ==========
app.post('/api/verify', verifyLimiter, (req, res) => {
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
        const token = jwt.sign({ role: 'user', code_id: row.id, device_id }, JWT_SECRET, { expiresIn: '12h' });
        return res.json({ valid: true, expires_at: act.expires_at, token });
    }

    const count = db.prepare("SELECT COUNT(*) AS c FROM activations WHERE code_id = ?").get(row.id).c;
    if (count >= row.max_devices) return res.json({ valid: false, reason: "max_devices_reached" });

    const expiresAt = row.duration_hours === 0
        ? new Date('9999-12-31').toISOString()
        : new Date(Date.now() + row.duration_hours * 3600 * 1000).toISOString();

    db.prepare("INSERT INTO activations (code_id, device_id, expires_at) VALUES (?, ?, ?)").run(row.id, device_id, expiresAt);
    const token = jwt.sign({ role: 'user', code_id: row.id, device_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ valid: true, expires_at: expiresAt, token });
});

// ========== رابط الاتصال (Subscription Link) ==========
// يُرجع رابط الاتصال بعد التحقق من توكن الجلسة وصلاحية الاشتراك.
// الرابط يُقرأ من متغير البيئة SUB_LINK (يمكن تغييره من Render دون تعديل الكود).
const SUB_LINK = process.env.SUB_LINK || "https://t.me/HAX_NON_ROOT";

app.get('/api/sub', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "no_token" });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "invalid_token_format" });

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return res.status(401).json({ error: "invalid_or_expired_token" });
    }

    if (!decoded || decoded.role !== 'user') return res.status(403).json({ error: "forbidden" });

    const act = db.prepare("SELECT * FROM activations WHERE code_id = ? AND device_id = ?")
        .get(decoded.code_id, decoded.device_id);
    if (!act) return res.status(403).json({ error: "no_activation" });
    if (new Date(act.expires_at) < new Date()) return res.status(403).json({ error: "expired" });

    res.json({ link: SUB_LINK });
});

// ========== API للوحة التحكم (محمية بـ adminAuth) ==========
app.post('/api/admin/codes', adminAuth, (req, res) => {
    const { duration_hours, max_devices = 1, count = 1, note = "" } = req.body;
    const codes = [];
    const stmt = db.prepare(`INSERT INTO codes (code, duration_hours, max_devices, note) VALUES (?, ?, ?, ?)`);
    for (let i = 0; i < count; i++) {
        const code = `Nacer-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
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

app.delete('/api/admin/codes/:id/reset', adminAuth, (req, res) => {
    db.prepare("DELETE FROM activations WHERE code_id = ?").run(req.params.id);
    res.json({ ok: true });
});

app.patch('/api/admin/codes/:id', adminAuth, (req, res) => {
    db.prepare("UPDATE codes SET is_active = ? WHERE id = ?").run(req.body.is_active ? 1 : 0, req.params.id);
    res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on port ${PORT}`));
