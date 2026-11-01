/**
 * ============================================================================
 *  Nacer_22 — Key Server  (v2 · محصّن)
 * ============================================================================
 *  نسخة محصّنة من السيرفر الأصلي.
 *  ⚠️ قاعدة ذهبية: واجهة لوحة التحكم (dashboard.html) لم تُلمس، وكل نقاط
 *     الـ API التي تستدعيها بقيت بنفس المسار ونفس شكل الطلب والرد.
 *
 *  الثغرات المُصلحة:
 *   1. تسريب keys.db و server.js عبر express.static('.')
 *   2. تصعيد الصلاحيات: adminAuth كان يتحقق من التوكن ولا يفحص الدور
 *   3. غياب حدّ المحاولات على /api/admin/login
 *   4. مقارنة كلمة المرور غير آمنة ضد هجمات التوقيت
 *   5. JWT_SECRET عشوائي عند غيابه (كل إعادة تشغيل تُبطل كل التوكنات)
 *   6. لا تحقق من المدخلات
 *   7. لا سجل محاولات
 *   8. لا فهارس على activations
 *   9. لا إبطال للتفعيلات
 *  10. لا نبضة حياة
 *  11. لا نقطة فحص صحة
 *  12. البحث عن الكود حساس لحالة الأحرف
 * ============================================================================
 */

'use strict';

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');

const app = express();

/* ==========================================================================
 * 1) الإعدادات — فحص صارم عند الإقلاع
 * ========================================================================== */

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || 'keys.db';
const SUB_LINK = process.env.SUB_LINK || 'https://t.me/HAX_NON_ROOT';

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// توافقية رجعية: إن لم تُضبط المفاتيح المنفصلة، نرجع إلى JWT_SECRET القديم
// حتى لا يتعطّل النشر الحالي. الفحص الحقيقي للدور هو ما يمنع تصعيد الصلاحيات.
const LEGACY_SECRET = process.env.JWT_SECRET;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || LEGACY_SECRET;
const USER_JWT_SECRET = process.env.USER_JWT_SECRET || LEGACY_SECRET;

const USER_TOKEN_TTL = process.env.USER_TOKEN_TTL || '12h';
const ADMIN_TOKEN_TTL = process.env.ADMIN_TOKEN_TTL || '1h';

function fatal(msg) {
  console.error('\n❌ خطأ إعداد: ' + msg + '\n');
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  fatal('ADMIN_PASSWORD غير مضبوط. اضبطه في متغيرات البيئة قبل الإقلاع.');
}
if (ADMIN_PASSWORD.length < 8) {
  console.warn('⚠️  ADMIN_PASSWORD أقصر من 8 أحرف — يُنصح بـ 16 حرفاً أو أكثر.');
}
if (!ADMIN_JWT_SECRET || ADMIN_JWT_SECRET.length < 16) {
  fatal('ADMIN_JWT_SECRET (أو JWT_SECRET) غير مضبوط أو أقصر من 16 حرفاً.');
}
if (!USER_JWT_SECRET || USER_JWT_SECRET.length < 16) {
  fatal('USER_JWT_SECRET (أو JWT_SECRET) غير مضبوط أو أقصر من 16 حرفاً.');
}
if (ADMIN_JWT_SECRET === USER_JWT_SECRET) {
  console.warn(
    '⚠️  ADMIN_JWT_SECRET و USER_JWT_SECRET متطابقان. الحماية قائمة على فحص الدور،\n' +
      '   لكن يُفضّل استخدام مفتاحين مختلفين (طبقة دفاع إضافية).'
  );
}

// Render / أي reverse proxy: نحتاج trust proxy حتى يعمل rate-limit على IP الحقيقي
if (process.env.TRUST_PROXY !== 'false') {
  app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
}

/* ==========================================================================
 * 2) قاعدة البيانات — جداول + فهارس + ترحيل تلقائي
 * ========================================================================== */

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

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
    FOREIGN KEY(code_id) REFERENCES codes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    code TEXT,
    device_id TEXT,
    ip TEXT,
    ok INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

/* --- طلبات نقل المفتاح إلى جهاز جديد (سياسة "ج": بموافقة الأدمن) --- */
CREATE TABLE IF NOT EXISTS transfer_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_id INTEGER NOT NULL,
    from_device_id TEXT,
    to_device_id TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected | cancelled
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by TEXT,
    FOREIGN KEY(code_id) REFERENCES codes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_act_code_device ON activations(code_id, device_id);
CREATE INDEX IF NOT EXISTS idx_tr_status       ON transfer_requests(status);
CREATE INDEX IF NOT EXISTS idx_tr_code         ON transfer_requests(code_id);
CREATE INDEX IF NOT EXISTS idx_act_code        ON activations(code_id);
CREATE INDEX IF NOT EXISTS idx_codes_code      ON codes(code);
CREATE INDEX IF NOT EXISTS idx_attempts_time   ON attempts(created_at);
`);

/** إضافة عمود إن لم يكن موجوداً (ترحيل قواعد البيانات القديمة) */
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    console.log(`   ↳ ترحيل: أُضيف العمود ${table}.${column}`);
  }
}

ensureColumn('activations', 'device_label', 'TEXT');
ensureColumn('activations', 'last_seen_at', 'TIMESTAMP');
ensureColumn('activations', 'revoked_at', 'TIMESTAMP');
ensureColumn('activations', 'pubkey', 'TEXT');           // مفتاح الجهاز العام (ECDSA P-256, SPKI base64)
ensureColumn('activations', 'attested', 'INTEGER DEFAULT 0'); // هل تم ربط الجهاز بتوقيع تشفيري؟
ensureColumn('codes', 'plan', "TEXT DEFAULT 'PRO'");

/* ==========================================================================
 * 3) أدوات مساعدة
 * ========================================================================== */

/** مقارنة آمنة ضد هجمات التوقيت */
function safeEqual(a, b) {
  const ab = Buffer.from(String(a ?? ''), 'utf8');
  const bb = Buffer.from(String(b ?? ''), 'utf8');
  if (ab.length !== bb.length) {
    // نقارن شيئاً بطوله نفسه لإبقاء الزمن ثابتاً
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function readBearer(req) {
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!h || typeof h !== 'string') return null;
  const parts = h.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1].trim() || null;
}

function clientIp(req) {
  return (req.ip || req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

const logAttempt = db.prepare(
  'INSERT INTO attempts (kind, code, device_id, ip, ok, reason) VALUES (?, ?, ?, ?, ?, ?)'
);
function recordAttempt(kind, { code = null, deviceId = null, ip = null, ok = 0, reason = null }) {
  try {
    logAttempt.run(kind, code, deviceId, ip, ok ? 1 : 0, reason);
  } catch (e) {
    console.error('recordAttempt failed:', e.message);
  }
}

const CODE_RE = /^[A-Za-z0-9_-]{4,64}$/;
const DEVICE_RE = /^[A-Za-z0-9._:-]{8,128}$/;

/* ==========================================================================
 * 4) الوسائط العامة
 * ========================================================================== */

// helmet مع تعطيل CSP: لوحة التحكم تستخدم سكربتات وأنماطاً مضمّنة وخطوطاً من CDN،
// وتشغيل CSP الافتراضي سيكسرها. (لم نلمس اللوحة، فلم نفرض عليها سياسة جديدة.)
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

// CORS: افتراضياً مفتوح للحفاظ على عمل اللوحة من أي أصل.
// يمكن تقييده بـ ALLOWED_ORIGINS="https://a.com,https://b.com"
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  })
);

app.use(express.json({ limit: '32kb' }));

/* ==========================================================================
 * 5) 🔴 الإصلاح الحرج #1 — منع تسريب الملفات الحساسة
 *    اللوحة تُخدم من الجذر (dashboard.html + assets/)، لذلك لا نستطيع نقلها.
 *    الحل: حجب صريح لكل ما هو حساس قبل express.static.
 * ========================================================================== */

const SENSITIVE_PATH = new RegExp(
  [
    '(^|/)(server\\.js|package(-lock)?\\.json|README\\.md|\\.env[^/]*|\\.git[^/]*|node_modules|test|tests|docs|data)(/|$)',
    '\\.(db|sqlite|sqlite3|db-wal|db-shm|db-journal|log|jks|keystore|pem|key|crt|map)$',
  ].join('|'),
  'i'
);

app.use((req, res, next) => {
  let p;
  try {
    p = decodeURIComponent(req.path);
  } catch {
    return res.status(400).type('text/plain').send('bad request');
  }
  if (p.includes('\0') || p.includes('..') || SENSITIVE_PATH.test(p)) {
    return res.status(404).type('text/plain').send('Not found');
  }
  next();
});

app.use(
  express.static('.', {
    dotfiles: 'deny',
    index: false,
    etag: true,
    maxAge: '1h',
    setHeaders(res, filePath) {
      if (/\.(db|sqlite|sqlite3|db-wal|db-shm|db-journal)$/i.test(filePath)) {
        res.status(404).end();
      }
    },
  })
);

/* ==========================================================================
 * 6) فحص الصحة — لـ Render والمراقبة
 * ========================================================================== */

app.get('/api/health', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ ok: true, uptime: Math.floor(process.uptime()) });
  } catch {
    res.status(503).json({ ok: false });
  }
});

/* ==========================================================================
 * 7) محددات المعدل
 * ========================================================================== */

const jsonLimit = (payload) => ({
  standardHeaders: true,
  legacyHeaders: false,
  message: payload,
});

// 🔴 الإصلاح الحرج #3 — حدّ على محاولات دخول المدير
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  skipSuccessfulRequests: true,
  ...jsonLimit({ error: 'too_many_attempts', message: 'محاولات كثيرة، حاول بعد 15 دقيقة' }),
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  ...jsonLimit({ valid: false, reason: 'too_many_requests' }),
});

const subLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  ...jsonLimit({ error: 'too_many_requests' }),
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  ...jsonLimit({ error: 'too_many_requests' }),
});

/* ==========================================================================
 * 8) 🔴 الإصلاح الحرج #2 — مصادقة المدير: فحص الدور فعلياً
 * ========================================================================== */

function adminAuth(req, res, next) {
  const token = readBearer(req);
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized', message: 'انتهت الجلسة' });
    // ← السطر الذي كان غائباً في النسخة الأصلية
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden', message: 'صلاحيات غير كافية' });
    }
    req.user = decoded;
    next();
  });
}

/* ==========================================================================
 * 9) دخول المدير
 * ========================================================================== */

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!password) {
    recordAttempt('admin_login', { ip: clientIp(req), ok: 0, reason: 'missing_password' });
    return res.status(401).json({ error: 'Unauthorized', message: 'كلمة المرور غير صحيحة' });
  }

  if (!safeEqual(password, ADMIN_PASSWORD)) {
    recordAttempt('admin_login', { ip: clientIp(req), ok: 0, reason: 'bad_password' });
    return res.status(401).json({ error: 'Unauthorized', message: 'كلمة المرور غير صحيحة' });
  }

  recordAttempt('admin_login', { ip: clientIp(req), ok: 1 });
  const token = jwt.sign({ role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: ADMIN_TOKEN_TTL });
  res.json({ token });
});

/* ==========================================================================
 * 9.5) ربط الجهاز تشفيرياً — ECDSA P-256 + nonce
 * --------------------------------------------------------------------------
 *  الفكرة: التطبيق يولّد مفتاحاً داخل Android Keystore (غير قابل للتصدير).
 *  عند كل تفعيل/نبضة يوقّع الرسالة:  code|device_id|nonce
 *  السيرفر يتحقق من التوقيع بالمفتاح العام، ويربط المفتاح بالتفعيل.
 *  بهذا لا يمكن نسخ ملف التفعيل إلى جهاز آخر — المفتاح الخاص لا يخرج من الشريحة.
 * ========================================================================== */

const NONCE_TTL = '120s';

/** إصدار nonce موقّع قصير العمر */
function issueNonce() {
  return jwt.sign(
    { typ: 'nonce', n: crypto.randomBytes(16).toString('hex') },
    USER_JWT_SECRET,
    { expiresIn: NONCE_TTL }
  );
}

function verifyNonce(nonce) {
  try {
    const d = jwt.verify(nonce, USER_JWT_SECRET, { algorithms: ['HS256'] });
    return d && d.typ === 'nonce' ? d : null;
  } catch {
    return null;
  }
}

/** التحقق من توقيع الجهاز وإرجاع بصمة المفتاح */
function verifyDeviceSignature({ pubkey, signature, code, deviceId, nonce }) {
  if (!pubkey || !signature || !nonce) return { ok: false, error: 'missing_signature' };
  if (!verifyNonce(nonce)) return { ok: false, error: 'bad_nonce' };

  let key;
  try {
    key = crypto.createPublicKey({
      key: Buffer.from(pubkey, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return { ok: false, error: 'bad_pubkey' };
  }
  if (key.asymmetricKeyType !== 'ec') return { ok: false, error: 'bad_pubkey' };

  const sig = Buffer.from(signature, 'base64');

  /* الأكواد مختلطة الأحرف: نجرّب الصيغة كما أرسلها التطبيق ثم حاليها */
  const candidates = [...new Set([code, code.toUpperCase(), code.toLowerCase()])];
  let ok = false;
  for (const c of candidates) {
    try {
      const msg = Buffer.from(`${c}|${deviceId}|${nonce}`, 'utf8');
      if (crypto.verify('sha256', msg, { key, dsaEncoding: 'der' }, sig)) { ok = true; break; }
    } catch {
      ok = false;
    }
  }
  if (!ok) return { ok: false, error: 'bad_signature' };

  const fingerprint = crypto
    .createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex')
    .slice(0, 32);

  return { ok: true, fingerprint };
}

const nonceLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
});

/* --- التطبيق يطلب nonce قبل التوقيع --- */
app.get('/api/nonce', nonceLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ nonce: issueNonce(), ttl: 120 });
});

/* ==========================================================================
 * 10) التحقق من الكود (يستدعيه التطبيق)
 * ========================================================================== */

app.post('/api/verify', verifyLimiter, (req, res) => {
  const body = req.body || {};
  const code = typeof body.code === 'string' ? body.code.trim() : '';
  const deviceId = typeof body.device_id === 'string' ? body.device_id.trim() : '';
  const ip = clientIp(req);

  if (!code || !deviceId) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'missing_params' });
    return res.json({ valid: false, reason: 'missing_params' });
  }
  if (!CODE_RE.test(code)) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'invalid_code_format' });
    return res.json({ valid: false, reason: 'invalid_code_format' });
  }
  if (!DEVICE_RE.test(deviceId)) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'invalid_device_id' });
    return res.json({ valid: false, reason: 'invalid_device_id' });
  }

  /* === ربط تشفيري (اختياري لكنه مُفعّل في التطبيق المحمي) === */
  const pubkey = typeof body.pubkey === 'string' ? body.pubkey.trim() : '';
  const signature = typeof body.signature === 'string' ? body.signature.trim() : '';
  const nonce = typeof body.nonce === 'string' ? body.nonce.trim() : '';
  let fingerprint = null;

  if (pubkey || signature) {
    const v = verifyDeviceSignature({ pubkey, signature, code, deviceId, nonce });
    if (!v.ok) {
      recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: v.error });
      return res.status(400).json({ valid: false, reason: v.error });
    }
    fingerprint = v.fingerprint;
  }

  // COLLATE NOCASE: الأكواد مختلطة الأحرف (Nacer-a1B2-...) فلا نجبر حالة واحدة
  const row = db.prepare('SELECT * FROM codes WHERE code = ? COLLATE NOCASE').get(code);
  if (!row) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'code_not_found' });
    return res.json({ valid: false, reason: 'code_not_found' });
  }
  if (!row.is_active) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'code_disabled' });
    return res.json({ valid: false, reason: 'code_disabled' });
  }
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'code_expired' });
    return res.json({ valid: false, reason: 'code_expired' });
  }

  const act = db
    .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ?')
    .get(row.id, deviceId);

  if (act) {
    if (act.revoked_at) {
      recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'revoked' });
      return res.json({ valid: false, reason: 'revoked' });
    }
    if (new Date(act.expires_at) < new Date()) {
      recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'expired' });
      return res.json({ valid: false, reason: 'expired' });
    }

    /* === التحقق من مطابقة مفتاح الجهاز === */
    if (act.pubkey) {
      if (!fingerprint) {
        recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'signature_required' });
        return res.status(401).json({ valid: false, reason: 'signature_required' });
      }
      if (act.pubkey !== fingerprint) {
        recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'device_key_mismatch' });
        return res.status(403).json({ valid: false, reason: 'device_key_mismatch' });
      }
    } else if (fingerprint) {
      // ترقية التفعيل القديم ليرتبط بالمفتاح
      db.prepare('UPDATE activations SET pubkey = ?, attested = 1 WHERE id = ?').run(
        fingerprint,
        act.id
      );
    }

    db.prepare('UPDATE activations SET last_seen_at = ? WHERE id = ?').run(
      new Date().toISOString(),
      act.id
    );

    const token = jwt.sign(
      { role: 'user', code_id: row.id, device_id: deviceId },
      USER_JWT_SECRET,
      { expiresIn: USER_TOKEN_TTL }
    );
    recordAttempt('verify', { code, deviceId, ip, ok: 1, reason: 'reused' });
    return res.json({
      valid: true,
      expires_at: act.expires_at,
      plan: row.plan || 'PRO',
      token,
    });
  }

  // عدد الأجهزة = التفعيلات غير المُبطلة فقط
  const used = db
    .prepare('SELECT COUNT(*) AS c FROM activations WHERE code_id = ? AND revoked_at IS NULL')
    .get(row.id).c;

  if (used >= row.max_devices) {
    recordAttempt('verify', { code, deviceId, ip, ok: 0, reason: 'max_devices_reached' });
    // سياسة (ج): نُخبر التطبيق أنه يستطيع تقديم طلب نقل بموافقة الأدمن
    const pending = db
      .prepare(
        "SELECT id FROM transfer_requests WHERE code_id = ? AND to_device_id = ? AND status = 'pending'"
      )
      .get(row.id, deviceId);
    return res.json({
      valid: false,
      reason: 'max_devices_reached',
      can_request_transfer: true,
      transfer_status: pending ? 'pending' : 'none',
      transfer_request_id: pending ? pending.id : null,
    });
  }

  const expiresAt =
    row.duration_hours === 0
      ? new Date('9999-12-31').toISOString()
      : new Date(Date.now() + row.duration_hours * 3600 * 1000).toISOString();

  db.prepare(
    'INSERT INTO activations (code_id, device_id, expires_at, last_seen_at, pubkey, attested) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(
    row.id,
    deviceId,
    expiresAt,
    new Date().toISOString(),
    fingerprint || null,
    fingerprint ? 1 : 0
  );

  const token = jwt.sign(
    { role: 'user', code_id: row.id, device_id: deviceId },
    USER_JWT_SECRET,
    { expiresIn: USER_TOKEN_TTL }
  );

  recordAttempt('verify', { code, deviceId, ip, ok: 1, reason: 'activated' });
  res.json({ valid: true, expires_at: expiresAt, plan: row.plan || 'PRO', token });
});

/* ==========================================================================
 * 11) رابطة الاشتراك
 * ========================================================================== */

app.get('/api/sub', subLimiter, (req, res) => {
  const token = readBearer(req);
  if (!token) return res.status(401).json({ error: 'no_token' });

  let decoded;
  try {
    decoded = jwt.verify(token, USER_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ error: 'invalid_or_expired_token' });
  }

  if (!decoded || decoded.role !== 'user') return res.status(403).json({ error: 'forbidden' });

  const act = db
    .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ?')
    .get(decoded.code_id, decoded.device_id);

  if (!act) return res.status(403).json({ error: 'no_activation' });
  if (act.revoked_at) return res.status(403).json({ error: 'revoked' });
  if (new Date(act.expires_at) < new Date()) return res.status(403).json({ error: 'expired' });

  db.prepare('UPDATE activations SET last_seen_at = ? WHERE id = ?').run(
    new Date().toISOString(),
    act.id
  );

  res.json({ link: SUB_LINK });
});

/* ==========================================================================
 * 12) نبضة الحياة — تُبطل الجلسة فور إبطال التفعيل من اللوحة
 * ========================================================================== */

app.post('/api/heartbeat', subLimiter, (req, res) => {
  const token = readBearer(req);
  if (!token) return res.status(401).json({ error: 'no_token' });

  let decoded;
  try {
    decoded = jwt.verify(token, USER_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ error: 'invalid_or_expired_token' });
  }
  if (!decoded || decoded.role !== 'user') return res.status(403).json({ error: 'forbidden' });

  const act = db
    .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ?')
    .get(decoded.code_id, decoded.device_id);

  if (!act) return res.json({ valid: false, reason: 'no_activation' });
  if (act.revoked_at) return res.json({ valid: false, reason: 'revoked' });
  if (new Date(act.expires_at) < new Date()) return res.json({ valid: false, reason: 'expired' });

  db.prepare('UPDATE activations SET last_seen_at = ? WHERE id = ?').run(
    new Date().toISOString(),
    act.id
  );

  res.json({ valid: true, expires_at: act.expires_at });
});

/* ==========================================================================
 * 12.5) نقل المفتاح إلى جهاز جديد — سياسة (ج): بموافقة الأدمن
 * ==========================================================================
 *  الفكرة:
 *   1. المستخدم على جهازه الجديد يفتح التطبيق → /api/verify يفشل بـ max_devices_reached
 *      ويُعاد معه can_request_transfer: true
 *   2. التطبيق يستدعي POST /api/transfer/request بالكود + معرّف الجهاز الجديد + سبب
 *   3. الطلب يظهر للأدمن في صفحة transfer-requests.html
 *   4. الأدمن يوافق → كل الأجهزة القديمة تُبطَل (revoked_at) والجهاز الجديد يُفعّل
 *   5. المستخدم يستدعي /api/verify مرة أخرى فينجح
 * ========================================================================== */

/** استخراج التوكن والتحقق منه — يُعيد {decoded} أو يرسل الخطأ */
function requireUserToken(req, res) {
  const token = readBearer(req);
  if (!token) {
    res.status(401).json({ error: 'no_token' });
    return null;
  }
  let decoded;
  try {
    decoded = jwt.verify(token, USER_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    res.status(401).json({ error: 'invalid_or_expired_token' });
    return null;
  }
  if (!decoded || decoded.role !== 'user') {
    res.status(403).json({ error: 'forbidden' });
    return null;
  }
  return decoded;
}

/* --- نبضة الجلسة: التحقق من أن التفعيل ما زال ساريًا على هذا الجهاز ---
   يُستخدم من واجهة التفعيل (ui/index.html) كل دقيقتين، ومن التطبيق عند الإقلاع. */
app.post('/api/session', subLimiter, (req, res) => {
  const body = req.body || {};
  const token = typeof body.token === 'string' ? body.token.trim() : '';
  const deviceId = typeof body.device_id === 'string' ? body.device_id.trim() : '';

  if (!token) return res.status(401).json({ valid: false, error: 'no_token' });

  let decoded;
  try {
    decoded = jwt.verify(token, USER_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ valid: false, error: 'invalid_or_expired_token' });
  }
  if (!decoded || decoded.role !== 'user') {
    return res.status(403).json({ valid: false, error: 'forbidden' });
  }

  const codeId = Number(decoded.code_id);
  const code = String(decoded.code || '');
  const row = Number.isFinite(codeId) && codeId > 0
    ? db.prepare('SELECT * FROM codes WHERE id = ?').get(codeId)
    : db.prepare('SELECT * FROM codes WHERE code = ? COLLATE NOCASE').get(code);
  if (!row) return res.status(401).json({ valid: false, reason: 'code_not_found' });
  if (!row.is_active) return res.status(403).json({ valid: false, reason: 'code_disabled' });
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    return res.status(403).json({ valid: false, reason: 'expired' });
  }

  let act = null;
  if (deviceId) {
    act = db
      .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ? AND revoked_at IS NULL')
      .get(row.id, deviceId);
    if (!act) return res.status(403).json({ valid: false, reason: 'revoked' });
    if (new Date(act.expires_at) < new Date()) {
      return res.status(403).json({ valid: false, reason: 'expired' });
    }

    /* === إن كان التفعيل مربوطاً بمفتاح جهاز، فالتوقيع إلزامي === */
    if (act.pubkey) {
      const v = verifyDeviceSignature({
        pubkey: typeof body.pubkey === 'string' ? body.pubkey.trim() : '',
        signature: typeof body.signature === 'string' ? body.signature.trim() : '',
        code: row.code,
        deviceId,
        nonce: typeof body.nonce === 'string' ? body.nonce.trim() : '',
      });
      if (!v.ok) {
        return res.status(401).json({ valid: false, reason: v.error });
      }
      if (v.fingerprint !== act.pubkey) {
        return res.status(403).json({ valid: false, reason: 'device_key_mismatch' });
      }
    }
  }

  return res.json({
    valid: true,
    plan: row.plan || 'PRO',
    expires_at: (act && act.expires_at) || row.expires_at || null,
    server_time: new Date().toISOString(),
  });
});

/* --- المستخدم يطلب نقل مفتاحه إلى جهاز جديد --- */
app.post('/api/transfer/request', subLimiter, (req, res) => {
  const body = req.body || {};
  const code = typeof body.code === 'string' ? body.code.trim() : '';
  const toDeviceId = typeof body.device_id === 'string' ? body.device_id.trim() : '';
  const reason = typeof body.reason === 'string' ? body.reason.trim().slice(0, 300) : '';
  const ip = clientIp(req);

  if (!code || !toDeviceId) {
    recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 0, reason: 'missing_params' });
    return res.status(400).json({ error: 'missing_params' });
  }
  if (!CODE_RE.test(code) || !DEVICE_RE.test(toDeviceId)) {
    recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 0, reason: 'invalid_format' });
    return res.status(400).json({ error: 'invalid_format' });
  }

  const row = db.prepare('SELECT * FROM codes WHERE code = ? COLLATE NOCASE').get(code);
  if (!row) {
    recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 0, reason: 'code_not_found' });
    return res.status(404).json({ error: 'code_not_found' });
  }
  if (!row.is_active) {
    recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 0, reason: 'code_disabled' });
    return res.status(403).json({ error: 'code_disabled' });
  }
  if (row.expires_at && new Date(row.expires_at) < new Date()) {
    recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 0, reason: 'code_expired' });
    return res.status(403).json({ error: 'code_expired' });
  }

  // الجهاز الجديد مُفعّل أصلاً؟ لا حاجة لطلب
  const already = db
    .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ? AND revoked_at IS NULL')
    .get(row.id, toDeviceId);
  if (already) {
    return res.json({ ok: true, status: 'already_active' });
  }

  // طلب معلّق لنفس الجهاز؟ لا نُكرّره
  const dup = db
    .prepare(
      "SELECT * FROM transfer_requests WHERE code_id = ? AND to_device_id = ? AND status = 'pending'"
    )
    .get(row.id, toDeviceId);
  if (dup) {
    return res.json({ ok: true, status: 'pending', request_id: dup.id });
  }

  const fromDevice = db
    .prepare('SELECT device_id FROM activations WHERE code_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1')
    .get(row.id);

  const info = db
    .prepare(
      'INSERT INTO transfer_requests (code_id, from_device_id, to_device_id, reason) VALUES (?, ?, ?, ?)'
    )
    .run(row.id, fromDevice?.device_id || null, toDeviceId, reason || null);

  recordAttempt('transfer_request', { code, deviceId: toDeviceId, ip, ok: 1, reason: 'created' });
  res.json({ ok: true, status: 'pending', request_id: info.lastInsertRowid });
});

/* --- المستخدم يتابع حالة طلبه --- */
app.get('/api/transfer/status', subLimiter, (req, res) => {
  const code = typeof req.query.code === 'string' ? req.query.code.trim() : '';
  const deviceId = typeof req.query.device_id === 'string' ? req.query.device_id.trim() : '';
  if (!code || !deviceId) return res.status(400).json({ error: 'missing_params' });

  const row = db.prepare('SELECT id FROM codes WHERE code = ? COLLATE NOCASE').get(code);
  if (!row) return res.status(404).json({ error: 'code_not_found' });

  const tr = db
    .prepare(
      'SELECT id, status, created_at, resolved_at FROM transfer_requests WHERE code_id = ? AND to_device_id = ? ORDER BY id DESC LIMIT 1'
    )
    .get(row.id, deviceId);

  if (!tr) return res.json({ status: 'none' });
  res.json(tr);
});

/* ==========================================================================
 * 13) لوحة التحكم — نفس المسارات ونفس شكل الردود تماماً
 * ========================================================================== */

function parseId(raw) {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/* --- إنشاء أكواد --- */
app.post('/api/admin/codes', adminLimiter, adminAuth, (req, res) => {
  const body = req.body || {};

  const durationHours = Number(body.duration_hours);
  const maxDevices = body.max_devices === undefined ? 1 : Number(body.max_devices);
  const count = body.count === undefined ? 1 : Number(body.count);
  const note = typeof body.note === 'string' ? body.note.slice(0, 200) : '';

  if (!Number.isFinite(durationHours) || durationHours < 0 || durationHours > 876000) {
    return res.status(400).json({ error: 'invalid_duration' });
  }
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 1000) {
    return res.status(400).json({ error: 'invalid_max_devices' });
  }
  if (!Number.isInteger(count) || count < 1 || count > 200) {
    return res.status(400).json({ error: 'invalid_count' });
  }

  const stmt = db.prepare(
    'INSERT INTO codes (code, duration_hours, max_devices, note) VALUES (?, ?, ?, ?)'
  );

  const created = [];
  const insertMany = db.transaction(() => {
    for (let i = 0; i < count; i++) {
      let code;
      let tries = 0;
      // ضمان عدم التكرار (UNIQUE) بدل الاعتماد على الحظ
      do {
        code =
          'Nacer-' +
          crypto.randomBytes(2).toString('hex').toUpperCase() +
          '-' +
          crypto.randomBytes(2).toString('hex').toUpperCase() +
          '-' +
          crypto.randomBytes(2).toString('hex').toUpperCase();
        tries++;
      } while (tries < 10 && db.prepare('SELECT 1 FROM codes WHERE code = ?').get(code));
      stmt.run(code, durationHours, maxDevices, note);
      created.push(code);
    }
  });

  try {
    insertMany();
  } catch (e) {
    console.error('create codes failed:', e.message);
    return res.status(500).json({ error: 'insert_failed' });
  }

  res.json({ created });
});

/* --- قراءة الأكواد (نفس أعمدة اللوحة + used) --- */
app.get('/api/admin/codes', adminLimiter, adminAuth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT c.*,
              (SELECT COUNT(*) FROM activations a
                 WHERE a.code_id = c.id AND a.revoked_at IS NULL) AS used
         FROM codes c
        ORDER BY c.id DESC`
    )
    .all();
  res.json(rows);
});

/* --- تفعيلات كود معيّن --- */
app.get('/api/admin/codes/:id/activations', adminLimiter, adminAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const rows = db.prepare('SELECT * FROM activations WHERE code_id = ? ORDER BY id DESC').all(id);
  res.json(rows);
});

/* --- إعادة تعيين الأجهزة (اللوحة تستدعي DELETE) ---
 * نُسجّل هذا المسار قبل /:id لضمان الأولوية بغض النظر عن ترتيب المطابقة.
 */
function resetDevices(req, res) {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const info = db.prepare('DELETE FROM activations WHERE code_id = ?').run(id);
  res.json({ ok: true, removed: info.changes });
}
app.delete('/api/admin/codes/:id/reset', adminLimiter, adminAuth, resetDevices);
app.post('/api/admin/codes/:id/reset', adminLimiter, adminAuth, resetDevices);

/* --- حذف كود --- */
app.delete('/api/admin/codes/:id', adminLimiter, adminAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const del = db.transaction(() => {
    db.prepare('DELETE FROM activations WHERE code_id = ?').run(id);
    return db.prepare('DELETE FROM codes WHERE id = ?').run(id);
  });

  const info = del();
  if (info.changes === 0) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

/* --- تفعيل/تعطيل كود --- */
app.patch('/api/admin/codes/:id', adminLimiter, adminAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const info = db
    .prepare('UPDATE codes SET is_active = ? WHERE id = ?')
    .run(req.body?.is_active ? 1 : 0, id);

  if (info.changes === 0) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

/* --- سجل المحاولات --- */
app.get('/api/admin/attempts', adminLimiter, adminAuth, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  const rows = db.prepare('SELECT * FROM attempts ORDER BY id DESC LIMIT ?').all(limit);
  res.json(rows);
});

/* ==========================================================================
 * 13.5) إدارة طلبات نقل المفتاح — للأدمن (صفحة transfer-requests.html)
 * ========================================================================== */

/* --- قائمة الطلبات (افتراضياً المعلّقة فقط) --- */
app.get('/api/admin/transfers', adminLimiter, adminAuth, (req, res) => {
  const status = typeof req.query.status === 'string' ? req.query.status : 'pending';
  const allowed = ['pending', 'approved', 'rejected', 'cancelled', 'all'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'invalid_status' });

  const base = `SELECT t.*, c.code AS code_text, c.max_devices, c.is_active,
                       (SELECT COUNT(*) FROM activations a
                          WHERE a.code_id = t.code_id AND a.revoked_at IS NULL) AS used
                  FROM transfer_requests t
                  JOIN codes c ON c.id = t.code_id`;
  const rows =
    status === 'all'
      ? db.prepare(`${base} ORDER BY t.id DESC LIMIT 500`).all()
      : db.prepare(`${base} WHERE t.status = ? ORDER BY t.id DESC LIMIT 500`).all(status);

  res.json(rows);
});

/* --- عدد الطلبات المعلّقة (شارة إشعار) --- */
app.get('/api/admin/transfers/count', adminLimiter, adminAuth, (req, res) => {
  const c = db
    .prepare("SELECT COUNT(*) AS c FROM transfer_requests WHERE status = 'pending'")
    .get().c;
  res.json({ pending: c });
});

/* --- موافقة: إبطال كل الأجهزة القديمة + تفعيل الجهاز الجديد --- */
app.post('/api/admin/transfers/:id/approve', adminLimiter, adminAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const tr = db.prepare('SELECT * FROM transfer_requests WHERE id = ?').get(id);
  if (!tr) return res.status(404).json({ error: 'not_found' });
  if (tr.status !== 'pending') return res.status(409).json({ error: 'already_resolved', status: tr.status });

  const code = db.prepare('SELECT * FROM codes WHERE id = ?').get(tr.code_id);
  if (!code) return res.status(404).json({ error: 'code_not_found' });

  const now = new Date().toISOString();
  const expiresAt =
    code.duration_hours === 0
      ? new Date('9999-12-31').toISOString()
      : new Date(Date.now() + code.duration_hours * 3600 * 1000).toISOString();

  const approve = db.transaction(() => {
    // إبطال كل التفعيلات الحالية
    db.prepare(
      'UPDATE activations SET revoked_at = ? WHERE code_id = ? AND revoked_at IS NULL'
    ).run(now, code.id);

    // تفعيل الجهاز الجديد (أو إعادة تفعيله إن كان موجوداً مُبطلاً)
    const existing = db
      .prepare('SELECT * FROM activations WHERE code_id = ? AND device_id = ?')
      .get(code.id, tr.to_device_id);

    if (existing) {
      db.prepare(
        'UPDATE activations SET revoked_at = NULL, expires_at = ?, last_seen_at = ? WHERE id = ?'
      ).run(expiresAt, now, existing.id);
    } else {
      db.prepare(
        'INSERT INTO activations (code_id, device_id, expires_at, last_seen_at) VALUES (?, ?, ?, ?)'
      ).run(code.id, tr.to_device_id, expiresAt, now);
    }

    db.prepare(
      "UPDATE transfer_requests SET status = 'approved', resolved_at = ?, resolved_by = 'admin' WHERE id = ?"
    ).run(now, id);

    // إلغاء أي طلبات معلّقة أخرى لنفس المفتاح
    db.prepare(
      "UPDATE transfer_requests SET status = 'cancelled', resolved_at = ?, resolved_by = 'auto' WHERE code_id = ? AND status = 'pending' AND id != ?"
    ).run(now, code.id, id);
  });

  approve();
  recordAttempt('transfer_approve', { code: code.code, deviceId: tr.to_device_id, ip: clientIp(req), ok: 1, reason: 'approved' });
  res.json({ ok: true, expires_at: expiresAt });
});

/* --- رفض --- */
app.post('/api/admin/transfers/:id/reject', adminLimiter, adminAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const tr = db.prepare('SELECT * FROM transfer_requests WHERE id = ?').get(id);
  if (!tr) return res.status(404).json({ error: 'not_found' });
  if (tr.status !== 'pending') return res.status(409).json({ error: 'already_resolved', status: tr.status });

  db.prepare(
    "UPDATE transfer_requests SET status = 'rejected', resolved_at = ?, resolved_by = 'admin' WHERE id = ?"
  ).run(new Date().toISOString(), id);

  res.json({ ok: true });
});

/* ==========================================================================
 * 14) 404 + معالج أخطاء (لا يكشف stack traces)
 * ========================================================================== */

app.use((req, res) => res.status(404).json({ error: 'not_found' }));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid_json' });
  }
  console.error('Unhandled error:', err?.message);
  res.status(500).json({ error: 'internal_error' });
});

/* ==========================================================================
 * 15) الإقلاع
 * ========================================================================== */

const server = app.listen(PORT, () => {
  console.log(`✅ Server on port ${PORT}`);
  console.log(`   DB: ${DB_PATH}`);
  console.log(`   CORS: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : 'ALL'}`);
  if (ADMIN_JWT_SECRET === USER_JWT_SECRET) {
    console.log('   ⚠️  مفتاح توقيع واحد للمدير والمستخدم — يُفضّل فصلهما.');
  }
});

function shutdown(sig) {
  console.log(`\n${sig} — إغلاق آمن…`);
  server.close(() => {
    try {
      db.close();
    } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
