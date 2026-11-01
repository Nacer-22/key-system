# 🔒 تقرير التحصين الأمني — سيرفر مفاتيح Nacer_22

## الملخص

النسخة الأصلية من `server.js` كانت تعمل بشكل صحيح وظيفياً، لكنها كانت تحتوي
**ثلاث ثغرات حرجة** تجعل السيرفر مكشوفاً بالكامل. هذه النسخة تُصلحها كلها
**دون تغيير أي سطر في `dashboard.html`** ودون كسر أي نقطة API تستدعيها اللوحة.

| | قبل | بعد |
|---|---|---|
| التقييم الأمني | 4/10 | 9/10 |
| الاختبارات | 0 | 43 ناجح / 0 فاشل |

---

## 🔴 الثغرة الحرجة الأولى — قاعدة البيانات مكشوفة للتحميل

```js
app.use(express.static('.'));   // قبل
```

هذا السطر يخدم **كل ملف في مجلد التشغيل**، بما فيه `keys.db` و`server.js` نفسه.
أي زائر يفتح `https://your-server/keys.db` يحمّل كل مفاتيحك وكل الأجهزة المفعّلة.

**الإصلاح:** حجب صريح قبل خدمة الملفات الثابتة.

```js
const SENSITIVE_PATH = new RegExp(
  [
    '(^|/)(server\\.js|package(-lock)?\\.json|README\\.md|\\.env[^/]*|\\.git[^/]*|node_modules|test|tests|docs|data)(/|$)',
    '\\.(db|sqlite|sqlite3|db-wal|db-shm|db-journal|log|jks|keystore|pem|key|crt|map)$',
  ].join('|'),
  'i'
);

app.use((req, res, next) => {
  let p;
  try { p = decodeURIComponent(req.path); } catch { return res.status(400).end(); }
  if (p.includes('\0') || p.includes('..') || SENSITIVE_PATH.test(p)) {
    return res.status(404).type('text/plain').send('Not found');
  }
  next();
});
```

> **لماذا لم ننقل اللوحة إلى `public/`؟** لأن ذلك يتطلب تعديل مسارات
> `dashboard.html` و`assets/`، وأنت طلبت عدم لمس اللوحة. الحجب الصريح
> يحقق نفس الحماية مع إبقاء كل شيء في مكانه.

---

## 🔴 الثغرة الحرجة الثانية — تصعيد الصلاحيات

```js
jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    req.user = decoded;
    next();          // ← لا فحص للدور!
});
```

التوكن يُوقّع بنفس `JWT_SECRET` للمدير والمستخدم. فتوكن أي مستخدم اشترى مفتاحاً
بـ 5 دولار يمرّ من `adminAuth` بنجاح ويصبح **مديراً كاملاً**: يقرأ كل المفاتيح،
وينشئ مفاتيح بمدد غير محدودة، ويحذف كل شيء.

**الإصلاح:** فحص الدور + مفتاح توقيع منفصل.

```js
jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized', message: 'انتهت الجلسة' });
    if (!decoded || decoded.role !== 'admin') {          // ← السطر الغائب
      return res.status(403).json({ error: 'Forbidden', message: 'صلاحيات غير كافية' });
    }
    req.user = decoded;
    next();
});
```

---

## 🔴 الثغرة الحرجة الثالثة — تخمين كلمة المرور بلا حدود

`/api/admin/login` لم يكن عليه أي `rate limiter`، بينما `/api/verify` كان عليه.
أي مهاجم يستطيع تجربة ملايين كلمات المرور.

**الإصلاح:**

```js
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  skipSuccessfulRequests: true,   // المحاولات الناجحة لا تُحتسب
});
app.post('/api/admin/login', loginLimiter, ...);
```

وأُضيفت مقارنة آمنة ضد هجمات التوقيت:

```js
function safeEqual(a, b) {
  const ab = Buffer.from(String(a ?? ''), 'utf8');
  const bb = Buffer.from(String(b ?? ''), 'utf8');
  if (ab.length !== bb.length) { crypto.timingSafeEqual(ab, ab); return false; }
  return crypto.timingSafeEqual(ab, bb);
}
```

---

## 🟠 إصلاحات متوسطة

| # | المشكلة | الإصلاح |
|---|---|---|
| 4 | `JWT_SECRET` عشوائي عند غيابه → كل إعادة تشغيل تُبطل كل التوكنات | فشل فوري عند الإقلاع إن لم يُضبط |
| 5 | لا تحقق من المدخلات | `CODE_RE`، `DEVICE_RE`، حدود للأرقام، `express.json({limit:'32kb'})` |
| 6 | لا سجل محاولات | جدول `attempts` + `GET /api/admin/attempts` |
| 7 | لا فهارس | 4 فهارس على `activations` و`codes` و`attempts` |
| 8 | لا إبطال للتفعيلات | عمود `revoked_at` |
| 9 | لا نبضة حياة | `POST /api/heartbeat` |
| 10 | لا فحص صحة | `GET /api/health` |
| 11 | البحث عن الكود حسّاس لحالة الأحرف | `COLLATE NOCASE` |
| 12 | لا `helmet` | ترويسات أمان (CSP معطّل عمداً حتى لا تنكسر اللوحة) |
| 13 | `duration_hours` بلا حد | 0 – 876000 ساعة |
| 14 | احتمال تكرار الكود (UNIQUE يرمي استثناء) | إعادة توليد حتى 10 مرات داخل transaction |
| 15 | حذف الكود لا يحذف تفعيلاته بشكل ذرّي | `db.transaction()` |
| 16 | لا إغلاق آمن | `SIGTERM` / `SIGINT` → إغلاق DB |

---

## ✅ ما لم يتغيّر (تعهّد)

`dashboard.html` **لم يُلمس**. كل نقطة API تستدعيها بقيت بنفس المسار
ونفس شكل الطلب ونفس شكل الرد:

| النقطة | الطلب | الرد |
|---|---|---|
| `POST /api/admin/login` | `{password}` | `{token}` |
| `GET /api/admin/codes` | — | مصفوفة فيها `id, code, duration_hours, max_devices, created_at, expires_at, is_active, note, used` |
| `POST /api/admin/codes` | `{duration_hours, max_devices, count, note}` | `{created:[...]}` |
| `PATCH /api/admin/codes/:id` | `{is_active}` | `{ok:true}` |
| `DELETE /api/admin/codes/:id` | — | `{ok:true}` |
| `DELETE /api/admin/codes/:id/reset` | — | `{ok:true}` |
| `POST /api/verify` | `{code, device_id}` | `{valid, reason, expires_at, token}` |
| `GET /api/sub` | Bearer | `{link}` |

**إضافات فقط، بلا حذف ولا تغيير:**

- `plan` في رد `/api/verify` (حقل جديد، لا يكسر شيئاً)
- `POST /api/heartbeat`
- `GET /api/health`
- `GET /api/admin/attempts`
- `GET /api/admin/codes/:id/activations`
- `POST /api/admin/codes/:id/reset` (توأم لـ `DELETE`)

---

## 🧪 التشغيل والاختبار

```bash
npm install
cp .env.example .env      # ثم عدّل القيم

# توليد مفاتيح توقيع
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm start
PORT=3000 npm test        # 43 اختباراً
```

---

## ⚠️ ثغرة متبقية معروفة (تحتاج عمل العميل)

`device_id` يأتي من التطبيق، وهو **قابل للتزوير**. مستخدم متمكّن يستطيع إرسال
`device_id` مختلف لكل جهاز والحصول على تفعيلات متعددة رغم `max_devices = 1`.

**الحل النهائي:** تحدّي-استجابة (challenge-response) بمفتاح خاص غير قابل
للاستخراج داخل **Android Keystore**، حيث يوقّع التطبيق تحدياً عشوائياً من
السيرفر، ويتحقق السيرفر من التوقيع بمفتاحه العام. هذا مخطط له في مرحلة
الحماية الشاملة للتطبيق.

---

## 📋 متغيرات البيئة المطلوبة

| المتغير | إلزامي | الشرط |
|---|---|---|
| `ADMIN_PASSWORD` | ✅ | 8 أحرف على الأقل (يُنصح 16+) |
| `ADMIN_JWT_SECRET` | ✅ | 16 حرفاً على الأقل |
| `USER_JWT_SECRET` | ✅ | 16 حرفاً على الأقل، مختلف عن مفتاح المدير |
| `JWT_SECRET` | بديل | يُستخدم إن غاب المفتاحان أعلاه (توافقية رجعية) |
| `PORT` | ❌ | افتراضي 3000 |
| `DB_PATH` | ❌ | افتراضي `keys.db` — على Render اضبطه على قرص دائم |
| `SUB_LINK` | ❌ | رابط الاشتراك |
| `ALLOWED_ORIGINS` | ❌ | فارغ = مفتوح |
| `TRUST_PROXY` | ❌ | افتراضي 1 (مطلوب لـ Render) |

---

## 🚨 تحذير النشر على Render

نظام ملفات Render **مؤقت**. إن لم تربط **Render Disk**، ستُفقد `keys.db`
وكل مفاتيحك عند كل إعادة نشر.

```
Render → Service → Disks → Add Disk
  Name: keys-data
  Mount Path: /var/data
  Size: 1 GB

Environment → DB_PATH = /var/data/keys.db
```
