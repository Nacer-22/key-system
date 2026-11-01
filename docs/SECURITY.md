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

---

# 📱 إضافة: نقل المفتاح إلى جهاز جديد — سياسة (ج)

## القرار
المفتاح **لا يُنقل تلقائياً** ولا يُقفل نهائياً. العميل يطلب النقل من التطبيق،
وأنت توافق أو ترفض من صفحة `transfer-requests.html`. عند الموافقة تُلغى كل
الأجهزة القديمة تلقائياً ويُفعّل الجهاز الجديد فوراً.

## كيف يعمل من البداية للنهاية

| الخطوة | الطرف | ما يحدث |
|--------|-------|---------|
| 1 | التطبيق | `POST /api/verify` بكود المفتاح ومعرّف الجهاز الجديد |
| 2 | السيرفر | يرد `{ valid:false, reason:'max_devices_reached', can_request_transfer:true }` |
| 3 | التطبيق | يعرض زر «نقل إلى هذا الجهاز» ويستدعي `POST /api/transfer/request` |
| 4 | السيرفر | يُنشئ سجلاً في `transfer_requests` بحالة `pending` |
| 5 | أنت | تفتح `transfer-requests.html` فترى الطلب مع سبب العميل |
| 6 | أنت | تضغط «موافقة» → كل الأجهزة القديمة `revoked_at` + تفعيل الجديد |
| 7 | التطبيق | يستدعي `/api/verify` مرة أخرى → `valid:true` |

## نقاط النهاية الجديدة

### للمستخدم (بلا توكن — الكود نفسه هو الإثبات)
```
POST /api/transfer/request
  body: { code, device_id, reason? }
  → { ok:true, status:'pending', request_id }
  → { ok:true, status:'already_active' }   // الجهاز مُفعّل أصلاً
  → { ok:true, status:'pending', request_id } // طلب مكرر، لا تكرار

GET /api/transfer/status?code=...&device_id=...
  → { id, status, created_at, resolved_at }
  → { status:'none' }
```

### للأدمن (توكن الأدمن)
```
GET  /api/admin/transfers?status=pending|approved|rejected|cancelled|all
GET  /api/admin/transfers/count          → { pending: N }
POST /api/admin/transfers/:id/approve    → { ok:true, expires_at }
POST /api/admin/transfers/:id/reject     → { ok:true }
```

## ضمانات الأمان
- `approve` تعمل داخل **معاملة واحدة** (`db.transaction`) — لا حالة وسطى.
- لا يمكن الموافقة مرتين → `409 already_resolved`.
- الموافقة على طلب واحد **تُلغي تلقائياً** كل الطلبات المعلّقة الأخرى لنفس المفتاح.
- توكن المستخدم **لا يستطيع** الوصول لنقاط نهاية الأدمن (مفتاح توقيع مختلف → 401).
- كل طلب وموافقة تُسجَّل في جدول `attempts`.
- الطلب المكرر لنفس الجهاز لا يُنشئ سجلاً جديداً (لا إغراق).

## صفحة الموافقة
`transfer-requests.html` — ملف **مستقل تماماً**، لم يُلمس `dashboard.html`.
تستخدم نفس كلمة مرور الأدمن ونفس التوكن المحفوظ في `localStorage`.
تحديث تلقائي كل 45 ثانية عند وجود طلبات معلّقة.

## الاختبارات
`test/transfer.test.js` — 22 تأكيداً، جميعها ناجحة:
```
✅ تفعيل الجهاز الأول
✅ الجهاز الثاني مرفوض + can_request_transfer
✅ إنشاء طلب نقل
✅ الطلب المكرر لا يُضاعف
✅ توكن المستخدم لا يرى طلبات النقل
✅ موافقة الأدمن
✅ الجهاز القديم مُبطل
✅ الجهاز الجديد مُفعّل
✅ لا موافقة مزدوجة
✅ المرفوض لا يُفعّل الجهاز
✅ dashboard.html → 200 ولم تُعدّل
```

---

## 🩹 الإصدار 2.2.0 — «أي كود من اللوحة يعمل على التطبيق»

### 1) إصلاح «الخادم مشغول حالياً» بعد إدخال كود صحيح
**السبب:** `verifyLimiter` كان يعدّ **كل** طلب `/api/verify` — بما فيها الطلبات الناجحة — داخل نافذة 15 دقيقة (30 في هذا المستودع، و15 في النسخة المنشورة). التطبيق يتحقق عند كل فتح، فبعد عدة فتحات كان الخادم يرد `429` فيظهر «الخادم مشغول حالياً» رغم صحة الكود.

**الحل:**
```js
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,                       // محاولات *فاشلة* فقط
  skipSuccessfulRequests: true,
  requestWasSuccessful: (req, res) => Boolean(res.locals && res.locals.verifyOk === true),
});
```
- التفعيل الناجح لا يستهلك الحصة أبداً (`res.locals.verifyOk = true` عند `valid:true` فقط).
- المحاولات الفاشلة ما زالت محدودة (300/15د لكل IP) → الحماية من التخمين قائمة.

### 2) الربط التشفيري للجهاز أصبح اختيارياً
`REQUIRE_SIGNATURE` (افتراضياً `false`):
- `false` → إذا كان التفعيل القديم مربوطاً بمفتاح جهاز، يُقبل الكود الصحيح حتى لو لم يوقّع التطبيق (بدل `401 signature_required`).
- `true` → السلوك المتحصّن القديم (رفض أي طلب غير موقّع).
- التوقيع الخاطئ/المفتاح المختلف يُرفض دائماً (`device_key_mismatch`).

### 3) تطبيع الكود (`normCode`) + بحث متسامح (`findCodeRow`)
إزالة المسافات والمحارف غير المرئية (`U+200B..200D`, `U+2060`, `U+FEFF`, `U+00A0`) وأي مسافة داخلية قبل المطابقة، في `/api/verify` و`/api/transfer/request` و`/api/transfer/status`. الكود يُطابق أيضاً بغض النظر عن حالة الأحرف (`COLLATE NOCASE`)، وإن لم يوجد تُجرَّب مطابقة بعد تجاهل الفواصل `-` و`_` — فيعمل `NACERF1CE51470789` مثل `Nacer-F1CE-5147-0789`.

### 4) فحص الإصدار
`GET /api/health` يعيد الآن `{ ok, uptime, version: "2.2.0", require_signature }` للتأكد من أن النشر الجديد هو المُشغَّل فعلاً.

### متغيّر بيئة جديد
| المتغيّر | إلزامي | الافتراضي | الوصف |
|---|---|---|---|
| `REQUIRE_SIGNATURE` | ❌ | `false` | إجبار توقيع الجهاز ECDSA. اتركه `false` ليعمل أي كود على أي نسخة من التطبيق. |
