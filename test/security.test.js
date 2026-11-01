/**
 * اختبارات أمنية — سيرفر مفاتيح Nacer_22
 * التشغيل:  npm test        (يتطلب سيرفراً يعمل على PORT)
 * أو:       BASE=http://127.0.0.1:3999 npm test
 */

'use strict';

const BASE = process.env.BASE || `http://127.0.0.1:${process.env.PORT || 3999}`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'NacerStrongPass123!';

let pass = 0;
let fail = 0;

function ok(name, cond, extra = '') {
  if (cond) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    console.log(`  ❌ ${name} ${extra}`);
  }
}

function section(title) {
  console.log(`\n=== ${title} ===`);
}

async function req(path, { method = 'GET', body, token, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (token) h['Authorization'] = `Bearer ${token}`;

  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, text, json, headers: res.headers };
}

async function main() {
  console.log(`\n🔍 اختبار ${BASE}`);

  /* ---------------------------------------------------------------- */
  section('1) لا يمكن تحميل الملفات الحساسة');

  for (const p of ['/keys.db', '/keys.db-wal', '/server.js', '/package.json', '/.env', '/node_modules/express/package.json']) {
    const r = await req(p);
    ok(`GET ${p} مرفوض`, r.status === 404 || r.status === 403, `→ HTTP ${r.status}`);
  }

  /* ---------------------------------------------------------------- */
  section('2) لوحة التحكم ما زالت تُخدم كما هي');

  const dash = await req('/dashboard.html');
  ok('GET /dashboard.html → 200', dash.status === 200, `→ HTTP ${dash.status}`);
  ok('لوحة التحكم لم تُعدّل (تحتوي عنوانها الأصلي)', dash.text.includes('لوحة التحكم · Nacer_22'));

  const asset = await req('/assets/logo.png');
  ok('GET /assets/logo.png → 200', asset.status === 200, `→ HTTP ${asset.status}`);

  /* ---------------------------------------------------------------- */
  section('3) دخول المدير');

  const bad = await req('/api/admin/login', { method: 'POST', body: { password: 'wrong-password' } });
  ok('كلمة مرور خاطئة تُرفض', bad.status === 401, `→ HTTP ${bad.status}`);

  const empty = await req('/api/admin/login', { method: 'POST', body: {} });
  ok('طلب بلا كلمة مرور يُرفض', empty.status === 401, `→ HTTP ${empty.status}`);

  const good = await req('/api/admin/login', { method: 'POST', body: { password: ADMIN_PASSWORD } });
  ok('كلمة المرور الصحيحة تُقبل', good.status === 200 && !!good.json?.token);
  const adminToken = good.json?.token;
  if (!adminToken) throw new Error('لا يمكن المتابعة بدون توكن مدير');

  /* ---------------------------------------------------------------- */
  section('4) إنشاء مفاتيح');

  const created = await req('/api/admin/codes', {
    method: 'POST',
    token: adminToken,
    body: { duration_hours: 24, max_devices: 1, count: 2, note: 'اختبار' },
  });
  ok('إنشاء مفتاحين', created.status === 200 && created.json?.created?.length === 2);
  const code = created.json?.created?.[0];
  ok('صيغة المفتاح الموقّع NACER-EXP-DEV-RAND-SIG', /^NACER-[0-9A-Z]{8}-[0-9A-Z]{2}-[0-9A-Z]{3}-[0-9A-Z]{8}$/.test(code || ''));

  const list = await req('/api/admin/codes', { token: adminToken });
  ok('قراءة قائمة المفاتيح', list.status === 200 && Array.isArray(list.json));
  ok('الحقل used موجود (تحتاجه اللوحة)', list.json?.[0] && 'used' in list.json[0]);

  /* ---------------------------------------------------------------- */
  section('5) 🔴 الثغرة الحرجة: تصعيد الصلاحيات');

  const userVerify = await req('/api/verify', {
    method: 'POST',
    body: { code, device_id: 'device-aaaaaaaaaaaa' },
  });
  ok('تفعيل المفتاح ينجح', userVerify.status === 200 && userVerify.json?.valid === true);
  const userToken = userVerify.json?.token;

  const esc1 = await req('/api/admin/codes', { token: userToken });
  ok('توكن المستخدم لا يقرأ لوحة التحكم', esc1.status === 401 || esc1.status === 403, `→ HTTP ${esc1.status}`);

  const esc2 = await req('/api/admin/codes', {
    method: 'POST',
    token: userToken,
    body: { duration_hours: 999999, count: 10 },
  });
  ok('توكن المستخدم لا ينشئ مفاتيح', esc2.status === 401 || esc2.status === 403, `→ HTTP ${esc2.status}`);

  const esc3 = await req('/api/admin/attempts', { token: userToken });
  ok('توكن المستخدم لا يقرأ سجل المحاولات', esc3.status === 401 || esc3.status === 403, `→ HTTP ${esc3.status}`);

  const esc4 = await req('/api/admin/codes', { token: 'garbage.token.here' });
  ok('توكن مُلفّق يُرفض', esc4.status === 401 || esc4.status === 403, `→ HTTP ${esc4.status}`);

  const esc5 = await req('/api/admin/codes');
  ok('بلا توكن → مرفوض', esc5.status === 401 || esc5.status === 403, `→ HTTP ${esc5.status}`);

  /* ---------------------------------------------------------------- */
  section('6) حدود الأجهزة');

  const dev2 = await req('/api/verify', {
    method: 'POST',
    body: { code, device_id: 'device-bbbbbbbbbbbb' },
  });
  ok('جهاز ثانٍ مرفوض عند max_devices=1', dev2.json?.valid === false && dev2.json?.reason === 'max_devices_reached');

  const dev1again = await req('/api/verify', {
    method: 'POST',
    body: { code, device_id: 'device-aaaaaaaaaaaa' },
  });
  ok('نفس الجهاز يعيد التفعيل بنجاح', dev1again.json?.valid === true);

  const lower = await req('/api/verify', {
    method: 'POST',
    body: { code: code.toLowerCase(), device_id: 'device-aaaaaaaaaaaa' },
  });
  ok('الكود غير حسّاس لحالة الأحرف', lower.json?.valid === true);

  /* ---------------------------------------------------------------- */
  section('7) رابطة الاشتراك ونبضة الحياة');

  const sub = await req('/api/sub', { token: userToken });
  ok('رابط الاشتراك متاح للمستخدم المفعّل', sub.status === 200 && !!sub.json?.link);

  const subNo = await req('/api/sub');
  ok('رابط الاشتراك مرفوض بلا توكن', subNo.status === 401);

  const subAdmin = await req('/api/sub', { token: adminToken });
  ok('توكن المدير لا يصل إلى نقطة المستخدم', subAdmin.status === 401 || subAdmin.status === 403);

  const hb = await req('/api/heartbeat', { method: 'POST', token: userToken });
  ok('نبضة الحياة تعمل', hb.status === 200 && hb.json?.valid === true);

  /* ---------------------------------------------------------------- */
  section('8) تحقق المدخلات');

  const badDur = await req('/api/admin/codes', {
    method: 'POST',
    token: adminToken,
    body: { duration_hours: -5, count: 1 },
  });
  ok('مدة سالبة مرفوضة', badDur.status === 400, `→ HTTP ${badDur.status}`);

  const badCount = await req('/api/admin/codes', {
    method: 'POST',
    token: adminToken,
    body: { duration_hours: 24, count: 5000 },
  });
  ok('عدد أكبر من 200 مرفوض', badCount.status === 400, `→ HTTP ${badCount.status}`);

  const shortCode = await req('/api/verify', { method: 'POST', body: { code: 'a', device_id: 'device-aaaaaaaaaaaa' } });
  ok('كود قصير/غير صالح مرفوض', shortCode.json?.reason === 'invalid_code_format');

  const badDev = await req('/api/verify', { method: 'POST', body: { code, device_id: 'x' } });
  ok('معرّف جهاز غير صالح مرفوض', badDev.json?.reason === 'invalid_device_id');

  /* ---------------------------------------------------------------- */
  section('9) سجل المحاولات');

  const att = await req('/api/admin/attempts?limit=50', { token: adminToken });
  ok('سجل المحاولات يعمل', att.status === 200 && Array.isArray(att.json) && att.json.length > 0);
  ok('السجل يسجّل محاولة دخول فاشلة', att.json?.some((a) => a.kind === 'admin_login' && a.ok === 0));

  /* ---------------------------------------------------------------- */
  section('10) إعادة تعيين الأجهزة (مسار اللوحة DELETE)');

  const id = list.json?.find((c) => c.code === code)?.id;
  const reset = await req(`/api/admin/codes/${id}/reset`, { method: 'DELETE', token: adminToken });
  ok('DELETE /api/admin/codes/:id/reset يعمل', reset.status === 200 && reset.json?.ok === true, `→ HTTP ${reset.status}`);

  const stillThere = await req('/api/admin/codes', { token: adminToken });
  ok('المفتاح نفسه لم يُحذف بعد إعادة التعيين', stillThere.json?.some((c) => c.id === id));

  const reVerify = await req('/api/verify', {
    method: 'POST',
    body: { code, device_id: 'device-cccccccccccc' },
  });
  ok('جهاز جديد يستطيع التفعيل بعد إعادة التعيين', reVerify.json?.valid === true);

  /* ---------------------------------------------------------------- */
  section('11) تعديل وحذف');

  const patch = await req(`/api/admin/codes/${id}`, {
    method: 'PATCH',
    token: adminToken,
    body: { is_active: false },
  });
  ok('PATCH تعطيل المفتاح', patch.status === 200 && patch.json?.ok === true);

  const disabled = await req('/api/verify', {
    method: 'POST',
    body: { code, device_id: 'device-cccccccccccc' },
  });
  ok('المفتاح المعطّل يرفض التفعيل', disabled.json?.reason === 'code_disabled');

  const del = await req(`/api/admin/codes/${id}`, { method: 'DELETE', token: adminToken });
  ok('DELETE حذف المفتاح', del.status === 200 && del.json?.ok === true);

  const gone = await req('/api/admin/codes', { token: adminToken });
  ok('المفتاح اختفى من القائمة', !gone.json?.some((c) => c.id === id));

  /* ---------------------------------------------------------------- */
  section('12) فحص الصحة');

  const health = await req('/api/health');
  ok('GET /api/health → ok', health.status === 200 && health.json?.ok === true);

  /* ---------------------------------------------------------------- */
  console.log('\n' + '='.repeat(50));
  console.log(`النتيجة: ${pass} ناجح / ${fail} فاشل`);
  console.log('='.repeat(50) + '\n');

  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('\n💥 فشل الاختبار:', e.message);
  process.exit(1);
});
