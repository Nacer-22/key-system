/**
 * اختبار الربط التشفيري للجهاز (ECDSA P-256 + nonce)
 * التشغيل:  BASE=http://127.0.0.1:4010 node test/crypto-binding.test.js
 */
const crypto = require('crypto');

const BASE = process.env.BASE || `http://127.0.0.1:${process.env.PORT || 3999}`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'NacerStrongPass123!';

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('✅ ' + name); }
  else { fail++; console.log('❌ ' + name + (extra ? ' → ' + JSON.stringify(extra) : '')); }
}

async function post(path, body, headers = {}) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  let d = null;
  try { d = await r.json(); } catch {}
  return { status: r.status, d };
}
async function get(path) {
  const r = await fetch(BASE + path);
  let d = null;
  try { d = await r.json(); } catch {}
  return { status: r.status, d };
}

(async () => {
  console.log('\n🔐 اختبار الربط التشفيري — ' + BASE + '\n');

  // 0) nonce
  const n1 = await get('/api/nonce');
  ok('GET /api/nonce → 200', n1.status === 200, n1);
  ok('nonce موجود', typeof n1.d.nonce === 'string' && n1.d.nonce.length > 20);

  const n2 = await get('/api/nonce');
  ok('nonce مختلف في كل طلب', n1.d.nonce !== n2.d.nonce);

  // 1) توليد مفتاح جهاز (يحاكي Android Keystore)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  // 2) إنشاء كود
  const login = await post('/api/admin/login', { password: ADMIN_PASSWORD });
  ok('دخول الأدمن', login.status === 200 && !!login.d.token);
  const auth = { Authorization: 'Bearer ' + login.d.token };

  const created = await post('/api/admin/codes', {
    count: 1, duration_hours: 720, plan: 'PRO', max_devices: 1,
  }, auth);
  const code = (created.d.created || [])[0];
  ok('إنشاء كود', !!code, created.d);

  const deviceId = 'AND-' + crypto.randomBytes(8).toString('hex');

  // 3) تفعيل بتوقيع صحيح
  const nonce = (await get('/api/nonce')).d.nonce;
  const msg = Buffer.from(`${code}|${deviceId}|${nonce}`, 'utf8');
  const sig = crypto.sign('sha256', msg, { key: privateKey, dsaEncoding: 'der' }).toString('base64');

  const v1 = await post('/api/verify', { code, device_id: deviceId, pubkey: spki, signature: sig, nonce });
  ok('تفعيل بتوقيع صحيح → valid', v1.d && v1.d.valid === true, v1);

  // 4) إعادة التفعيل بتوقيع صحيح → valid
  const nonce2 = (await get('/api/nonce')).d.nonce;
  const msg2 = Buffer.from(`${code}|${deviceId}|${nonce2}`, 'utf8');
  const sig2 = crypto.sign('sha256', msg2, { key: privateKey, dsaEncoding: 'der' }).toString('base64');
  const v2 = await post('/api/verify', { code, device_id: deviceId, pubkey: spki, signature: sig2, nonce: nonce2 });
  ok('إعادة تفعيل بتوقيع صحيح → valid', v2.d && v2.d.valid === true, v2);

  // 5) بدون توقيع بعد الربط:
  //    - REQUIRE_SIGNATURE=false (الافتراضي) → يُقبل، لأن التطبيق الحالي لا يوقّع
  //    - REQUIRE_SIGNATURE=true → مرفوض signature_required
  const REQUIRE_SIGNATURE = String(process.env.REQUIRE_SIGNATURE || 'false').toLowerCase() === 'true';
  const v3 = await post('/api/verify', { code, device_id: deviceId });
  if (REQUIRE_SIGNATURE) {
    ok('بدون توقيع → signature_required', v3.d && v3.d.reason === 'signature_required', v3);
  } else {
    ok('بدون توقيع → يُقبل (الربط اختياري)', v3.d && v3.d.valid === true, v3);
  }

  // 6) توقيع بمفتاح مختلف (جهاز منسوخ) → مرفوض
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const otherSpki = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const nonce3 = (await get('/api/nonce')).d.nonce;
  const msg3 = Buffer.from(`${code}|${deviceId}|${nonce3}`, 'utf8');
  const sig3 = crypto.sign('sha256', msg3, { key: other.privateKey, dsaEncoding: 'der' }).toString('base64');
  const v4 = await post('/api/verify', { code, device_id: deviceId, pubkey: otherSpki, signature: sig3, nonce: nonce3 });
  ok('مفتاح مختلف → device_key_mismatch', v4.d && v4.d.reason === 'device_key_mismatch', v4);

  // 7) nonce منتهي/مزوّر → مرفوض
  const v5 = await post('/api/verify', { code, device_id: deviceId, pubkey: spki, signature: sig, nonce: 'forged' });
  ok('nonce مزوّر → bad_nonce', v5.d && v5.d.reason === 'bad_nonce', v5);

  // 8) نبضة جلسة بتوقيع صحيح
  const token = v2.d.token;
  const nonce4 = (await get('/api/nonce')).d.nonce;
  const msg4 = Buffer.from(`${code}|${deviceId}|${nonce4}`, 'utf8');
  const sig4 = crypto.sign('sha256', msg4, { key: privateKey, dsaEncoding: 'der' }).toString('base64');
  const s1 = await post('/api/session', { token, device_id: deviceId, pubkey: spki, signature: sig4, nonce: nonce4 });
  ok('نبضة جلسة موقّعة → valid', s1.d && s1.d.valid === true, s1);

  // 9) نبضة جلسة بدون توقيع → مرفوض
  const s2 = await post('/api/session', { token, device_id: deviceId });
  ok('نبضة بدون توقيع → مرفوض', s2.status === 401, s2);

  console.log('\n==================================================');
  console.log(`النتيجة: ${pass} ناجح / ${fail} فاشل`);
  console.log('==================================================\n');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('💥 فشل الاختبار:', e.message); process.exit(1); });
