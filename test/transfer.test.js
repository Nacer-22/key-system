const BASE = 'http://127.0.0.1:4010';
const PW = 'NacerStrongPass123!';
let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('✅ ' + name); }
  else { fail++; console.log('❌ ' + name + (extra ? '  → ' + JSON.stringify(extra) : '')); }
}
async function j(path, opts = {}) {
  const r = await fetch(BASE + path, opts);
  let d = null; try { d = await r.json(); } catch {}
  return { status: r.status, d };
}
const H = (t) => ({ 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) });

(async () => {
  // 1) دخول الأدمن
  const login = await j('/api/admin/login', { method: 'POST', headers: H(), body: JSON.stringify({ password: PW }) });
  ok('دخول الأدمن', login.status === 200 && login.d.token, login);
  const admin = login.d.token;

  // 2) إنشاء مفتاح بجهاز واحد
  const created = await j('/api/admin/codes', {
    method: 'POST', headers: H(admin),
    body: JSON.stringify({ duration_hours: 24, max_devices: 1, count: 1 }),
  });
  const codeText = (created.d.created || [])[0];
  ok('إنشاء مفتاح', !!codeText, created.d);

  // 3) تفعيل الجهاز الأول
  const v1 = await j('/api/verify', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-AAAA-1111' }) });
  ok('تفعيل الجهاز الأول', v1.d.valid === true, v1.d);

  // 4) الجهاز الثاني يُرفض مع can_request_transfer
  const v2 = await j('/api/verify', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-BBBB-2222' }) });
  ok('الجهاز الثاني مرفوض', v2.d.valid === false && v2.d.reason === 'max_devices_reached', v2.d);
  ok('يُسمح بطلب النقل', v2.d.can_request_transfer === true, v2.d);

  // 5) طلب نقل
  const req1 = await j('/api/transfer/request', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-BBBB-2222', reason: 'غيّرت هاتفي' }) });
  ok('إنشاء طلب نقل', req1.d.ok === true && req1.d.status === 'pending', req1.d);
  const reqId = req1.d.request_id;

  // 6) طلب مكرر لا يُنشئ سجلاً جديداً
  const req2 = await j('/api/transfer/request', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-BBBB-2222' }) });
  ok('الطلب المكرر لا يُضاعف', req2.d.request_id === reqId, req2.d);

  // 7) حالة الطلب من جهة المستخدم
  const st = await j('/api/transfer/status?code=' + encodeURIComponent(codeText) + '&device_id=DEVICE-BBBB-2222');
  ok('حالة الطلب = pending', st.d.status === 'pending', st.d);

  // 8) الأدمن يرى الطلب
  const list = await j('/api/admin/transfers?status=pending', { headers: H(admin) });
  ok('الأدمن يرى الطلب', Array.isArray(list.d) && list.d.some(r => r.id === reqId), list.d);

  // 9) توكن مستخدم لا يستطيع رؤية الطلبات (تصعيد صلاحيات)
  const userTok = v1.d.token;
  const forbidden = await j('/api/admin/transfers', { headers: H(userTok) });
  ok('توكن المستخدم لا يرى طلبات النقل', forbidden.status === 401 || forbidden.status === 403, forbidden);

  // 10) موافقة الأدمن
  const appr = await j('/api/admin/transfers/' + reqId + '/approve', { method: 'POST', headers: H(admin) });
  ok('موافقة الأدمن', appr.status === 200 && appr.d.ok === true, appr.d);

  // 11) الجهاز القديم أصبح مُبطلاً
  const oldDev = await j('/api/verify', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-AAAA-1111' }) });
  ok('الجهاز القديم مُبطل', oldDev.d.valid === false, oldDev.d);

  // 12) الجهاز الجديد يعمل الآن
  const newDev = await j('/api/verify', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-BBBB-2222' }) });
  ok('الجهاز الجديد مُفعّل', newDev.d.valid === true, newDev.d);

  // 13) الطلب صار approved
  const st2 = await j('/api/transfer/status?code=' + encodeURIComponent(codeText) + '&device_id=DEVICE-BBBB-2222');
  ok('الطلب صار approved', st2.d.status === 'approved', st2.d);

  // 14) لا يمكن الموافقة مرتين
  const twice = await j('/api/admin/transfers/' + reqId + '/approve', { method: 'POST', headers: H(admin) });
  ok('لا موافقة مزدوجة', twice.status === 409, twice);

  // 15) رفض طلب جديد
  const req3 = await j('/api/transfer/request', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-CCCC-3333' }) });
  const rej = await j('/api/admin/transfers/' + req3.d.request_id + '/reject', { method: 'POST', headers: H(admin) });
  ok('رفض الطلب', rej.d.ok === true, rej.d);
  const afterRej = await j('/api/verify', { method: 'POST', headers: H(), body: JSON.stringify({ code: codeText, device_id: 'DEVICE-CCCC-3333' }) });
  ok('المرفوض لا يُفعّل الجهاز', afterRej.d.valid === false, afterRej.d);

  // 16) صفحة الموافقة تُقدَّم
  const page = await fetch(BASE + '/transfer-requests.html');
  const html = await page.text();
  ok('صفحة transfer-requests.html → 200', page.status === 200, page.status);
  ok('الصفحة تحتوي عنوانها', html.includes('طلبات نقل المفاتيح'));

  // 17) لوحة التحكم ما زالت تعمل
  const dash = await fetch(BASE + '/dashboard.html');
  const dhtml = await dash.text();
  ok('dashboard.html → 200', dash.status === 200, dash.status);
  ok('لوحة التحكم لم تُعدّل', dhtml.includes('لوحة التحكم · Nacer_22'));

  // 18) قاعدة البيانات ما زالت محجوبة
  const dbLeak = await fetch(BASE + '/test.db');
  ok('test.db محجوب', dbLeak.status === 404, dbLeak.status);

  console.log('\n' + '='.repeat(50));
  console.log(`  ${pass} ناجح / ${fail} فاشل`);
  console.log('='.repeat(50));
  process.exit(fail ? 1 : 0);
})();
