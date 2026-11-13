'use strict';
// اختبار تكاملي حقيقي: يحتاج قاعدة PostgreSQL فارغة للاختبار (ليست قاعدة الإنتاج!)
//   TEST_DATABASE_URL=postgresql://... npm test
const test = require('node:test');
const assert = require('node:assert');

if (!process.env.TEST_DATABASE_URL) {
  console.log('تخطي الاختبار: ضع TEST_DATABASE_URL لقاعدة بيانات اختبار.');
  process.exit(0);
}
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
process.env.DATABASE_SSL = process.env.TEST_DATABASE_SSL || 'false';
process.env.SESSION_SECRET = 'test-secret-test-secret-test-secret-123456';
process.env.CORS_ORIGINS = 'http://site.test';
process.env.NODE_ENV = 'development';
process.env.BCRYPT_ROUNDS = '10';

const { pool, initSchema } = require('../src/db');
const { createApp } = require('../src/app');

const ORIGIN = 'http://site.test';
let server, base, jar = '';

async function call(method, path, body, { cookie = jar, origin = ORIGIN } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (origin) headers.Origin = origin;
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data, setCookie: sc };
}
const grab = (r) => { const c = r.setCookie.find((x) => x.startsWith('ak_session=')); return c ? c.split(';')[0] : ''; };

test.before(async () => {
  await initSchema();
  await pool.query('DELETE FROM users');
  server = createApp().listen(0);
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(async () => { server.close(); await pool.end(); });

const U = { name: 'مستخدم اختبار', email: 'Test@Example.com', password: 'Pass12345' };

test('إنشاء حساب + كوكي HttpOnly + عدم إرجاع بيانات حساسة', async () => {
  const r = await call('POST', '/api/auth/signup', U, { cookie: '' });
  assert.strictEqual(r.status, 201);
  assert.strictEqual(r.data.user.name, U.name);
  assert.ok(!('password_hash' in r.data.user) && !('email' in r.data.user));
  const raw = r.setCookie.find((x) => x.startsWith('ak_session='));
  assert.ok(/HttpOnly/i.test(raw));
  jar = grab(r);
});

test('كلمة المرور مخزنة كـ bcrypt وليست نصًا عاديًا', async () => {
  const { rows } = await pool.query('SELECT password_hash FROM users');
  assert.strictEqual(rows.length, 1);
  assert.notStrictEqual(rows[0].password_hash, U.password);
  assert.ok(/^\$2[aby]\$\d\d\$/.test(rows[0].password_hash));
});

test('منع البريد المكرر (حتى باختلاف حالة الأحرف)', async () => {
  const r = await call('POST', '/api/auth/signup', { ...U, email: 'test@example.COM' }, { cookie: '' });
  assert.strictEqual(r.status, 409);
});

test('التحقق من البيانات في السيرفر', async () => {
  assert.strictEqual((await call('POST', '/api/auth/signup', { ...U, email: 'x' }, { cookie: '' })).status, 400);
  assert.strictEqual((await call('POST', '/api/auth/signup', { ...U, email: 'a@b.co', password: '123' }, { cookie: '' })).status, 400);
  assert.strictEqual((await call('POST', '/api/auth/signup', { ...U, email: 'a@b.co', name: '' }, { cookie: '' })).status, 400);
});

test('الجلسة محفوظة (me) ثم تسجيل الخروج', async () => {
  const me = await call('GET', '/api/auth/me');
  assert.strictEqual(me.data.user.name, U.name);
  const out = await call('POST', '/api/auth/logout');
  assert.strictEqual(out.status, 200);
  const me2 = await call('GET', '/api/auth/me', null, { cookie: '' });
  assert.strictEqual(me2.data.user, null);
});

test('تسجيل الدخول: صحيح وخاطئ', async () => {
  const bad = await call('POST', '/api/auth/login', { email: U.email, password: 'wrong-pass' }, { cookie: '' });
  assert.strictEqual(bad.status, 401);
  const none = await call('POST', '/api/auth/login', { email: 'nobody@example.com', password: 'Pass12345' }, { cookie: '' });
  assert.strictEqual(none.status, 401);
  assert.strictEqual(bad.data.error, none.data.error);
  const ok = await call('POST', '/api/auth/login', { email: U.email, password: U.password }, { cookie: '' });
  assert.strictEqual(ok.status, 200);
  assert.ok(grab(ok));
});

test('رفض الطلبات من موقع غير مسموح (CSRF/CORS)', async () => {
  const r = await call('POST', '/api/auth/login', { email: U.email, password: U.password }, { cookie: '', origin: 'http://evil.test' });
  assert.strictEqual(r.status, 403);
  const r2 = await call('POST', '/api/auth/login', { email: U.email, password: U.password }, { cookie: '', origin: '' });
  assert.strictEqual(r2.status, 403);
});

test('الحماية من تخمين كلمة المرور (429 بعد محاولات فاشلة متكررة)', async () => {
  let last;
  for (let i = 0; i < 10; i++) {
    last = await call('POST', '/api/auth/login', { email: 'brute@example.com', password: 'bad-bad-bad' }, { cookie: '' });
  }
  assert.strictEqual(last.status, 429);
});
