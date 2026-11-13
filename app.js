'use strict';
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const cfg = require('./config');
const { pool } = require('./db');
const v = require('./validate');

const SESSION_MS = cfg.sessionDays * 24 * 60 * 60 * 1000;

// hash وهمي لمقارنة زمنية متساوية عندما لا يوجد الحساب (يمنع كشف الإيميلات بالتوقيت)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', cfg.bcryptRounds);

function publicUser(row) {
  // لا نُرجع أي بيانات حساسة: لا هاش ولا إيميل
  return { id: String(row.id), name: row.name };
}

function setSessionCookie(res, userId) {
  const token = jwt.sign({ sub: String(userId) }, cfg.sessionSecret, {
    algorithm: 'HS256',
    expiresIn: Math.floor(SESSION_MS / 1000),
  });
  res.cookie(cfg.cookie.name, token, {
    httpOnly: true,
    secure: cfg.cookie.secure,
    sameSite: cfg.cookie.sameSite,
    domain: cfg.cookie.domain,
    maxAge: SESSION_MS,
    path: '/',
  });
}

function clearSessionCookie(res) {
  res.clearCookie(cfg.cookie.name, {
    httpOnly: true,
    secure: cfg.cookie.secure,
    sameSite: cfg.cookie.sameSite,
    domain: cfg.cookie.domain,
    path: '/',
  });
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Render يضع بروكسي واحد أمام التطبيق

  app.use(helmet());
  app.use(
    cors({
      origin(origin, cb) {
        // طلبات بدون Origin (مثل health check) مسموحة؛ المتصفح دائمًا يرسل Origin
        if (!origin || cfg.corsOrigins.includes(origin)) return cb(null, true);
        return cb(null, false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type'],
      maxAge: 600,
    })
  );
  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser());

  // حماية CSRF: أي طلب تعديل لازم يأتي من موقعنا المسموح فقط
  app.use((req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    const origin = req.get('origin');
    if (!origin || !cfg.corsOrigins.includes(origin)) {
      return res.status(403).json({ error: 'طلب غير مسموح.' });
    }
    next();
  });

  const tooMany = (_req, res) =>
    res.status(429).json({ error: 'محاولات كثيرة. حاول مرة أخرى بعد قليل.' });

  // حد عام لكل IP على عمليات الدخول والتسجيل
  const ipLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: tooMany,
  });
  // حد خاص بكل بريد إلكتروني لإيقاف تخمين كلمة المرور لحساب معيّن
  const emailLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: false,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => 'e:' + v.normalizeEmail(req.body && req.body.email),
    handler: tooMany,
  });

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.post('/api/auth/signup', ipLimiter, async (req, res) => {
    try {
      const body = req.body || {};
      const email = v.normalizeEmail(body.email);
      const eErr = v.validateEmail(email);
      if (eErr) return res.status(400).json({ error: eErr, field: 'email' });
      const nErr = v.validateName(body.name);
      if (nErr) return res.status(400).json({ error: nErr, field: 'name' });
      const pErr = v.validatePassword(body.password);
      if (pErr) return res.status(400).json({ error: pErr, field: 'password' });

      const hash = await bcrypt.hash(body.password, cfg.bcryptRounds);
      try {
        const { rows } = await pool.query(
          'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name',
          [v.cleanName(body.name), email, hash]
        );
        setSessionCookie(res, rows[0].id);
        return res.status(201).json({ user: publicUser(rows[0]) });
      } catch (e) {
        if (e && e.code === '23505') {
          return res.status(409).json({ error: 'البريد الإلكتروني مستخدم بالفعل. جرّب تسجيل الدخول.', field: 'email' });
        }
        throw e;
      }
    } catch (e) {
      console.error('signup error:', e.message);
      return res.status(500).json({ error: 'حدث خطأ في السيرفر. حاول مرة أخرى.' });
    }
  });

  app.post('/api/auth/login', ipLimiter, emailLimiter, async (req, res) => {
    try {
      const body = req.body || {};
      const email = v.normalizeEmail(body.email);
      const password = typeof body.password === 'string' ? body.password : '';
      if (!email) return res.status(400).json({ error: 'اكتب البريد الإلكتروني.', field: 'email' });
      if (v.validateEmail(email)) return res.status(400).json({ error: 'البريد الإلكتروني غير صحيح.', field: 'email' });
      if (!password) return res.status(400).json({ error: 'اكتب كلمة المرور.', field: 'password' });
      if (Buffer.byteLength(password, 'utf8') > 72) {
        return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
      }

      const { rows } = await pool.query(
        'SELECT id, name, password_hash FROM users WHERE lower(email) = $1 LIMIT 1',
        [email]
      );
      const user = rows[0];
      const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
      if (!user || !ok) {
        return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
      }
      setSessionCookie(res, user.id);
      return res.json({ user: publicUser(user) });
    } catch (e) {
      console.error('login error:', e.message);
      return res.status(500).json({ error: 'حدث خطأ في السيرفر. حاول مرة أخرى.' });
    }
  });

  app.post('/api/auth/logout', (_req, res) => {
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  app.get('/api/auth/me', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const token = req.cookies && req.cookies[cfg.cookie.name];
    if (!token) return res.json({ user: null });
    let payload;
    try {
      payload = jwt.verify(token, cfg.sessionSecret, { algorithms: ['HS256'] });
    } catch (_e) {
      clearSessionCookie(res);
      return res.json({ user: null });
    }
    try {
      const { rows } = await pool.query('SELECT id, name FROM users WHERE id = $1', [payload.sub]);
      if (!rows[0]) {
        clearSessionCookie(res);
        return res.json({ user: null });
      }
      return res.json({ user: publicUser(rows[0]) });
    } catch (e) {
      console.error('me error:', e.message);
      return res.status(500).json({ error: 'حدث خطأ في السيرفر.' });
    }
  });

  app.use((_req, res) => res.status(404).json({ error: 'غير موجود.' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'بيانات غير صالحة.' });
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'البيانات كبيرة جدًا.' });
    console.error('unhandled error:', err && err.message);
    res.status(500).json({ error: 'حدث خطأ في السيرفر.' });
  });

  return app;
}

module.exports = { createApp };
