'use strict';
require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

function fail(msg) {
  console.error('❌ إعدادات ناقصة: ' + msg);
  process.exit(1);
}

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) fail('DATABASE_URL غير موجود');

const SESSION_SECRET = process.env.SESSION_SECRET || '';
if (SESSION_SECRET.length < 32) fail('SESSION_SECRET يجب أن يكون 32 حرفًا على الأقل');

const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);
if (CORS_ORIGINS.length === 0) fail('CORS_ORIGINS غير موجود (ضع رابط موقعك)');

const sameSite = (process.env.COOKIE_SAMESITE || (isProd ? 'none' : 'lax')).toLowerCase();
if (!['none', 'lax', 'strict'].includes(sameSite)) fail('COOKIE_SAMESITE يجب أن تكون none أو lax أو strict');
// SameSite=None لا يعمل بدون Secure
const cookieSecure = isProd || sameSite === 'none';

module.exports = {
  isProd,
  port: Number(process.env.PORT) || 3000,
  databaseUrl: DATABASE_URL,
  databaseSsl: (process.env.DATABASE_SSL || 'true').toLowerCase() !== 'false',
  sessionSecret: SESSION_SECRET,
  sessionDays: Math.max(1, Number(process.env.SESSION_DAYS) || 30),
  bcryptRounds: Math.min(15, Math.max(10, Number(process.env.BCRYPT_ROUNDS) || 12)),
  corsOrigins: CORS_ORIGINS,
  cookie: {
    name: 'ak_session',
    sameSite,
    secure: cookieSecure,
    domain: process.env.COOKIE_DOMAIN || undefined,
  },
};
