'use strict';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function normalizeEmail(v) {
  return typeof v === 'string' ? v.trim().toLowerCase() : '';
}

function validateEmail(email) {
  if (!email) return 'اكتب البريد الإلكتروني.';
  if (email.length > 254 || !EMAIL_RE.test(email)) return 'البريد الإلكتروني غير صحيح.';
  return null;
}

function validateName(name) {
  if (typeof name !== 'string') return 'اكتب اسم المستخدم.';
  const n = name.trim().replace(/\s+/g, ' ');
  if (n.length < 2) return 'اكتب اسم المستخدم (حرفان على الأقل).';
  if (n.length > 40) return 'اسم المستخدم طويل (الحد الأقصى 40 حرفًا).';
  // منع الرموز الخطرة/محارف التحكم (النص يُعرض عبر textContent أيضًا في الواجهة)
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f<>]/.test(n)) return 'اسم المستخدم يحتوي على رموز غير مسموحة.';
  return null;
}

function validatePassword(pw) {
  if (typeof pw !== 'string' || !pw) return 'اكتب كلمة المرور.';
  if (pw.length < 8) return 'كلمة المرور ضعيفة؛ استخدم 8 أحرف على الأقل.';
  // bcrypt يتجاهل ما بعد 72 بايت، فنرفض الأطول بدل أن نقصّه بصمت
  if (Buffer.byteLength(pw, 'utf8') > 72) return 'كلمة المرور طويلة جدًا (الحد الأقصى 72 بايت).';
  return null;
}

function cleanName(name) {
  return name.trim().replace(/\s+/g, ' ');
}

module.exports = { normalizeEmail, validateEmail, validateName, validatePassword, cleanName };
