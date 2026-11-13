// يعمل على Vercel أثناء البناء: يكتب config.js من متغير البيئة API_BASE_URL
const fs = require('fs');
const path = require('path');

const raw = (process.env.API_BASE_URL || '').trim().replace(/\/+$/, '');
if (!raw) {
  if (process.env.VERCEL) {
    console.error('❌ متغير البيئة API_BASE_URL غير موجود. أضفه في Vercel ← Settings ← Environment Variables (رابط سيرفر Render).');
    process.exit(1);
  }
  console.log('API_BASE_URL غير مضبوط: سيبقى config.js الافتراضي (localhost).');
  process.exit(0);
}
if (!/^https?:\/\/[^\s"'<>]+$/.test(raw)) {
  console.error('❌ API_BASE_URL غير صالح: ' + raw);
  process.exit(1);
}
const out = 'window.APP_CONFIG = ' + JSON.stringify({ API_BASE: raw }) + ';\n';
fs.writeFileSync(path.join(__dirname, 'config.js'), out);
console.log('✅ تم ضبط config.js على ' + raw);
