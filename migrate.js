'use strict';
const { pool, initSchema } = require('./db');

initSchema()
  .then(() => console.log('✅ تم تجهيز جدول الحسابات'))
  .catch((e) => { console.error('❌ فشل تجهيز قاعدة البيانات:', e.message); process.exitCode = 1; })
  .finally(() => pool.end());
