'use strict';
const cfg = require('./config');
const { pool, initSchema } = require('./db');
const { createApp } = require('./app');

async function main() {
  await initSchema();
  const app = createApp();
  const server = app.listen(cfg.port, () => {
    console.log(`✅ السيرفر يعمل على المنفذ ${cfg.port} | CORS: ${cfg.corsOrigins.join(', ')}`);
  });
  const stop = () => server.close(() => pool.end().then(() => process.exit(0)));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

main().catch((e) => {
  console.error('❌ فشل تشغيل السيرفر:', e.message);
  process.exit(1);
});
