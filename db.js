'use strict';
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const cfg = require('./config');

const pool = new Pool({
  connectionString: cfg.databaseUrl,
  ssl: cfg.databaseSsl ? { rejectUnauthorized: true } : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

pool.on('error', (err) => console.error('pg pool error:', err.message));

// ينشئ جدول الحسابات إذا لم يكن موجودًا (آمن للتكرار)
async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  await pool.query(sql);
}

module.exports = { pool, initSchema };
