// ---------------------------------------------------------------------------
// Өгөгдлийн сан (PostgreSQL) холболт ба хүснэгт үүсгэх
// ---------------------------------------------------------------------------
const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("АЛДАА: DATABASE_URL тохируулаагүй байна. .env файлаа шалгана уу.");
}

// Neon / Supabase зэрэг үүлэн санд SSL шаардлагатай; локал дээр SSL хэрэггүй.
const isLocal =
  connectionString &&
  (connectionString.includes("localhost") || connectionString.includes("127.0.0.1"));

const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
});

// Хүснэгтүүдийг үүсгэх (байхгүй бол)
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          SERIAL PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      name        TEXT NOT NULL DEFAULT '',
      password    TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'viewer',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id          TEXT PRIMARY KEY,
      machine     TEXT NOT NULL,
      unit        TEXT NOT NULL DEFAULT '',
      work        TEXT NOT NULL,
      team        TEXT NOT NULL DEFAULT '',
      lead        TEXT NOT NULL DEFAULT '',
      parts       TEXT NOT NULL DEFAULT '',
      start_date  TEXT NOT NULL,
      end_date    TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'plan',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, init };
