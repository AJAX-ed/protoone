const path = require("path");
const Database = require("better-sqlite3");

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "..", "data", "app.db");

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

function getUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email);
}

function createUser(email, passwordHash) {
  const stmt = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
  const info = stmt.run(email, passwordHash);
  return { id: info.lastInsertRowid, email };
}

module.exports = {
  db,
  getUserByEmail,
  createUser,
};
