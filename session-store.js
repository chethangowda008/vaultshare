'use strict';

import session from 'express-session';
import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, 'data');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'sessions.db');

const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire INTEGER NOT NULL
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_sessions_expire
  ON sessions(expire)
`);

class SQLiteSessionStore extends session.Store {
  constructor() {
    super();

    this.getStatement = db.prepare(`
      SELECT sess, expire
      FROM sessions
      WHERE sid = ?
    `);

    this.setStatement = db.prepare(`
      INSERT INTO sessions (sid, sess, expire)
      VALUES (?, ?, ?)
      ON CONFLICT(sid)
      DO UPDATE SET
        sess = excluded.sess,
        expire = excluded.expire
    `);

    this.destroyStatement = db.prepare(`
      DELETE FROM sessions
      WHERE sid = ?
    `);

    this.touchStatement = db.prepare(`
      UPDATE sessions
      SET expire = ?
      WHERE sid = ?
    `);

    this.clearExpiredStatement = db.prepare(`
      DELETE FROM sessions
      WHERE expire <= ?
    `);

    this.clearExpired();
  }

  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid);

      if (!row) {
        return callback(null, null);
      }

      const now = Date.now();

      if (row.expire <= now) {
        this.destroy(sid, () => {});
        return callback(null, null);
      }

      const sessionData = JSON.parse(row.sess);

      callback(null, sessionData);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sessionData, callback) {
    try {
      const maxAge =
        sessionData.cookie?.maxAge ??
        7 * 24 * 60 * 60 * 1000;

      const expire = Date.now() + maxAge;

      this.setStatement.run(
        sid,
        JSON.stringify(sessionData),
        expire
      );

      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }

  destroy(sid, callback) {
    try {
      this.destroyStatement.run(sid);
      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }

  touch(sid, sessionData, callback) {
    try {
      const maxAge =
        sessionData.cookie?.maxAge ??
        7 * 24 * 60 * 60 * 1000;

      const expire = Date.now() + maxAge;

      this.touchStatement.run(expire, sid);

      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }

  clearExpired() {
    try {
      this.clearExpiredStatement.run(Date.now());
    } catch (error) {
      console.error('[session-store] cleanup error:', error.message);
    }
  }
}

const store = new SQLiteSessionStore();

setInterval(() => {
  store.clearExpired();
}, 60 * 60 * 1000);

// ── FEATURE: ACTIVE SESSION MANAGEMENT ───────────────────────────────────
// These read/write the same underlying sessions.db directly. They exist
// alongside (not instead of) the express-session Store API above so the
// Security Center / Active Sessions page can list and terminate a user's
// own sessions, including ones on OTHER devices/browsers.

const listAllStatement = db.prepare(`SELECT sid, sess, expire FROM sessions WHERE expire > ?`);

/**
 * Every non-expired session that belongs to `userId`, newest-created first.
 * Each session's extra fields (ip, userAgent, createdAt) are set by
 * auth.js at login/register time — see req.session.ip / .userAgent below.
 */
export function listSessionsForUser(userId) {
  const now = Date.now();
  const rows = listAllStatement.all(now);
  const sessions = [];
  for (const row of rows) {
    let data;
    try {
      data = JSON.parse(row.sess);
    } catch {
      continue;
    }
    if (data.userId === userId) {
      sessions.push({
        sid: row.sid,
        userId: data.userId,
        ip: data.ip || null,
        userAgent: data.userAgent || null,
        createdAt: data.createdAt || null,
        expire: row.expire,
      });
    }
  }
  sessions.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return sessions;
}

/** Destroys one session by sid, but ONLY if it actually belongs to `userId`. Returns true if destroyed. */
export function destroySessionForUser(sid, userId) {
  const row = store.getStatement.get(sid);
  if (!row) return false;
  let data;
  try {
    data = JSON.parse(row.sess);
  } catch {
    return false;
  }
  if (data.userId !== userId) return false;
  store.destroyStatement.run(sid);
  return true;
}

/** Destroys every session belonging to `userId` EXCEPT `keepSid` (used by "log out all other sessions"). */
export function destroyOtherSessionsForUser(userId, keepSid) {
  let count = 0;
  for (const s of listSessionsForUser(userId)) {
    if (s.sid !== keepSid) {
      store.destroyStatement.run(s.sid);
      count += 1;
    }
  }
  return count;
}

export default store;