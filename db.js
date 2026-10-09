/**
 * VaultShare — db.js
 * =====================================================================
 * SQLite database setup for VaultShare.
 *
 * Uses Node's BUILT-IN `node:sqlite` module (available in Node 22.5+,
 * no extra npm package, no native compiler needed — this avoids the
 * Visual Studio Build Tools requirement that better-sqlite3 has on
 * Windows).
 *
 * You will see a one-line "ExperimentalWarning: SQLite is an
 * experimental feature" printed when the server starts. That is
 * expected and harmless — it's just Node telling you this built-in
 * module is still fairly new.
 *
 * This file creates (or opens) a local SQLite database file at
 * ./data/vaultshare.db and makes sure the `users`, `files`, `shares`,
 * and `activity_logs` tables all exist.
 * =====================================================================
 */

'use strict';

import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── MAKE SURE THE data/ FOLDER EXISTS ───────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// ── OPEN (OR CREATE) THE DATABASE FILE ──────────────────────────────────
const dbPath = path.join(dataDir, 'vaultshare.db');
const db = new DatabaseSync(dbPath);

// Recommended pragmas for a small local app
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// ── CREATE users TABLE IF IT DOES NOT EXIST YET ─────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
  );
`);

// ── CREATE files TABLE ───────────────────────────────────────────────────
// Not filled in yet (Personal Vault / Feature 4 comes in a later step),
// but the table exists now so the Dashboard (Feature 2) can query REAL
// counts from it instead of showing fake numbers.
db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL,
    file_path         TEXT NOT NULL,
    file_size         INTEGER NOT NULL,
    algorithm         TEXT NOT NULL,
    file_hash         TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── CREATE shares TABLE ──────────────────────────────────────────────────
// Not filled in yet (Secure File Sharing / Feature 5 comes in a later
// step), but the table exists now for the same reason as above.
db.exec(`
  CREATE TABLE IF NOT EXISTS shares (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id          INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    share_token      TEXT NOT NULL UNIQUE,
    expires_at       TEXT,
    download_limit   INTEGER,
    download_count   INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    last_accessed_at TEXT
  );
`);

// ── CREATE activity_logs TABLE ───────────────────────────────────────────
// This one IS used starting now — every login/logout/register is logged
// here so the Dashboard's "Recent Activity" list shows real events.
db.exec(`
  CREATE TABLE IF NOT EXISTS activity_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    file_id    INTEGER REFERENCES files(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── FEATURE 18: ADMIN — is_admin column migration ────────────────────────
// SQLite (older versions) has no clean "ADD COLUMN IF NOT EXISTS", so we
// just try the ALTER TABLE and ignore the "duplicate column name" error
// that fires if this has already run against this database file before.
try {
  db.exec(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;`);
  console.log('[db] Added is_admin column to users table.');
} catch (err) {
  if (!/duplicate column name/i.test(err.message)) {
    throw err;
  }
}

// ── VAULTSHARE 2.0 MIGRATIONS ────────────────────────────────────────────
// Same safe pattern as the is_admin migration above: try the ALTER TABLE,
// swallow only the "duplicate column name" error so this file can be run
// again and again against an existing database without ever losing data.
function safeAlter(sql) {
  try {
    db.exec(sql);
  } catch (err) {
    if (!/duplicate column name/i.test(err.message)) throw err;
  }
}

// files: soft-delete (Recycle Bin) and version tracking.
// NOTE: the Folders feature (and its `folders` table) was removed — see the
// cleanup migration further down. files.folder_id is kept as an inert,
// always-NULL column rather than risk an ALTER TABLE ... DROP COLUMN on the
// shared `files` table; nothing reads or writes it anymore.
safeAlter(`ALTER TABLE files ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL;`);
safeAlter(`ALTER TABLE files ADD COLUMN deleted_at TEXT;`);
safeAlter(`ALTER TABLE files ADD COLUMN version INTEGER NOT NULL DEFAULT 1;`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_owner_folder ON files(owner_id, folder_id);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(owner_id, deleted_at);`);

// File Version History — every version EXCEPT the current one (the
// current version's storage info always lives directly on the files row).
db.exec(`
  CREATE TABLE IF NOT EXISTS file_versions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id            INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    version_number     INTEGER NOT NULL,
    original_filename  TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL,
    file_path          TEXT NOT NULL,
    file_size          INTEGER NOT NULL,
    algorithm          TEXT NOT NULL,
    file_hash          TEXT NOT NULL,
    uploaded_by        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_versions_file ON file_versions(file_id);`);

// Password-protected share links (Feature: Password-Protected Share Links)
safeAlter(`ALTER TABLE shares ADD COLUMN password_hash TEXT;`);

// Per-user settings (recycle-bin retention, sharing defaults)
db.exec(`
  CREATE TABLE IF NOT EXISTS user_settings (
    user_id              INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    recycle_days         INTEGER,
    default_share_expiry TEXT,
    default_share_limit  TEXT
  );
`);

// Resumable uploads: a chunked upload in progress (bytes are appended to a temp file)
db.exec(`
  CREATE TABLE IF NOT EXISTS upload_sessions (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    total_size  INTEGER NOT NULL,
    received    INTEGER NOT NULL DEFAULT 0,
    algorithm   TEXT NOT NULL,
    file_hash   TEXT NOT NULL,
    folder_id   INTEGER REFERENCES folders(id) ON DELETE SET NULL,
    temp_path   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_upload_sessions_user ON upload_sessions(user_id);
`);

// Multi-file secure sharing: one share can cover several of the owner's files
db.exec(`
  CREATE TABLE IF NOT EXISTS share_items (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    file_id  INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    UNIQUE (share_id, file_id)
  );
  CREATE INDEX IF NOT EXISTS idx_share_items_share ON share_items(share_id);
`);

// ── VaultShare 3.0 migrations ──────────────────────────────────────────

// User account status + storage quota (Feature 6, 9: quotas, suspend/unsuspend)
safeAlter(`ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';`);
safeAlter(`ALTER TABLE users ADD COLUMN storage_quota_bytes INTEGER;`); // NULL = use server default

// Favorites, expiration, integrity tracking on files (Feature 12, 14, 4)
safeAlter(`ALTER TABLE files ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;`);
safeAlter(`ALTER TABLE files ADD COLUMN expires_at TEXT;`);
safeAlter(`ALTER TABLE files ADD COLUMN last_verified_at TEXT;`);
safeAlter(`ALTER TABLE files ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'unverified';`); // unverified|ok|failed
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_favorite ON files(owner_id, is_favorite);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_files_hash ON files(owner_id, file_hash);`); // duplicate detection (Feature 7)

// File tagging (Feature 15)
db.exec(`
  CREATE TABLE IF NOT EXISTS file_tags (
    file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (file_id, tag)
  );
  CREATE INDEX IF NOT EXISTS idx_file_tags_tag ON file_tags(tag);
`);

// System-wide app settings (Feature 6: default quota, configurable by admin)
db.exec(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);

// Login history — still used by Suspicious Login Detection (kept) and the
// Security Center's "Recent Logins" list (kept). Only the Security
// Incidents table that USED to be fed from this, and the notifications that
// used to fire from it, were removed — see the cleanup migration below.
db.exec(`
  CREATE TABLE IF NOT EXISTS login_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip          TEXT,
    user_agent  TEXT,
    device_hash TEXT NOT NULL,
    net_prefix  TEXT,
    suspicious  INTEGER NOT NULL DEFAULT 0,
    reasons     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, created_at);
`);

// ── FEATURE REMOVAL CLEANUP ────────────────────────────────────────────
// Folders, Favorites, Security Incidents, 2FA, Notifications and AI Tools
// were removed on request. Tables used EXCLUSIVELY by those features are
// dropped here — each one is a standalone table nothing else references as
// a parent, so this cannot touch users/files/shares/file_versions/recycle
// bin/sessions/activity_logs or any other preserved data. Columns added to
// SHARED tables for these features (files.folder_id, files.is_favorite) are
// NOT dropped — ALTER TABLE...DROP COLUMN on a table other live features
// still read/write was judged an unnecessary risk; those columns are simply
// never read or written anymore and stay permanently NULL/0 going forward.
// NOTE: the `folders` table itself is intentionally NOT dropped. files.folder_id
// (and upload_sessions.folder_id) declare `REFERENCES folders(id)` — SQLite
// validates that the referenced table exists when COMPILING any statement
// that touches files/upload_sessions (confirmed by testing: dropping `folders`
// made every files.* query fail at startup with "no such table: main.folders",
// even though every write is now NULL). Recreating files/upload_sessions
// without the constraint would mean rebuilding a live table with real user
// data — judged a bigger risk than leaving one small, permanently-empty
// table in the schema. The `folders` table has no API route, no UI, and
// nothing is ever inserted into it again — it is inert, not functional.
db.exec(`CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`);
db.exec(`DROP TABLE IF EXISTS user_2fa;`);       // 2FA feature
db.exec(`DROP TABLE IF EXISTS recovery_codes;`); // 2FA feature
db.exec(`DROP TABLE IF EXISTS security_incidents;`); // Security Incidents feature
db.exec(`DROP TABLE IF EXISTS notifications;`);       // Notifications feature
db.exec(`DROP TABLE IF EXISTS notification_prefs;`);  // Notifications feature
db.exec(`DROP TABLE IF EXISTS ai_classifications;`);  // AI feature
db.exec(`DROP TABLE IF EXISTS ai_summaries;`);        // AI feature

console.log(`[db] SQLite database ready at ${dbPath}`);

// ── PREPARED STATEMENTS (reused for speed + safety against SQL injection) ─
const stmts = {
  insertUser: db.prepare(
    `INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`
  ),
  findByEmail: db.prepare(
    `SELECT * FROM users WHERE email = ?`
  ),
  findById: db.prepare(
    `SELECT id, name, email, created_at, last_login, is_admin FROM users WHERE id = ?`
  ),
  touchLastLogin: db.prepare(
    `UPDATE users SET last_login = datetime('now') WHERE id = ?`
  ),

  // ── Feature 18 (Admin) statements ──
  countUsers: db.prepare(
    `SELECT COUNT(*) AS n FROM users`
  ),
  setUserAdmin: db.prepare(
    `UPDATE users SET is_admin = 1 WHERE id = ?`
  ),
  countAllFiles: db.prepare(
    `SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NULL`
  ),
  countAllShares: db.prepare(
    `SELECT COUNT(*) AS n FROM shares`
  ),
  countAllDownloads: db.prepare(
    `SELECT COUNT(*) AS n FROM activity_logs WHERE action = 'DOWNLOAD'`
  ),
  shareStatusCountsAll: db.prepare(
    `SELECT status, COUNT(*) AS n FROM shares GROUP BY status`
  ),
  recentActivityAllUsers: db.prepare(
    `SELECT a.id, a.action, a.file_id, a.created_at, a.user_id,
            u.name AS user_name, u.email AS user_email
     FROM activity_logs a
     LEFT JOIN users u ON u.id = a.user_id
     ORDER BY a.created_at DESC, a.id DESC
     LIMIT ?`
  ),

  // ── Feature 2 (Dashboard) statements ──
  insertActivity: db.prepare(
    `INSERT INTO activity_logs (user_id, file_id, action, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?)`
  ),
  recentActivityForUser: db.prepare(
    `SELECT id, action, file_id, created_at
     FROM activity_logs
     WHERE user_id = ?
     ORDER BY created_at DESC, id DESC
     LIMIT ?`
  ),
  countMyFiles: db.prepare(
    `SELECT COUNT(*) AS n FROM files WHERE owner_id = ? AND deleted_at IS NULL`
  ),
  countSharedWithMe: db.prepare(
    `SELECT COUNT(*) AS n FROM shares
     WHERE recipient_id = ? AND status = 'active'`
  ),
  countDownloads: db.prepare(
    `SELECT COUNT(*) AS n FROM activity_logs
     WHERE user_id = ? AND action = 'DOWNLOAD'`
  ),
  countActiveShares: db.prepare(
    `SELECT COUNT(*) AS n FROM shares
     WHERE owner_id = ? AND status = 'active'`
  ),

  // ── Feature 4 (Personal Vault) statements ──
  insertFile: db.prepare(
    `INSERT INTO files
       (owner_id, original_filename, encrypted_filename, file_path,
        file_size, algorithm, file_hash, folder_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ),
  filesForOwner: db.prepare(
    `SELECT id, original_filename, algorithm, file_hash, file_size, created_at, version,
            expires_at, last_verified_at, verification_status
     FROM files
     WHERE owner_id = ? AND deleted_at IS NULL
     ORDER BY created_at DESC, id DESC`
  ),
  fileByIdForOwner: db.prepare(
    `SELECT * FROM files WHERE id = ? AND owner_id = ? AND deleted_at IS NULL`
  ),
  deleteFileById: db.prepare(
    `DELETE FROM files WHERE id = ? AND owner_id = ?`
  ),

  // ── Feature 5 (Secure File Sharing) statements ──
  nowPlusSeconds: db.prepare(
    `SELECT datetime('now', '+' || ? || ' seconds') AS d`
  ),
  insertShare: db.prepare(
    `INSERT INTO shares
       (file_id, owner_id, recipient_id, share_token, expires_at, download_limit, status)
     VALUES (?, ?, ?, ?, ?, ?, 'active')`
  ),
  shareById: db.prepare(
    `SELECT * FROM shares WHERE id = ?`
  ),
  shareByIdForOwner: db.prepare(
    `SELECT * FROM shares WHERE id = ? AND owner_id = ?`
  ),
  shareByToken: db.prepare(
    `SELECT s.*, f.original_filename, f.file_size, f.algorithm, f.file_path
     FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.share_token = ? AND f.deleted_at IS NULL`
  ),
  sharesForOwner: db.prepare(
    `SELECT s.id, s.share_token, s.expires_at, s.download_limit, s.download_count,
            s.status, s.created_at, s.recipient_id, f.original_filename,
            u.email AS recipient_email,
            (s.password_hash IS NOT NULL) AS password_protected
     FROM shares s
     JOIN files f ON f.id = s.file_id
     LEFT JOIN users u ON u.id = s.recipient_id
     WHERE s.owner_id = ?
     ORDER BY s.created_at DESC, s.id DESC`
  ),
  sharesForRecipient: db.prepare(
    `SELECT s.id, s.share_token, s.expires_at, s.download_limit, s.download_count,
            s.status, s.created_at, f.original_filename, ow.name AS owner_name
     FROM shares s
     JOIN files f ON f.id = s.file_id
     JOIN users ow ON ow.id = s.owner_id
     WHERE s.recipient_id = ?
     ORDER BY s.created_at DESC, s.id DESC`
  ),
  setShareStatus: db.prepare(
    `UPDATE shares SET status = ? WHERE id = ? AND owner_id = ?`
  ),
  incrementShareDownload: db.prepare(
    `UPDATE shares SET download_count = download_count + 1, last_accessed_at = datetime('now') WHERE id = ?`
  ),
  completeShareIfAtLimit: db.prepare(
    `UPDATE shares SET status = 'completed'
     WHERE id = ? AND download_limit IS NOT NULL AND download_count >= download_limit`
  ),
  expireStaleShares: db.prepare(
    `UPDATE shares SET status = 'expired'
     WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= datetime('now')`
  ),

  // ── Feature 9 (Activity Log) / Feature 10 (Security Dashboard) statements ──
  activityForUserFiltered: db.prepare(
    `SELECT id, action, file_id, created_at
     FROM activity_logs
     WHERE user_id = ?
     ORDER BY created_at DESC, id DESC
     LIMIT ?`
  ),
  shareStatusCountsForOwner: db.prepare(
    `SELECT status, COUNT(*) AS n FROM shares WHERE owner_id = ? GROUP BY status`
  ),
  securityEventCountForUser: db.prepare(
    `SELECT COUNT(*) AS n FROM activity_logs WHERE user_id = ?`
  ),
  failedLoginCountForUser: db.prepare(
    `SELECT COUNT(*) AS n FROM activity_logs WHERE user_id = ? AND action = 'FAILED_LOGIN'`
  ),

  // ── Recycle Bin ──
  softDeleteFileStmt: db.prepare(
    `UPDATE files SET deleted_at = datetime('now') WHERE id = ? AND owner_id = ? AND deleted_at IS NULL`
  ),
  restoreFileStmt: db.prepare(
    `UPDATE files SET deleted_at = NULL WHERE id = ? AND owner_id = ? AND deleted_at IS NOT NULL`
  ),
  recycleBinForOwner: db.prepare(
    `SELECT f.*
     FROM files f
     WHERE f.owner_id = ? AND f.deleted_at IS NOT NULL
     ORDER BY f.deleted_at DESC`
  ),
  deletedFileByIdForOwner: db.prepare(
    `SELECT * FROM files WHERE id = ? AND owner_id = ? AND deleted_at IS NOT NULL`
  ),
  purgeExpiredDeletedFiles: db.prepare(
    `SELECT * FROM files WHERE deleted_at IS NOT NULL AND deleted_at <= datetime('now', '-' || ? || ' days')`
  ),
  hardDeleteFileStmt: db.prepare(
    `DELETE FROM files WHERE id = ?`
  ),

  // ── File Version History ──
  insertFileVersion: db.prepare(
    `INSERT INTO file_versions
       (file_id, version_number, original_filename, encrypted_filename, file_path, file_size, algorithm, file_hash, uploaded_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ),
  versionsForFile: db.prepare(
    `SELECT * FROM file_versions WHERE file_id = ? ORDER BY version_number DESC`
  ),
  versionByIdForFile: db.prepare(
    `SELECT * FROM file_versions WHERE id = ? AND file_id = ?`
  ),
  deleteVersionStmt: db.prepare(
    `DELETE FROM file_versions WHERE id = ? AND file_id = ?`
  ),
  bumpFileToNewVersion: db.prepare(
    `UPDATE files SET encrypted_filename = ?, file_path = ?, file_size = ?, algorithm = ?, file_hash = ?,
                       original_filename = ?, version = ?, updated_at = datetime('now')
     WHERE id = ? AND owner_id = ?`
  ),

  // ── Password-protected shares ──
  setSharePasswordStmt: db.prepare(
    `UPDATE shares SET password_hash = ? WHERE id = ?`
  ),
};

// ── HELPER FUNCTIONS USED BY auth.js ────────────────────────────────────

/**
 * Create a new user. Throws if the email already exists.
 * Feature 18 bootstrap rule: the very FIRST user ever registered on this
 * database automatically becomes admin — checked with COUNT(*) BEFORE
 * the insert, so the check can never be fooled by the row we're about
 * to create.
 */
export function createUser(name, email, passwordHash) {
  const isFirstUser = stmts.countUsers.get().n === 0;
  const info = stmts.insertUser.run(name, email.toLowerCase(), passwordHash);
  if (isFirstUser) {
    stmts.setUserAdmin.run(info.lastInsertRowid);
  }
  return stmts.findById.get(info.lastInsertRowid);
}

/** Find a user by email (includes password_hash — for login checks only). */
export function findUserByEmail(email) {
  return stmts.findByEmail.get(email.toLowerCase());
}

/** Find a user by id (no password_hash — safe to send to the browser). */
export function findUserById(id) {
  return stmts.findById.get(id);
}

/** Update a user's last_login timestamp to "now". */
export function touchLastLogin(id) {
  stmts.touchLastLogin.run(id);
}

/** Record one row in activity_logs. action = 'LOGIN' | 'LOGOUT' | 'REGISTER' | ... */
export function logActivity(userId, action, { fileId = null, ip = null, userAgent = null } = {}) {
  stmts.insertActivity.run(userId, fileId, action, ip, userAgent);
}

/** Get the user's real dashboard statistics — no fake numbers. */
export function getDashboardStats(userId) {
  return {
    myFiles:      stmts.countMyFiles.get(userId).n,
    sharedFiles:  stmts.countSharedWithMe.get(userId).n,
    downloads:    stmts.countDownloads.get(userId).n,
    activeShares: stmts.countActiveShares.get(userId).n,
  };
}

/** Get the user's most recent activity, newest first. */
export function getRecentActivity(userId, limit = 8) {
  return stmts.recentActivityForUser.all(userId, limit);
}

// ── FEATURE 4: PERSONAL VAULT HELPERS ────────────────────────────────────

/** Insert a new file record after a client-encrypted package is stored on disk. */
export function insertFile({ ownerId, originalFilename, encryptedFilename, filePath, fileSize, algorithm, fileHash, folderId = null }) {
  const info = stmts.insertFile.run(
    ownerId, originalFilename, encryptedFilename, filePath, fileSize, algorithm, fileHash, folderId
  );
  return stmts.fileByIdForOwner.get(info.lastInsertRowid, ownerId);
}

/** List every file owned by this user (does not expose file_path). */
export function listFilesForOwner(ownerId) {
  const files = stmts.filesForOwner.all(ownerId);
  const tagMap = getTagsForFiles(files.map((f) => f.id));
  return files.map((f) => ({ ...f, tags: tagMap.get(f.id) || [] }));
}

/** Fetch one file, but ONLY if it belongs to this owner — never trust a bare file id. */
export function getFileForOwner(fileId, ownerId) {
  return stmts.fileByIdForOwner.get(fileId, ownerId);
}

/** Delete a file row, but ONLY if it belongs to this owner. Returns true if a row was deleted. */
export function deleteFileForOwner(fileId, ownerId) {
  const info = stmts.deleteFileById.run(fileId, ownerId);
  return info.changes > 0;
}

// ── FEATURE 5: SECURE FILE SHARING HELPERS ───────────────────────────────

/** Marks any 'active' share whose expiry has passed as 'expired'. Safe to call often. */
export function expireStaleShares() {
  const newlyExpired = db.prepare(
    `SELECT s.id, s.owner_id, s.recipient_id, f.original_filename FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.status = 'active' AND s.expires_at IS NOT NULL AND s.expires_at <= datetime('now')`
  ).all();
  stmts.expireStaleShares.run();
  expiredQueue.push(...newlyExpired);
}

// Shares that just expired, waiting for the notification job to tell their owners.
// (Kept as a queue so db.js doesn't need to import the notification module.)
const expiredQueue = [];
export function drainExpiredShares() {
  return expiredQueue.splice(0, expiredQueue.length);
}

/** Returns a SQLite-format timestamp `seconds` in the future, or null for "never". */
export function timestampSecondsFromNow(seconds) {
  if (seconds === null) return null;
  return stmts.nowPlusSeconds.get(seconds).d;
}

/** Create a new share for a file the caller already confirmed they own. */
export function createShare({ fileId, ownerId, recipientId, shareToken, expiresAt, downloadLimit, passwordHash = null }) {
  const info = stmts.insertShare.run(fileId, ownerId, recipientId, shareToken, expiresAt, downloadLimit);
  if (passwordHash) {
    stmts.setSharePasswordStmt.run(passwordHash, info.lastInsertRowid);
  }
  return stmts.shareById.get(info.lastInsertRowid);
}

/** Look up a share by its public token, together with the file it points to. */
export function getShareByToken(token) {
  expireStaleShares();
  return stmts.shareByToken.get(token);
}

/** Fetch one share, but ONLY if it belongs to this owner. */
export function getShareForOwner(shareId, ownerId) {
  return stmts.shareByIdForOwner.get(shareId, ownerId);
}

/** List every share this user created ("My Shares"). */
export function listSharesForOwner(ownerId) {
  expireStaleShares();
  return stmts.sharesForOwner.all(ownerId);
}

/** List every share sent TO this user ("Shared With Me"). */
export function listSharesForRecipient(recipientId) {
  expireStaleShares();
  return stmts.sharesForRecipient.all(recipientId);
}

/** Set a share's status, but ONLY if it belongs to this owner. Returns true if updated. */
export function setShareStatus(shareId, ownerId, status) {
  const info = stmts.setShareStatus.run(status, shareId, ownerId);
  return info.changes > 0;
}

/** Record one successful download against a share, completing it if the limit is now reached. */
export function incrementShareDownload(shareId) {
  stmts.incrementShareDownload.run(shareId);
  stmts.completeShareIfAtLimit.run(shareId);
}

// ── FEATURE 9: ACTIVITY LOG HELPERS ───────────────────────────────────────

/** Fetch up to `limit` activity rows for a user, newest first (filtering by action happens in activity.js). */
export function listActivityForUser(userId, limit = 200) {
  return stmts.activityForUserFiltered.all(userId, limit);
}

// ── FEATURE 10: SECURITY DASHBOARD HELPERS ────────────────────────────────

/** Real counts of this user's shares grouped by status: { active, expired, revoked, completed }. */
export function getShareStatusCounts(ownerId) {
  expireStaleShares();
  const rows = stmts.shareStatusCountsForOwner.all(ownerId);
  const counts = { active: 0, expired: 0, revoked: 0, completed: 0 };
  for (const row of rows) {
    if (Object.prototype.hasOwnProperty.call(counts, row.status)) counts[row.status] = row.n;
  }
  return counts;
}

/** Total number of activity_logs rows for this user — used as "Security Events". */
export function getSecurityEventCount(userId) {
  return stmts.securityEventCountForUser.get(userId).n;
}

/** Number of failed login attempts recorded against this user. */
export function getFailedLoginCount(userId) {
  return stmts.failedLoginCountForUser.get(userId).n;
}

// ── FEATURE 18: ADMIN / SECURITY VIEW HELPERS ────────────────────────────

/** Real, platform-wide counts. No fake numbers — every value is a real query. */
export function getPlatformStats() {
  expireStaleShares();

  const shares = { active: 0, expired: 0, revoked: 0, completed: 0 };
  for (const row of stmts.shareStatusCountsAll.all()) {
    if (Object.prototype.hasOwnProperty.call(shares, row.status)) {
      shares[row.status] = row.n;
    }
  }

  return {
    totalUsers: stmts.countUsers.get().n,
    totalFiles: stmts.countAllFiles.get().n,
    totalShares: stmts.countAllShares.get().n,
    totalDownloads: stmts.countAllDownloads.get().n,
    shares,
  };
}

/** Most recent activity_logs rows across ALL users, newest first, with a display name. */
export function getRecentActivityAllUsers(limit = 15) {
  return stmts.recentActivityAllUsers.all(limit);
}

// ── RECYCLE BIN ───────────────────────────────────────────────────────────

/** Soft-delete: move a file to the Recycle Bin instead of destroying it immediately. */
export function softDeleteFile(fileId, ownerId) {
  const info = stmts.softDeleteFileStmt.run(fileId, ownerId);
  return info.changes > 0;
}

/** Restore a file out of the Recycle Bin back to where it was. */
export function restoreFileFromBin(fileId, ownerId) {
  const info = stmts.restoreFileStmt.run(fileId, ownerId);
  return info.changes > 0;
}

/** Everything currently sitting in this owner's Recycle Bin. */
export function listRecycleBin(ownerId) {
  return stmts.recycleBinForOwner.all(ownerId);
}

/** One deleted file, but ONLY if it belongs to this owner AND is actually in the bin. */
export function getDeletedFileForOwner(fileId, ownerId) {
  return stmts.deletedFileByIdForOwner.get(fileId, ownerId);
}

/** Permanently remove a file row (its on-disk bytes are cleaned up by the caller). */
export function hardDeleteFile(fileId) {
  stmts.hardDeleteFileStmt.run(fileId);
}

/** Every deleted file across all users older than `retentionDays` — used by the auto-purge job. */
export function findExpiredRecycleBinFiles(retentionDays) {
  // A user's own setting (user_settings.recycle_days) overrides the server default.
  return db.prepare(
    `SELECT f.* FROM files f LEFT JOIN user_settings s ON s.user_id = f.owner_id
     WHERE f.deleted_at IS NOT NULL
       AND f.deleted_at <= datetime('now', '-' || COALESCE(s.recycle_days, ?) || ' days')`
  ).all(retentionDays);
}

// ── FILE VERSION HISTORY ─────────────────────────────────────────────────

/**
 * Record a new version. Snapshots the file's CURRENT storage info into
 * file_versions (so it's never lost), then overwrites the files row with
 * the newly uploaded version's info. Old encrypted bytes on disk are left
 * exactly where they are — only the version_number in file_versions
 * changes hands, never the bytes themselves.
 */
export function addFileVersion(fileId, ownerId, newVersionData) {
  const current = stmts.fileByIdForOwner.get(fileId, ownerId);
  if (!current) return null;

  stmts.insertFileVersion.run(
    fileId, current.version, current.original_filename, current.encrypted_filename,
    current.file_path, current.file_size, current.algorithm, current.file_hash, ownerId
  );

  stmts.bumpFileToNewVersion.run(
    newVersionData.encryptedFilename, newVersionData.filePath, newVersionData.fileSize,
    newVersionData.algorithm, newVersionData.fileHash,
    newVersionData.originalFilename || current.original_filename,
    current.version + 1, fileId, ownerId
  );

  return stmts.fileByIdForOwner.get(fileId, ownerId);
}

/** Every OLD version of a file, newest first (the current version lives on the files row itself). */
export function listFileVersions(fileId, ownerId) {
  const file = stmts.fileByIdForOwner.get(fileId, ownerId);
  if (!file) return null;
  return { current: file, olderVersions: stmts.versionsForFile.all(fileId) };
}

/** One specific old version row, but ONLY if it belongs to a file this owner owns. */
export function getFileVersionForOwner(fileId, versionId, ownerId) {
  const file = stmts.fileByIdForOwner.get(fileId, ownerId);
  if (!file) return null;
  return stmts.versionByIdForFile.get(versionId, fileId);
}

/** Delete one OLD version row (never the current version — that's not in this table). */
export function deleteFileVersion(fileId, versionId, ownerId) {
  const file = stmts.fileByIdForOwner.get(fileId, ownerId);
  if (!file) return null;
  const version = stmts.versionByIdForFile.get(versionId, fileId);
  if (!version) return null;
  stmts.deleteVersionStmt.run(versionId, fileId);
  return version;
}

/**
 * Restore an old version: the CURRENT version is snapshotted into
 * file_versions (nothing is destroyed), then the files row is set to a
 * COPY of the old version's bytes (the caller physically copies the file
 * on disk and passes the new path in `copiedStorage`) at the next version
 * number — same non-destructive approach git uses for "revert".
 */
export function restoreFileVersion(fileId, ownerId, copiedStorage) {
  return addFileVersion(fileId, ownerId, copiedStorage);
}

// ── MULTI-FILE SHARES ────────────────────────────────────────────────────
export function addShareItems(shareId, fileIds) {
  const ins = db.prepare('INSERT OR IGNORE INTO share_items (share_id, file_id) VALUES (?, ?)');
  for (const id of fileIds) ins.run(shareId, id);
}
/** Items of a share whose files are not in the Recycle Bin. itemId is opaque outside this share. */
export function getShareItems(shareId) {
  return db.prepare(
    `SELECT si.id AS item_id, f.original_filename, f.file_size, f.algorithm, f.file_path
     FROM share_items si JOIN files f ON f.id = si.file_id
     WHERE si.share_id = ? AND f.deleted_at IS NULL ORDER BY si.id`
  ).all(shareId);
}
export function hasShareItems(shareId) {
  return db.prepare('SELECT COUNT(*) AS n FROM share_items WHERE share_id = ?').get(shareId).n > 0;
}

// ── APP SETTINGS (default storage quota etc.) ────────────────────────────
const DEFAULT_QUOTA_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB per user, overridable by admin or per-user

export function getAppSetting(key, fallback = null) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}
export function setAppSetting(key, value) {
  db.prepare(`INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, String(value));
}
export function getDefaultQuotaBytes() {
  const v = getAppSetting('default_quota_bytes');
  return v ? parseInt(v, 10) : DEFAULT_QUOTA_BYTES;
}

// ── STORAGE QUOTAS (Feature 6) ────────────────────────────────────────────
export function getUserQuotaBytes(userId) {
  const u = db.prepare('SELECT storage_quota_bytes FROM users WHERE id = ?').get(userId);
  return (u && u.storage_quota_bytes) || getDefaultQuotaBytes();
}
export function getUserStorageUsedBytes(userId) {
  return db.prepare('SELECT COALESCE(SUM(file_size),0) AS n FROM files WHERE owner_id = ? AND deleted_at IS NULL').get(userId).n;
}
export function setUserQuota(userId, bytes) {
  db.prepare('UPDATE users SET storage_quota_bytes = ? WHERE id = ?').run(bytes, userId);
}
/** Would uploading `incomingBytes` more push this user over quota? */
export function wouldExceedQuota(userId, incomingBytes) {
  return getUserStorageUsedBytes(userId) + incomingBytes > getUserQuotaBytes(userId);
}

// ── DUPLICATE DETECTION (Feature 7) ───────────────────────────────────────
/** Non-deleted files this owner already has with the same content hash. */
export function findDuplicateFiles(ownerId, fileHash) {
  return db.prepare('SELECT id, original_filename, created_at FROM files WHERE owner_id = ? AND file_hash = ? AND deleted_at IS NULL')
    .all(ownerId, fileHash);
}

// ── FILE TAGGING (Feature 15) ─────────────────────────────────────────────
const TAG_RE = /^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,29}$/;
export function isValidTag(tag) { return typeof tag === 'string' && TAG_RE.test(tag.trim()); }
export function addTag(fileId, ownerId, tag) {
  const file = db.prepare('SELECT id FROM files WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(fileId, ownerId);
  if (!file) return false;
  db.prepare('INSERT OR IGNORE INTO file_tags (file_id, tag) VALUES (?, ?)').run(fileId, tag.trim());
  return true;
}
export function removeTag(fileId, ownerId, tag) {
  const file = db.prepare('SELECT id FROM files WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').get(fileId, ownerId);
  if (!file) return false;
  db.prepare('DELETE FROM file_tags WHERE file_id = ? AND tag = ?').run(fileId, tag.trim());
  return true;
}
export function getTagsForFile(fileId) {
  return db.prepare('SELECT tag FROM file_tags WHERE file_id = ? ORDER BY tag').all(fileId).map((r) => r.tag);
}
export function getTagsForFiles(fileIds) {
  if (fileIds.length === 0) return new Map();
  const placeholders = fileIds.map(() => '?').join(',');
  const rows = db.prepare(`SELECT file_id, tag FROM file_tags WHERE file_id IN (${placeholders}) ORDER BY tag`).all(...fileIds);
  const map = new Map();
  for (const r of rows) { if (!map.has(r.file_id)) map.set(r.file_id, []); map.get(r.file_id).push(r.tag); }
  return map;
}
export function listAllTagsForOwner(ownerId) {
  return db.prepare(`SELECT ft.tag, COUNT(*) AS n FROM file_tags ft JOIN files f ON f.id = ft.file_id
    WHERE f.owner_id = ? AND f.deleted_at IS NULL GROUP BY ft.tag ORDER BY ft.tag`).all(ownerId);
}

// ── FILE EXPIRATION / AUTO-DELETE (Feature 12) ────────────────────────────
export function setFileExpiration(fileId, ownerId, expiresAt) {
  const info = db.prepare('UPDATE files SET expires_at = ? WHERE id = ? AND owner_id = ? AND deleted_at IS NULL').run(expiresAt, fileId, ownerId);
  return info.changes > 0;
}
/** Non-deleted files whose expiry has passed — used by the auto-delete job. */
export function findExpiredFiles() {
  return db.prepare(`SELECT * FROM files WHERE expires_at IS NOT NULL AND expires_at <= datetime('now') AND deleted_at IS NULL`).all();
}
/** Files expiring within `hours` — used for the "expiring soon" warning. */
export function findFilesExpiringSoon(ownerId, hours = 24) {
  return db.prepare(`SELECT id, original_filename, expires_at FROM files
    WHERE owner_id = ? AND deleted_at IS NULL AND expires_at IS NOT NULL
      AND expires_at <= datetime('now', '+' || ? || ' hours') AND expires_at > datetime('now')
    ORDER BY expires_at`).all(ownerId, hours);
}

// ── FILE INTEGRITY (Feature 4) ────────────────────────────────────────────
export function recordVerification(fileId, ownerId, status) {
  const info = db.prepare(`UPDATE files SET last_verified_at = datetime('now'), verification_status = ? WHERE id = ? AND owner_id = ? AND deleted_at IS NULL`)
    .run(status, fileId, ownerId);
  return info.changes > 0;
}
export function getIntegritySummary(ownerId) {
  const row = db.prepare(`SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN verification_status = 'ok' THEN 1 ELSE 0 END) AS verified,
      SUM(CASE WHEN verification_status = 'failed' THEN 1 ELSE 0 END) AS failed,
      SUM(CASE WHEN verification_status = 'unverified' THEN 1 ELSE 0 END) AS never_verified,
      SUM(CASE WHEN last_verified_at IS NOT NULL AND last_verified_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) AS recently_verified
    FROM files WHERE owner_id = ? AND deleted_at IS NULL`).get(ownerId);
  return { total: row.total || 0, verified: row.verified || 0, failed: row.failed || 0, neverVerified: row.never_verified || 0, recentlyVerified: row.recently_verified || 0 };
}

// ── ADMIN: USER MANAGEMENT (Feature 9) ────────────────────────────────────
export function listUsersForAdmin() {
  return db.prepare(`SELECT u.id, u.name, u.email, u.status, u.created_at, u.last_login, u.is_admin, u.storage_quota_bytes,
      (SELECT COUNT(*) FROM files f WHERE f.owner_id = u.id AND f.deleted_at IS NULL) AS file_count,
      (SELECT COALESCE(SUM(file_size),0) FROM files f WHERE f.owner_id = u.id AND f.deleted_at IS NULL) AS storage_bytes,
      (SELECT COUNT(*) FROM shares s WHERE s.owner_id = u.id) AS share_count
    FROM users u ORDER BY u.id`).all();
}
export function setUserStatus(userId, status) {
  const info = db.prepare(`UPDATE users SET status = ? WHERE id = ?`).run(status, userId);
  return info.changes > 0;
}
export function isUserSuspended(userId) {
  const u = db.prepare('SELECT status FROM users WHERE id = ?').get(userId);
  return !!(u && u.status === 'suspended');
}

// ── SYSTEM-WIDE SECURITY AUDIT (Feature 10) ───────────────────────────────
export function eventsByDay(actions, days = 14) {
  const placeholders = actions.map(() => '?').join(',');
  return db.prepare(`SELECT date(created_at) AS d, COUNT(*) AS n FROM activity_logs WHERE action IN (${placeholders}) AND created_at >= datetime('now','-' || ? || ' days') GROUP BY d`)
    .all(...actions, days - 1);
}
export function eventsByType(limit = 15) {
  return db.prepare('SELECT action, COUNT(*) AS n FROM activity_logs GROUP BY action ORDER BY n DESC LIMIT ?').all(limit);
}
export function loginSuccessVsFailByDay(days = 14) {
  return db.prepare(`SELECT date(created_at) AS d, action, COUNT(*) AS n FROM activity_logs WHERE action IN ('LOGIN','FAILED_LOGIN') AND created_at >= datetime('now','-' || ? || ' days') GROUP BY d, action`).all(days - 1);
}

export default db;
