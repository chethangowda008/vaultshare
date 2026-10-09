/**
 * VaultShare 2.0 — recyclebin.js
 * =====================================================================
 * Feature: Recycle Bin.
 *
 * Deleting a file from the Vault (see the updated DELETE route in
 * vault.js) no longer destroys it immediately — it's soft-deleted
 * (files.deleted_at is set) and shows up here instead. It stays
 * completely unreachable through the normal /api/vault/download/:id
 * route (that query only ever matches deleted_at IS NULL rows).
 *
 * Exposes:
 *   GET    /api/recycle-bin              — list this user's deleted files
 *   POST   /api/recycle-bin/:id/restore  — restore a file back to the Vault
 *   DELETE /api/recycle-bin/:id          — permanently delete ONE file
 *   DELETE /api/recycle-bin              — empty the whole bin
 *
 * Also exports startRecycleBinPurgeJob(), called once from server.js,
 * which permanently deletes anything older than RECYCLE_BIN_RETENTION_DAYS
 * (default 30, configurable via that env var) on a recurring timer.
 * =====================================================================
 */

'use strict';

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { requireAuthApi } from './auth.js';
import db, {
  listRecycleBin, getDeletedFileForOwner, restoreFileFromBin,
  hardDeleteFile, findExpiredRecycleBinFiles, logActivity,
} from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const VAULT_ROOT = path.join(__dirname, 'vault-storage');

export const RECYCLE_BIN_RETENTION_DAYS =
  parseInt(process.env.RECYCLE_BIN_RETENTION_DAYS, 10) > 0
    ? parseInt(process.env.RECYCLE_BIN_RETENTION_DAYS, 10)
    : 30;

const router = express.Router();

/** Best-effort removal of a file's bytes from disk — DB is the source of truth either way. */
function unlinkQuiet(relativePath) {
  if (!relativePath) return;
  const absolutePath = path.join(__dirname, relativePath);
  if (absolutePath.startsWith(VAULT_ROOT)) {
    fs.unlink(absolutePath, () => {});
  }
}

// ── GET /api/recycle-bin ────────────────────────────────────────────────
router.get('/api/recycle-bin', requireAuthApi, (req, res) => {
  try {
    const files = listRecycleBin(req.session.userId).map((f) => ({
      id: f.id,
      original_filename: f.original_filename,
      file_size: f.file_size,
      algorithm: f.algorithm,
      deleted_at: f.deleted_at,
    }));
    const own = db.prepare('SELECT recycle_days FROM user_settings WHERE user_id = ?').get(req.session.userId);
    return res.json({ ok: true, files, retentionDays: (own && own.recycle_days) || RECYCLE_BIN_RETENTION_DAYS });
  } catch (e) {
    console.error('[recycle-bin] list error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load Recycle Bin.'] });
  }
});

// ── POST /api/recycle-bin/:id/restore ───────────────────────────────────
router.post('/api/recycle-bin/:id/restore', requireAuthApi, (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (!Number.isInteger(fileId)) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });

    const ok = restoreFileFromBin(fileId, req.session.userId);
    if (!ok) return res.status(404).json({ ok: false, errors: ['File not found in Recycle Bin.'] });

    logActivity(req.session.userId, 'FILE_RESTORE', { fileId, ip: req.ip, userAgent: req.get('user-agent') });
    return res.json({ ok: true });
  } catch (e) {
    console.error('[recycle-bin] restore error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not restore file.'] });
  }
});

// ── DELETE /api/recycle-bin/:id — permanently delete ONE file ─────────
router.delete('/api/recycle-bin/:id', requireAuthApi, (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (!Number.isInteger(fileId)) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });

    const file = getDeletedFileForOwner(fileId, req.session.userId);
    if (!file) return res.status(404).json({ ok: false, errors: ['File not found in Recycle Bin.'] });

    logActivity(req.session.userId, 'FILE_PURGE', { fileId, ip: req.ip, userAgent: req.get('user-agent') });
    hardDeleteFile(fileId); // ON DELETE CASCADE also removes its file_versions rows
    unlinkQuiet(file.file_path);

    return res.json({ ok: true });
  } catch (e) {
    console.error('[recycle-bin] permanent delete error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not permanently delete file.'] });
  }
});

// ── DELETE /api/recycle-bin — empty the whole bin ──────────────────────
router.delete('/api/recycle-bin', requireAuthApi, (req, res) => {
  try {
    const files = listRecycleBin(req.session.userId);
    for (const file of files) {
      hardDeleteFile(file.id);
      unlinkQuiet(file.file_path);
    }
    logActivity(req.session.userId, 'RECYCLE_BIN_EMPTY', { ip: req.ip, userAgent: req.get('user-agent') });
    return res.json({ ok: true, count: files.length });
  } catch (e) {
    console.error('[recycle-bin] empty error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not empty Recycle Bin.'] });
  }
});

/**
 * Permanently deletes anything that has been in the Recycle Bin longer
 * than RECYCLE_BIN_RETENTION_DAYS. Safe to call as often as you like.
 */
export function purgeExpiredRecycleBin() {
  try {
    const expired = findExpiredRecycleBinFiles(RECYCLE_BIN_RETENTION_DAYS);
    for (const file of expired) {
      hardDeleteFile(file.id);
      unlinkQuiet(file.file_path);
      logActivity(file.owner_id, 'FILE_AUTO_PURGE', { fileId: file.id });
    }
    if (expired.length > 0) {
      console.log(`[recycle-bin] Auto-purged ${expired.length} file(s) older than ${RECYCLE_BIN_RETENTION_DAYS} days.`);
    }
  } catch (e) {
    console.error('[recycle-bin] auto-purge error:', e.message);
  }
}

/** Starts the recurring auto-purge timer. Call once from server.js. */
export function startRecycleBinPurgeJob() {
  purgeExpiredRecycleBin(); // run once at startup
  setInterval(purgeExpiredRecycleBin, 6 * 60 * 60 * 1000); // then every 6 hours
}

export default router;
