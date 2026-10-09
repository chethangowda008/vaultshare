/**
 * VaultShare — fileops.js
 * =====================================================================
 * Tagging, file expiration/auto-delete, and integrity verification.
 * Kept in one router since each is a small, focused extension of an
 * existing file row rather than a new subsystem.
 *
 * NOTE: Favorites, Security Incidents, and Notifications were removed
 * from this file on request. Their database tables/columns were either
 * dropped (security_incidents, notifications, notification_prefs — see
 * db.js migrations) or, for the shared `files.is_favorite` column, left
 * in place but unused (dropping a column from a table other features
 * still write to was judged an unnecessary risk to existing data).
 *
 * INTEGRITY VERIFICATION — HONEST DESIGN NOTE (viva-relevant):
 * The server cannot recompute a plaintext SHA-256 itself, because the
 * file is encrypted and the server never has the password (zero-
 * knowledge). So there are two tiers:
 *   1. "Quick check" (server-side, no password needed): confirms the
 *      encrypted file still exists on disk, is the expected size, and
 *      still starts with the VaultShare "VLTE" header. Catches
 *      corruption/truncation, NOT tampering with content.
 *   2. "Full verify" (client-side): the browser downloads and decrypts
 *      the file with the password (same code path as Preview/Decrypt),
 *      recomputes SHA-256 of the plaintext, and compares it to the hash
 *      stored at upload time. The RESULT (pass/fail) is then reported
 *      to the server so verification_status/last_verified_at update.
 *      (A failure used to also raise a Security Incident and send a
 *      notification — both removed. The verification result itself is
 *      still recorded and visible on the file.)
 * =====================================================================
 */
'use strict';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  isValidTag, addTag, removeTag, getTagsForFile, listAllTagsForOwner,
  setFileExpiration, findFilesExpiringSoon, findExpiredFiles, softDeleteFile, getFileForOwner,
  recordVerification, getIntegritySummary, logActivity,
} from './db.js';
import { requireAuthApi } from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VAULT_ROOT = path.join(__dirname, 'vault-storage');
const MAGIC = Buffer.from([0x56, 0x4c, 0x54, 0x45]); // "VLTE"
const router = express.Router();

const fileIdParam = (req) => { const n = parseInt(req.params.id, 10); return Number.isInteger(n) ? n : null; };
const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

// ── TAGGING ────────────────────────────────────────────────────────────
router.post('/api/vault/files/:id/tags', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  const tag = (req.body || {}).tag;
  if (id === null) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });
  if (!isValidTag(tag)) return res.status(400).json({ ok: false, errors: ['Tags may only contain letters, numbers, spaces, "-" or "_" (max 30 chars).'] });
  if (!addTag(id, req.session.userId, tag)) return res.status(404).json({ ok: false, errors: ['File not found.'] });
  res.json({ ok: true, tags: getTagsForFile(id) });
});
router.delete('/api/vault/files/:id/tags/:tag', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  if (id === null) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });
  if (!removeTag(id, req.session.userId, req.params.tag)) return res.status(404).json({ ok: false, errors: ['File not found.'] });
  res.json({ ok: true, tags: getTagsForFile(id) });
});
router.get('/api/vault/files/:id/tags', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  if (id === null || !getFileForOwner(id, req.session.userId)) return res.status(404).json({ ok: false, errors: ['File not found.'] });
  res.json({ ok: true, tags: getTagsForFile(id) });
});
router.get('/api/vault/tags', requireAuthApi, (req, res) => {
  res.json({ ok: true, tags: listAllTagsForOwner(req.session.userId) });
});

// ── FILE EXPIRATION / AUTO-DELETE ────────────────────────────────────────
const EXPIRY_PRESETS = { '1d': 1, '7d': 7, '30d': 30 };
router.put('/api/vault/files/:id/expiration', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  const { preset, customDate } = req.body || {};
  if (id === null) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });

  let expiresAt = null;
  if (preset === 'none') {
    expiresAt = null;
  } else if (preset && EXPIRY_PRESETS[preset]) {
    expiresAt = new Date(Date.now() + EXPIRY_PRESETS[preset] * 86400000).toISOString().slice(0, 19).replace('T', ' ');
  } else if (preset === 'custom') {
    const d = new Date(customDate);
    if (Number.isNaN(d.getTime()) || d.getTime() <= Date.now()) {
      return res.status(400).json({ ok: false, errors: ['Custom expiration must be a valid future date.'] });
    }
    expiresAt = d.toISOString().slice(0, 19).replace('T', ' ');
  } else {
    return res.status(400).json({ ok: false, errors: ['Invalid expiration preset.'] });
  }

  if (!setFileExpiration(id, req.session.userId, expiresAt)) return res.status(404).json({ ok: false, errors: ['File not found.'] });
  logActivity(req.session.userId, 'FILE_EXPIRATION_SET', { fileId: id, ...ctx(req) });
  res.json({ ok: true, expiresAt });
});
router.get('/api/vault/expiring-soon', requireAuthApi, (req, res) => {
  const hours = Math.min(24 * 30, Math.max(1, parseInt(req.query.hours, 10) || 24));
  res.json({ ok: true, files: findFilesExpiringSoon(req.session.userId, hours) });
});

/** Permanently deletes nothing — just moves due files to the Recycle Bin (the existing recycle-bin purge job handles the rest). */
export async function runExpirationJob() {
  try {
    for (const f of findExpiredFiles()) {
      softDeleteFile(f.id, f.owner_id);
      logActivity(f.owner_id, 'FILE_AUTO_EXPIRED', { fileId: f.id });
    }
  } catch (e) {
    console.error('[fileops] expiration job error:', e.message);
  }
}

/** Starts the recurring file-expiration timer (runs once at start-up, then hourly). Call once from server.js. */
export function startExpirationJob() {
  runExpirationJob();
  setInterval(runExpirationJob, 60 * 60 * 1000);
}

// ── FILE INTEGRITY ────────────────────────────────────────────────────────

// Quick, server-side, password-free check: existence, size, magic header.
router.post('/api/integrity/:id/quick-check', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  const file = id === null ? null : getFileForOwner(id, req.session.userId);
  if (!file) return res.status(404).json({ ok: false, errors: ['File not found.'] });

  const absPath = path.join(__dirname, file.file_path);
  let status = 'ok';
  const problems = [];
  if (!absPath.startsWith(VAULT_ROOT) || !fs.existsSync(absPath)) {
    status = 'failed'; problems.push('File is missing from storage.');
  } else {
    const stat = fs.statSync(absPath);
    if (stat.size !== file.file_size) { status = 'failed'; problems.push(`Stored size (${stat.size}) does not match the recorded size (${file.file_size}).`); }
    const fd = fs.openSync(absPath, 'r'); const head = Buffer.alloc(4); fs.readSync(fd, head, 0, 4, 0); fs.closeSync(fd);
    if (!head.equals(MAGIC)) { status = 'failed'; problems.push('File no longer starts with a valid VaultShare header.'); }
  }

  logActivity(req.session.userId, 'INTEGRITY_CHECK', { fileId: id, ...ctx(req) });
  res.json({ ok: true, status, problems, note: 'Quick check confirms the encrypted file is intact on disk. It cannot detect tampering with content — use Full Verify (decrypts in your browser) for that.' });
});

// Full verify: the BROWSER already decrypted and compared hashes; this just records the result.
router.post('/api/integrity/:id/report', requireAuthApi, (req, res) => {
  const id = fileIdParam(req);
  const { status } = req.body || {};
  if (id === null || !['ok', 'failed'].includes(status)) return res.status(400).json({ ok: false, errors: ['Invalid request.'] });
  const file = getFileForOwner(id, req.session.userId);
  if (!file) return res.status(404).json({ ok: false, errors: ['File not found.'] });

  recordVerification(id, req.session.userId, status);
  logActivity(req.session.userId, 'INTEGRITY_VERIFY', { fileId: id, ...ctx(req) });
  res.json({ ok: true });
});

router.get('/api/integrity/summary', requireAuthApi, (req, res) => {
  res.json({ ok: true, summary: getIntegritySummary(req.session.userId) });
});

export default router;
