/**
 * VaultShare 2.0 — uploads.js
 * =====================================================================
 * Feature: Resumable large-file uploads (chunked).
 *
 * The browser encrypts the whole file first (unchanged zero-knowledge
 * flow), then sends the ENCRYPTED package in 4 MB chunks:
 *
 *   POST   /api/uploads/init          {originalFilename,totalSize,algorithm,fileHash}
 *   GET    /api/uploads/:id           -> { received }  (ask where to resume)
 *   PUT    /api/uploads/:id?offset=N  raw bytes; N must equal bytes already received
 *   POST   /api/uploads/:id/complete  -> validates size + "VLTE" header, creates the vault file
 *   DELETE /api/uploads/:id           cancel
 *
 * If the network drops, the client asks GET /api/uploads/:id and continues
 * from `received` instead of starting again. Chunks are only accepted in
 * order at the exact offset, so a retry can never corrupt the file.
 * Stale unfinished uploads are deleted after 24 h.
 * =====================================================================
 */
'use strict';
import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import db, { insertFile, logActivity, wouldExceedQuota, findDuplicateFiles } from './db.js';
import { requireAuthApi } from './auth.js';
import { isBlockedFilename } from './vault.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VAULT_ROOT = path.join(__dirname, 'vault-storage');
const MAX_BYTES = 500 * 1024 * 1024;
const MAX_CHUNK = 8 * 1024 * 1024;
const MAGIC = Buffer.from('VLTE');
const ALGOS = new Set(['AES-256-GCM', 'AES-256-CBC', 'AES-256-CTR']);
const router = express.Router();

const cleanName = (n) => String(n || 'file').replace(/[\\/]/g, '_').replace(/[\x00-\x1f]/g, '').trim().slice(0, 255) || 'file';
const getSession = (id, userId) => db.prepare('SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?').get(id, userId);
const validId = (id) => /^[0-9a-f]{32}$/.test(id);

router.post('/api/uploads/init', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const { originalFilename, totalSize, algorithm, fileHash } = req.body || {};
    const errors = [];
    const size = Number(totalSize);
    if (!originalFilename || typeof originalFilename !== 'string') errors.push('Missing original filename.');
    else if (isBlockedFilename(originalFilename)) errors.push('Executable file types (.exe, .bat, .cmd, .msi, …) are not allowed.');
    if (!Number.isInteger(size) || size < 5 || size > MAX_BYTES) errors.push('File size must be between 5 bytes and 500 MB.');
    if (!ALGOS.has(algorithm)) errors.push('Unrecognized encryption algorithm.');
    if (!/^[0-9a-f]{64}$/i.test(fileHash || '')) errors.push('Missing or malformed SHA-256 hash.');
    if (Number.isInteger(size) && wouldExceedQuota(userId, size)) errors.push('Storage quota exceeded.');
    if (errors.length) return res.status(400).json({ ok: false, errors });

    // Duplicate detection (Feature 7) — same backstop as the single-shot upload route.
    if (req.body?.confirmDuplicate !== true) {
      const dupes = findDuplicateFiles(userId, fileHash.toLowerCase());
      if (dupes.length > 0) return res.status(409).json({ ok: false, duplicate: true, errors: ['An identical file already exists in your vault.'], existing: dupes });
    }

    const id = crypto.randomBytes(16).toString('hex');
    const dir = path.join(VAULT_ROOT, String(userId), '.partial');
    fs.mkdirSync(dir, { recursive: true });
    const tempPath = path.join(dir, `${id}.part`);
    fs.writeFileSync(tempPath, Buffer.alloc(0));
    db.prepare('INSERT INTO upload_sessions (id, user_id, filename, total_size, algorithm, file_hash, temp_path) VALUES (?,?,?,?,?,?,?)')
      .run(id, userId, cleanName(originalFilename), size, algorithm, fileHash.toLowerCase(), path.relative(__dirname, tempPath));
    res.status(201).json({ ok: true, uploadId: id, chunkSize: 4 * 1024 * 1024 });
  } catch (e) {
    console.error('[uploads] init error:', e.message);
    res.status(500).json({ ok: false, errors: ['Could not start upload.'] });
  }
});

router.get('/api/uploads/:id', requireAuthApi, (req, res) => {
  const s = validId(req.params.id) ? getSession(req.params.id, req.session.userId) : null;
  if (!s) return res.status(404).json({ ok: false, errors: ['Upload not found (it may have expired). Start again.'] });
  res.json({ ok: true, received: s.received, totalSize: s.total_size });
});

router.put('/api/uploads/:id', requireAuthApi,
  express.raw({ type: 'application/octet-stream', limit: MAX_CHUNK }),
  (req, res) => {
    try {
      const s = validId(req.params.id) ? getSession(req.params.id, req.session.userId) : null;
      if (!s) return res.status(404).json({ ok: false, errors: ['Upload not found (it may have expired). Start again.'] });
      const offset = parseInt(req.query.offset, 10);
      const chunk = req.body;
      if (!Buffer.isBuffer(chunk) || chunk.length === 0) return res.status(400).json({ ok: false, errors: ['Empty chunk.'] });
      if (offset !== s.received) {
        return res.status(409).json({ ok: false, errors: ['Chunk out of order.'], received: s.received });
      }
      if (s.received + chunk.length > s.total_size) return res.status(400).json({ ok: false, errors: ['Upload is larger than declared.'] });
      const abs = path.join(__dirname, s.temp_path);
      if (!abs.startsWith(VAULT_ROOT)) return res.status(400).json({ ok: false, errors: ['Bad upload.'] });
      fs.appendFileSync(abs, chunk);
      const received = s.received + chunk.length;
      db.prepare("UPDATE upload_sessions SET received = ?, updated_at = datetime('now') WHERE id = ?").run(received, s.id);
      res.json({ ok: true, received });
    } catch (e) {
      console.error('[uploads] chunk error:', e.message);
      res.status(500).json({ ok: false, errors: ['Could not store chunk.'] });
    }
  });

router.post('/api/uploads/:id/complete', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const s = validId(req.params.id) ? getSession(req.params.id, userId) : null;
    if (!s) return res.status(404).json({ ok: false, errors: ['Upload not found.'] });
    if (s.received !== s.total_size) return res.status(400).json({ ok: false, errors: ['Upload is incomplete.'], received: s.received });
    const tmp = path.join(__dirname, s.temp_path);
    const fd = fs.openSync(tmp, 'r'); const head = Buffer.alloc(4); fs.readSync(fd, head, 0, 4, 0); fs.closeSync(fd);
    if (!head.equals(MAGIC)) {
      fs.unlink(tmp, () => {}); db.prepare('DELETE FROM upload_sessions WHERE id = ?').run(s.id);
      return res.status(400).json({ ok: false, errors: ['File does not look like a valid VaultShare (.vaultenc) package.'] });
    }
    const name = `${crypto.randomUUID()}.vaultenc`;
    const finalAbs = path.join(VAULT_ROOT, String(userId), name);
    fs.renameSync(tmp, finalAbs);
    const row = insertFile({ ownerId: userId, originalFilename: s.filename, encryptedFilename: name, filePath: path.relative(__dirname, finalAbs),
      fileSize: s.total_size, algorithm: s.algorithm, fileHash: s.file_hash });
    db.prepare('DELETE FROM upload_sessions WHERE id = ?').run(s.id);
    logActivity(userId, 'UPLOAD', { fileId: row.id, ip: req.ip, userAgent: req.get('user-agent') });
    res.status(201).json({ ok: true, file: { id: row.id, original_filename: row.original_filename, file_size: row.file_size } });
  } catch (e) {
    console.error('[uploads] complete error:', e.message);
    res.status(500).json({ ok: false, errors: ['Could not finish upload.'] });
  }
});

router.delete('/api/uploads/:id', requireAuthApi, (req, res) => {
  const s = validId(req.params.id) ? getSession(req.params.id, req.session.userId) : null;
  if (!s) return res.status(404).json({ ok: false, errors: ['Upload not found.'] });
  fs.unlink(path.join(__dirname, s.temp_path), () => {});
  db.prepare('DELETE FROM upload_sessions WHERE id = ?').run(s.id);
  res.json({ ok: true });
});

/** Deletes unfinished uploads not touched for 24 hours. */
export function purgeStaleUploads() {
  try {
    const stale = db.prepare("SELECT id, temp_path FROM upload_sessions WHERE updated_at <= datetime('now','-1 day')").all();
    for (const s of stale) {
      fs.unlink(path.join(__dirname, s.temp_path), () => {});
      db.prepare('DELETE FROM upload_sessions WHERE id = ?').run(s.id);
    }
  } catch (e) { console.error('[uploads] purge error:', e.message); }
}
export default router;
