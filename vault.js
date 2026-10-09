/**
 * VaultShare — vault.js
 * =====================================================================
 * Feature 4: Personal Vault.
 *
 * IMPORTANT SECURITY NOTE — READ THIS FIRST:
 * All encryption and decryption still happen ONLY in the browser
 * (see public/js/crypto.js). This file NEVER sees a plaintext file and
 * NEVER sees an encryption password. It only stores and serves back
 * the already-encrypted ".vaultenc" bytes the browser produced, and
 * keeps metadata about them in the database.
 *
 * Exposes:
 *   POST   /api/vault/upload         — store an encrypted file
 *   GET    /api/vault/files          — list the logged-in user's files
 *   GET    /api/vault/download/:id   — download one of the user's files
 *   DELETE /api/vault/files/:id      — delete one of the user's files
 *
 * Every route is protected by requireAuthApi, and every lookup filters
 * by owner_id server-side — the file id alone is never enough to read
 * or delete someone else's file, no matter what the frontend sends.
 * =====================================================================
 */

'use strict';

import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

import { requireAuthApi } from './auth.js';
import {
  insertFile, listFilesForOwner, getFileForOwner, deleteFileForOwner, logActivity,
  softDeleteFile, addFileVersion, listFileVersions, getFileVersionForOwner,
  deleteFileVersion, restoreFileVersion,
  wouldExceedQuota, getUserQuotaBytes, getUserStorageUsedBytes, findDuplicateFiles,
} from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const router = express.Router();

// ── STORAGE LOCATION ──────────────────────────────────────────────────
// Encrypted files live OUTSIDE public/, so they can only ever be served
// through the authenticated /api/vault/download/:id route below —
// never as a raw static file.
const VAULT_ROOT = path.join(__dirname, 'vault-storage');
if (!fs.existsSync(VAULT_ROOT)) fs.mkdirSync(VAULT_ROOT, { recursive: true });

const MAX_UPLOAD_BYTES = 500 * 1024 * 1024; // 500 MB — matches the UI's stated limit
const ALLOWED_ALGORITHMS = new Set(['AES-256-GCM', 'AES-256-CBC', 'AES-256-CTR']);
const VAULTENC_MAGIC = Buffer.from([0x56, 0x4c, 0x54, 0x45]); // "VLTE"

/** Strips path separators/control characters so a filename is safe to store and display. */
function sanitizeFilename(name) {
  const base = String(name || 'file')
    .replace(/[\\/]/g, '_')
    .replace(/[\x00-\x1f]/g, '')
    .trim();
  return base.slice(0, 255) || 'file';
}

// Executable / script-launcher types are refused. The bytes on the server are
// ciphertext (so content can't be scanned), which makes the FILENAME the only
// thing we can policy here; stored files are never executed and are always
// served as downloads with nosniff.
export const BLOCKED_EXTENSIONS = new Set(['exe', 'bat', 'cmd', 'com', 'scr', 'msi', 'dll', 'vbs', 'ps1', 'pif', 'cpl', 'jar', 'app', 'apk']);
export function isBlockedFilename(name) {
  const m = /\.([a-z0-9]+)$/i.exec(String(name || ''));
  return !!(m && BLOCKED_EXTENSIONS.has(m[1].toLowerCase()));
}

// ── MULTER STORAGE ────────────────────────────────────────────────────
// The filename on disk is ALWAYS a fresh random UUID — never derived
// from anything the client sent — so there is no path-traversal risk
// and no way for one user's upload to overwrite another's file.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userId = req.session && req.session.userId;
    if (!userId) return cb(new Error('Not logged in.'));
    const userDir = path.join(VAULT_ROOT, String(userId));
    fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${crypto.randomUUID()}.vaultenc`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
});

// ── POST /api/vault/upload ────────────────────────────────────────────
// ── POST /api/vault/check-duplicate — pre-upload check (Feature 7) ────
// Lets the browser warn "An identical file already exists" and offer
// Upload anyway / Cancel BEFORE spending time uploading and encrypting again.
router.post('/api/vault/check-duplicate', requireAuthApi, (req, res) => {
  const { fileHash } = req.body || {};
  if (!fileHash || !/^[0-9a-f]{64}$/i.test(fileHash)) {
    return res.status(400).json({ ok: false, errors: ['Missing or malformed SHA-256 hash.'] });
  }
  const existing = findDuplicateFiles(req.session.userId, fileHash.toLowerCase());
  res.json({ ok: true, duplicate: existing.length > 0, existing });
});

// ── GET /api/vault/quota — current usage vs limit (Feature 6) ─────────
router.get('/api/vault/quota', requireAuthApi, (req, res) => {
  const userId = req.session.userId;
  const used = getUserStorageUsedBytes(userId);
  const limit = getUserQuotaBytes(userId);
  res.json({ ok: true, usedBytes: used, limitBytes: limit, remainingBytes: Math.max(0, limit - used), percentUsed: limit ? Math.min(100, Math.round((used / limit) * 100)) : 0 });
});

router.post('/api/vault/upload', requireAuthApi, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? 'File is larger than the 500 MB limit.'
        : 'Upload failed.';
      return res.status(400).json({ ok: false, errors: [msg] });
    }

    try {
      const userId = req.session.userId;
      const uploaded = req.file;
      const { originalFilename, algorithm, fileHash } = req.body || {};

      // ── Validate everything the browser sent ──
      const errors = [];
      if (!uploaded) errors.push('No file was received.');
      if (!originalFilename || typeof originalFilename !== 'string') {
        errors.push('Missing original filename.');
      } else if (isBlockedFilename(originalFilename)) {
        errors.push('Executable file types (.exe, .bat, .cmd, .msi, …) are not allowed.');
      }
      if (!ALLOWED_ALGORITHMS.has(algorithm)) {
        errors.push('Unrecognized encryption algorithm.');
      }
      if (!fileHash || !/^[0-9a-f]{64}$/i.test(fileHash)) {
        errors.push('Missing or malformed SHA-256 hash.');
      }

      // ── STORAGE QUOTA (Feature 6) ──
      if (uploaded && wouldExceedQuota(userId, uploaded.size)) {
        errors.push(`Storage quota exceeded. You have ${getUserStorageUsedBytes(userId)} of ${getUserQuotaBytes(userId)} bytes used.`);
      }

      // ── DUPLICATE DETECTION (Feature 7) — server-side guard; the FRONTEND
      // also checks /api/vault/check-duplicate BEFORE upload so the user sees
      // a warning and can choose. This is the backstop if that step is skipped
      // (e.g. a direct API call) — allowUpload=false lets a same-hash upload be
      // explicitly confirmed by the client after the warning.
      if (fileHash && /^[0-9a-f]{64}$/i.test(fileHash) && req.body?.confirmDuplicate !== 'true') {
        const dupes = findDuplicateFiles(userId, fileHash.toLowerCase());
        if (dupes.length > 0) {
          if (uploaded) fs.unlink(uploaded.path, () => {});
          return res.status(409).json({ ok: false, duplicate: true, errors: ['An identical file already exists in your vault.'], existing: dupes });
        }
      }

      if (errors.length > 0) {
        if (uploaded) fs.unlink(uploaded.path, () => {});
        return res.status(400).json({ ok: false, errors });
      }

      // ── Confirm the uploaded bytes are really a .vaultenc package ──
      // (defence in depth — the browser should only ever send these,
      // but the server never trusts that on its own.)
      const headBuf = Buffer.alloc(4);
      const fd = fs.openSync(uploaded.path, 'r');
      fs.readSync(fd, headBuf, 0, 4, 0);
      fs.closeSync(fd);

      if (!headBuf.equals(VAULTENC_MAGIC)) {
        fs.unlink(uploaded.path, () => {});
        return res.status(400).json({
          ok: false,
          errors: ['File does not look like a valid VaultShare (.vaultenc) package.'],
        });
      }

      // Store the path RELATIVE to the project root in the database —
      // never an absolute path a client could influence.
      const relativePath = path.relative(__dirname, uploaded.path);

      const fileRow = insertFile({
        ownerId: userId,
        originalFilename: sanitizeFilename(originalFilename),
        encryptedFilename: uploaded.filename,
        filePath: relativePath,
        fileSize: uploaded.size,
        algorithm,
        fileHash: fileHash.toLowerCase(),
      });

      logActivity(userId, 'ENCRYPT', { fileId: fileRow.id, ip: req.ip, userAgent: req.get('user-agent') });
      logActivity(userId, 'UPLOAD',  { fileId: fileRow.id, ip: req.ip, userAgent: req.get('user-agent') });

      return res.status(201).json({
        ok: true,
        file: {
          id: fileRow.id,
          original_filename: fileRow.original_filename,
          algorithm: fileRow.algorithm,
          file_hash: fileRow.file_hash,
          file_size: fileRow.file_size,
          created_at: fileRow.created_at,
          version: fileRow.version,
        },
      });
    } catch (e) {
      console.error('[vault] upload error:', e.message);
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(500).json({ ok: false, errors: ['Could not save file to vault.'] });
    }
  });
});

// ── GET /api/vault/files ──────────────────────────────────────────────
router.get('/api/vault/files', requireAuthApi, (req, res) => {
  try {
    const files = listFilesForOwner(req.session.userId);
    return res.json({ ok: true, files });
  } catch (e) {
    console.error('[vault] list error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load your files.'] });
  }
});

// ── GET /api/vault/download/:id ───────────────────────────────────────
router.get('/api/vault/download/:id', requireAuthApi, (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (!Number.isInteger(fileId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });
    }

    // Ownership is checked INSIDE the query itself — a user can never
    // download another user's file by guessing an id.
    const file = getFileForOwner(fileId, req.session.userId);
    if (!file) {
      return res.status(404).json({ ok: false, errors: ['File not found.'] });
    }

    const absolutePath = path.join(__dirname, file.file_path);

    // Defence in depth: the resolved path must still be inside VAULT_ROOT.
    if (!absolutePath.startsWith(VAULT_ROOT)) {
      return res.status(400).json({ ok: false, errors: ['Invalid file path.'] });
    }

    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({ ok: false, errors: ['File is missing from storage.'] });
    }

    logActivity(req.session.userId, 'DOWNLOAD', { fileId: file.id, ip: req.ip, userAgent: req.get('user-agent') });

    const downloadName = sanitizeFilename(file.original_filename).replace(/\.[^/.]+$/, '') + '.vaultenc';
    res.download(absolutePath, downloadName);
  } catch (e) {
    console.error('[vault] download error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not download file.'] });
  }
});

// ── DELETE /api/vault/files/:id ───────────────────────────────────────
// FEATURE: RECYCLE BIN — this no longer destroys the file. It soft-deletes
// it (files.deleted_at is set), so it moves to the Recycle Bin instead of
// being gone forever. Permanent deletion happens from recyclebin.js, either
// by the user or by the retention-period auto-purge job.
router.delete('/api/vault/files/:id', requireAuthApi, (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (!Number.isInteger(fileId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });
    }

    const file = getFileForOwner(fileId, req.session.userId);
    if (!file) {
      return res.status(404).json({ ok: false, errors: ['File not found.'] });
    }

    const ok = softDeleteFile(fileId, req.session.userId);
    if (!ok) {
      return res.status(404).json({ ok: false, errors: ['File not found.'] });
    }

    logActivity(req.session.userId, 'DELETE', { fileId: file.id, ip: req.ip, userAgent: req.get('user-agent') });

    return res.json({ ok: true, movedToRecycleBin: true });
  } catch (e) {
    console.error('[vault] delete error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not delete file.'] });
  }
});

// ══════════════════════════════════════════════════════════════════════
// FEATURE: FILE VERSION HISTORY
//
// Uploading a "new version" of an existing file works exactly like the
// original upload (the browser encrypts client-side and sends the
// resulting .vaultenc bytes) — the only difference is the server snapshots
// the CURRENT version into file_versions before it overwrites the files
// row, so nothing already stored is ever destroyed.
// ══════════════════════════════════════════════════════════════════════

// ── POST /api/vault/files/:id/versions — upload a new version ─────────
router.post('/api/vault/files/:id/versions', requireAuthApi, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File is larger than the 500 MB limit.' : 'Upload failed.';
      return res.status(400).json({ ok: false, errors: [msg] });
    }

    try {
      const userId = req.session.userId;
      const fileId = parseInt(req.params.id, 10);
      const uploaded = req.file;
      const { algorithm, fileHash } = req.body || {};

      const errors = [];
      if (!Number.isInteger(fileId)) errors.push('Invalid file id.');
      if (!uploaded) errors.push('No file was received.');
      if (!ALLOWED_ALGORITHMS.has(algorithm)) errors.push('Unrecognized encryption algorithm.');
      if (!fileHash || !/^[0-9a-f]{64}$/i.test(fileHash)) errors.push('Missing or malformed SHA-256 hash.');

      const existing = Number.isInteger(fileId) ? getFileForOwner(fileId, userId) : null;
      if (!existing) errors.push('Original file not found.');

      if (errors.length > 0) {
        if (uploaded) fs.unlink(uploaded.path, () => {});
        return res.status(400).json({ ok: false, errors });
      }

      const headBuf = Buffer.alloc(4);
      const fd = fs.openSync(uploaded.path, 'r');
      fs.readSync(fd, headBuf, 0, 4, 0);
      fs.closeSync(fd);
      if (!headBuf.equals(VAULTENC_MAGIC)) {
        fs.unlink(uploaded.path, () => {});
        return res.status(400).json({ ok: false, errors: ['File does not look like a valid VaultShare (.vaultenc) package.'] });
      }

      const relativePath = path.relative(__dirname, uploaded.path);

      const updated = addFileVersion(fileId, userId, {
        encryptedFilename: uploaded.filename,
        filePath: relativePath,
        fileSize: uploaded.size,
        algorithm,
        fileHash: fileHash.toLowerCase(),
        originalFilename: existing.original_filename,
      });

      logActivity(userId, 'VERSION_UPLOAD', { fileId, ip: req.ip, userAgent: req.get('user-agent') });

      return res.status(201).json({
        ok: true,
        file: {
          id: updated.id,
          original_filename: updated.original_filename,
          version: updated.version,
          file_size: updated.file_size,
          algorithm: updated.algorithm,
          file_hash: updated.file_hash,
        },
      });
    } catch (e) {
      console.error('[vault] version upload error:', e.message);
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(500).json({ ok: false, errors: ['Could not save new version.'] });
    }
  });
});

// ── GET /api/vault/files/:id/versions — list version history ──────────
router.get('/api/vault/files/:id/versions', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const fileId = parseInt(req.params.id, 10);
    if (!Number.isInteger(fileId)) return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });

    const result = listFileVersions(fileId, userId);
    if (!result) return res.status(404).json({ ok: false, errors: ['File not found.'] });

    return res.json({
      ok: true,
      current: {
        version: result.current.version,
        file_size: result.current.file_size,
        algorithm: result.current.algorithm,
        file_hash: result.current.file_hash,
        created_at: result.current.updated_at,
      },
      olderVersions: result.olderVersions.map((v) => ({
        id: v.id,
        version_number: v.version_number,
        file_size: v.file_size,
        algorithm: v.algorithm,
        file_hash: v.file_hash,
        created_at: v.created_at,
      })),
    });
  } catch (e) {
    console.error('[vault] version list error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load version history.'] });
  }
});

// ── GET /api/vault/files/:id/versions/:versionId/download ─────────────
router.get('/api/vault/files/:id/versions/:versionId/download', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const fileId = parseInt(req.params.id, 10);
    const versionId = parseInt(req.params.versionId, 10);
    if (!Number.isInteger(fileId) || !Number.isInteger(versionId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid id.'] });
    }

    const version = getFileVersionForOwner(fileId, versionId, userId);
    if (!version) return res.status(404).json({ ok: false, errors: ['Version not found.'] });

    const absolutePath = path.join(__dirname, version.file_path);
    if (!absolutePath.startsWith(VAULT_ROOT) || !fs.existsSync(absolutePath)) {
      return res.status(404).json({ ok: false, errors: ['That version is missing from storage.'] });
    }

    logActivity(userId, 'VERSION_DOWNLOAD', { fileId, ip: req.ip, userAgent: req.get('user-agent') });
    const downloadName = sanitizeFilename(version.original_filename).replace(/\.[^/.]+$/, '') + `.v${version.version_number}.vaultenc`;
    res.download(absolutePath, downloadName);
  } catch (e) {
    console.error('[vault] version download error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not download that version.'] });
  }
});

// ── POST /api/vault/files/:id/versions/:versionId/restore ─────────────
// Non-destructive "restore": the CURRENT version is snapshotted (never
// deleted), and a fresh copy of the OLD version's bytes becomes the new
// current version, at the next version number — same approach `git
// revert` uses, rather than overwriting history.
router.post('/api/vault/files/:id/versions/:versionId/restore', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const fileId = parseInt(req.params.id, 10);
    const versionId = parseInt(req.params.versionId, 10);
    if (!Number.isInteger(fileId) || !Number.isInteger(versionId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid id.'] });
    }

    const version = getFileVersionForOwner(fileId, versionId, userId);
    if (!version) return res.status(404).json({ ok: false, errors: ['Version not found.'] });

    const sourcePath = path.join(__dirname, version.file_path);
    if (!sourcePath.startsWith(VAULT_ROOT) || !fs.existsSync(sourcePath)) {
      return res.status(404).json({ ok: false, errors: ['That version is missing from storage.'] });
    }

    // Physically copy the old encrypted bytes to a brand-new random filename —
    // never reuse or move the original version's file, so it stays intact.
    const userDir = path.join(VAULT_ROOT, String(userId));
    const newFilename = `${crypto.randomUUID()}.vaultenc`;
    const newAbsolutePath = path.join(userDir, newFilename);
    fs.copyFileSync(sourcePath, newAbsolutePath);
    const newRelativePath = path.relative(__dirname, newAbsolutePath);

    const updated = restoreFileVersion(fileId, userId, {
      encryptedFilename: newFilename,
      filePath: newRelativePath,
      fileSize: version.file_size,
      algorithm: version.algorithm,
      fileHash: version.file_hash,
      originalFilename: version.original_filename,
    });

    logActivity(userId, 'VERSION_RESTORE', { fileId, ip: req.ip, userAgent: req.get('user-agent') });

    return res.json({ ok: true, file: { id: updated.id, version: updated.version } });
  } catch (e) {
    console.error('[vault] version restore error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not restore that version.'] });
  }
});

// ── DELETE /api/vault/files/:id/versions/:versionId — delete one OLD version ──
router.delete('/api/vault/files/:id/versions/:versionId', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const fileId = parseInt(req.params.id, 10);
    const versionId = parseInt(req.params.versionId, 10);
    if (!Number.isInteger(fileId) || !Number.isInteger(versionId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid id.'] });
    }

    const version = deleteFileVersion(fileId, versionId, userId);
    if (!version) return res.status(404).json({ ok: false, errors: ['Version not found.'] });

    const absolutePath = path.join(__dirname, version.file_path);
    if (absolutePath.startsWith(VAULT_ROOT)) fs.unlink(absolutePath, () => {});

    logActivity(userId, 'VERSION_DELETE', { fileId, ip: req.ip, userAgent: req.get('user-agent') });
    return res.json({ ok: true });
  } catch (e) {
    console.error('[vault] version delete error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not delete that version.'] });
  }
});

export default router;
