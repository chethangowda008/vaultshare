/**
 * VaultShare — shares.js
 * =====================================================================
 * Feature 5: Secure File Sharing.
 *
 * Authenticated routes (owner only):
 *   POST   /api/shares                — create a secure share for a file
 *   GET    /api/shares/mine           — "My Shares"
 *   GET    /api/shares/received       — "Shared With Me"
 *   POST   /api/shares/:id/revoke     — revoke a share
 *
 * Public routes (no login required — this is how a recipient, who may
 * not even have a VaultShare account, opens a shared link):
 *   GET    /api/public/shares/:token           — share metadata
 *   GET    /api/public/shares/:token/download  — the actual file
 *
 * SECURITY NOTES:
 * - share_token is generated with crypto.randomBytes — never a
 *   predictable/sequential id.
 * - Expiration and download-limit are enforced HERE, on the server,
 *   every time — never trusted from the frontend.
 * - The encryption password is still never involved anywhere in this
 *   file. A recipient who downloads a shared file still needs the
 *   password (shared with them separately, same as the existing
 *   zero-knowledge design) to decrypt it on the Decrypt tab.
 * =====================================================================
 */

'use strict';

import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';

import { requireAuthApi } from './auth.js';
import {
  getFileForOwner, findUserByEmail, addShareItems, getShareItems, hasShareItems,
  createShare, getShareByToken, getShareForOwner,
  listSharesForOwner, listSharesForRecipient, setShareStatus,
  incrementShareDownload, timestampSecondsFromNow, logActivity,
} from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const VAULT_ROOT = path.join(__dirname, 'vault-storage');

const router = express.Router();

// ── ALLOWED OPTIONS (never trust raw values from the frontend) ──────────
const EXPIRY_SECONDS = { '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000, never: null };
const DOWNLOAD_LIMITS = { '1': 1, '5': 5, '10': 10, unlimited: null };

function sanitizeFilename(name) {
  return String(name || 'file').replace(/[\\/]/g, '_').replace(/[\x00-\x1f]/g, '').trim().slice(0, 255) || 'file';
}

function shareUrl(req, token) {
  return `${req.protocol}://${req.get('host')}/share/${token}`;
}

// FEATURE: PASSWORD-PROTECTED SHARE LINKS — prevents brute-forcing a
// share's password by throttling attempts per IP, same pattern as login.
const sharePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, errors: ['Too many attempts. Please try again in a few minutes.'] },
});

// ── POST /api/shares — create a secure share ─────────────────────────────
router.post('/api/shares', requireAuthApi, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { fileId, fileIds, recipientEmail, downloadLimit, sharePassword, customHours } = req.body || {};
    let expiresIn = (req.body || {}).expiresIn;
    let customSeconds = null;
    if (expiresIn === 'custom') {
      const h = Number(customHours);
      if (!Number.isFinite(h) || h < 1 || h > 8760) {
        return res.status(400).json({ ok: false, errors: ['Custom expiry must be between 1 and 8760 hours.'] });
      }
      customSeconds = Math.round(h * 3600);
      expiresIn = '1h'; // validated below; real value comes from customSeconds
    }

    // Single file (fileId) or several files (fileIds, max 20) — one share either way.
    let ids;
    if (Array.isArray(fileIds)) {
      ids = [...new Set(fileIds.map((x) => parseInt(x, 10)))];
      if (ids.length < 1 || ids.length > 20 || ids.some((x) => !Number.isInteger(x))) {
        return res.status(400).json({ ok: false, errors: ['Choose between 1 and 20 files.'] });
      }
    } else {
      ids = [parseInt(fileId, 10)];
      if (!Number.isInteger(ids[0])) {
        return res.status(400).json({ ok: false, errors: ['Invalid file id.'] });
      }
    }
    const parsedFileId = ids[0];

    // Ownership check for EVERY file — you can only share YOUR OWN files.
    for (const id of ids) {
      if (!getFileForOwner(id, userId)) {
        return res.status(404).json({ ok: false, errors: ['File not found.'] });
      }
    }
    const file = getFileForOwner(parsedFileId, userId);

    if (!Object.prototype.hasOwnProperty.call(EXPIRY_SECONDS, expiresIn)) {
      return res.status(400).json({ ok: false, errors: ['Invalid expiration option.'] });
    }
    if (!Object.prototype.hasOwnProperty.call(DOWNLOAD_LIMITS, downloadLimit)) {
      return res.status(400).json({ ok: false, errors: ['Invalid download limit option.'] });
    }

    let recipientId = null;
    let recipientHasAccount = false;
    const trimmedEmail = (recipientEmail || '').trim();
    if (trimmedEmail) {
      const recipientUser = findUserByEmail(trimmedEmail);
      if (recipientUser) {
        if (recipientUser.id === userId) {
          return res.status(400).json({ ok: false, errors: ['You cannot share a file with yourself.'] });
        }
        recipientId = recipientUser.id;
        recipientHasAccount = true;
      }
    }

    const token = crypto.randomBytes(24).toString('base64url'); // cryptographically random, unguessable
    const expiresAt = timestampSecondsFromNow(customSeconds !== null ? customSeconds : EXPIRY_SECONDS[expiresIn]);
    const limit = DOWNLOAD_LIMITS[downloadLimit];

    // ── FEATURE: PASSWORD-PROTECTED SHARE LINKS ──
    // The password (if any) is hashed with bcrypt exactly like account
    // passwords — never stored in plaintext, and it is a SEPARATE secret
    // from the client-side encryption password: this just gates who can
    // reach the download, it never touches the file's actual encryption.
    let passwordHash = null;
    const trimmedPassword = typeof sharePassword === 'string' ? sharePassword.trim() : '';
    if (trimmedPassword) {
      if (trimmedPassword.length < 4) {
        return res.status(400).json({ ok: false, errors: ['Share password must be at least 4 characters.'] });
      }
      passwordHash = await bcrypt.hash(trimmedPassword, 10);
    }

    const share = createShare({
      fileId: parsedFileId,
      ownerId: userId,
      recipientId,
      shareToken: token,
      expiresAt,
      downloadLimit: limit,
      passwordHash,
    });

    if (ids.length > 1) addShareItems(share.id, ids);

    logActivity(userId, 'SHARE', { fileId: parsedFileId, ip: req.ip, userAgent: req.get('user-agent') });

    return res.status(201).json({
      ok: true,
      share: {
        id: share.id,
        token: share.share_token,
        url: shareUrl(req, share.share_token),
        expiresAt: share.expires_at,
        downloadLimit: share.download_limit,
        recipientEmail: trimmedEmail || null,
        recipientHasAccount,
      },
    });
  } catch (e) {
    console.error('[shares] create error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not create share.'] });
  }
});

// ── GET /api/shares/mine — "My Shares" ────────────────────────────────────
router.get('/api/shares/mine', requireAuthApi, (req, res) => {
  try {
    const shares = listSharesForOwner(req.session.userId).map((s) => ({
      ...s,
      url: shareUrl(req, s.share_token),
    }));
    return res.json({ ok: true, shares });
  } catch (e) {
    console.error('[shares] mine error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load your shares.'] });
  }
});

// ── GET /api/shares/received — "Shared With Me" ──────────────────────────
router.get('/api/shares/received', requireAuthApi, (req, res) => {
  try {
    const shares = listSharesForRecipient(req.session.userId).map((s) => ({
      ...s,
      url: shareUrl(req, s.share_token),
    }));
    return res.json({ ok: true, shares });
  } catch (e) {
    console.error('[shares] received error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load shares sent to you.'] });
  }
});

// ── GET /api/shares/:id/qr.png — Feature 11: QR Code Secure Sharing ──────
// The QR image encodes ONLY the share URL — never the password, never
// anything else. It stops working the moment the share itself does,
// because it just points at the same /share/:token page.
router.get('/api/shares/:id/qr.png', requireAuthApi, async (req, res) => {
  try {
    const shareId = parseInt(req.params.id, 10);
    if (!Number.isInteger(shareId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid share id.'] });
    }

    const share = getShareForOwner(shareId, req.session.userId);
    if (!share) {
      return res.status(404).json({ ok: false, errors: ['Share not found.'] });
    }

    const url = shareUrl(req, share.share_token);
    const pngBuffer = await QRCode.toBuffer(url, { type: 'png', width: 300, margin: 1 });

    logActivity(req.session.userId, 'QR_GENERATED', { fileId: share.file_id, ip: req.ip, userAgent: req.get('user-agent') });

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'no-store');
    return res.send(pngBuffer);
  } catch (e) {
    console.error('[shares] qr error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not generate QR code.'] });
  }
});

// ── POST /api/shares/:id/revoke ───────────────────────────────────────────
router.post('/api/shares/:id/revoke', requireAuthApi, (req, res) => {
  try {
    const shareId = parseInt(req.params.id, 10);
    if (!Number.isInteger(shareId)) {
      return res.status(400).json({ ok: false, errors: ['Invalid share id.'] });
    }

    const share = getShareForOwner(shareId, req.session.userId);
    if (!share) {
      return res.status(404).json({ ok: false, errors: ['Share not found.'] });
    }

    setShareStatus(shareId, req.session.userId, 'revoked');
    logActivity(req.session.userId, 'REVOKE_SHARE', { fileId: share.file_id, ip: req.ip, userAgent: req.get('user-agent') });

    return res.json({ ok: true });
  } catch (e) {
    console.error('[shares] revoke error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not revoke share.'] });
  }
});

// ── GET /api/public/shares/:token — metadata for the public share page ───
// No login required. Never returns anything about the owner beyond what
// the share page needs to display.
router.get('/api/public/shares/:token', (req, res) => {
  try {
    const share = getShareByToken(req.params.token);
    if (!share) {
      return res.status(404).json({ ok: false, errors: ['This share link does not exist.'] });
    }

    return res.json({
      ok: true,
      share: {
        filename: sanitizeFilename(share.original_filename),
        fileSize: share.file_size,
        algorithm: share.algorithm,
        status: share.status,
        expiresAt: share.expires_at,
        downloadLimit: share.download_limit,
        downloadCount: share.download_count,
        passwordProtected: !!share.password_hash,
        files: hasShareItems(share.id)
          ? getShareItems(share.id).map((i) => ({ itemId: i.item_id, filename: sanitizeFilename(i.original_filename), fileSize: i.file_size, algorithm: i.algorithm }))
          : null,
      },
    });
  } catch (e) {
    console.error('[shares] public metadata error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load this share.'] });
  }
});

// ── POST /api/public/shares/:token/download — the actual file ────────────
// POST (not GET) so a share password never ends up in a URL, browser
// history, or server access log.
router.post('/api/public/shares/:token/download', sharePasswordLimiter, async (req, res) => {
  try {
    const share = getShareByToken(req.params.token);
    if (!share) {
      return res.status(404).json({ ok: false, errors: ['This share link does not exist.'] });
    }

    if (share.status !== 'active') {
      const messages = {
        expired:   'This share link has expired.',
        revoked:   'This share link has been revoked by the owner.',
        completed: 'Download limit reached for this share link.',
      };
      return res.status(410).json({ ok: false, errors: [messages[share.status] || 'This share link is no longer active.'] });
    }

    if (share.password_hash) {
      const provided = typeof req.body?.password === 'string' ? req.body.password : '';
      const match = provided ? await bcrypt.compare(provided, share.password_hash) : false;
      if (!match) {
        logActivity(share.owner_id, 'SHARE_AUTH_FAILED', { fileId: share.file_id, ip: req.ip, userAgent: req.get('user-agent') });
        return res.status(401).json({ ok: false, errors: ['Incorrect password.'], requiresPassword: true });
      }
    }

    // Multi-file share: the caller must say which item; single-file shares are unchanged.
    let target = { file_path: share.file_path, original_filename: share.original_filename };
    if (hasShareItems(share.id)) {
      const itemId = parseInt(req.body?.itemId, 10);
      const item = Number.isInteger(itemId) ? getShareItems(share.id).find((i) => i.item_id === itemId) : null;
      if (!item) return res.status(400).json({ ok: false, errors: ['Choose which file to download.'] });
      target = item;
    }

    const absolutePath = path.join(__dirname, target.file_path);
    if (!absolutePath.startsWith(VAULT_ROOT) || !fs.existsSync(absolutePath)) {
      return res.status(404).json({ ok: false, errors: ['File is missing from storage.'] });
    }

    incrementShareDownload(share.id);
    logActivity(null, 'ACCESS_SHARE', { fileId: share.file_id, ip: req.ip, userAgent: req.get('user-agent') });
    logActivity(share.owner_id, 'DOWNLOAD', { fileId: share.file_id, ip: req.ip, userAgent: req.get('user-agent') });

    const downloadName = sanitizeFilename(target.original_filename).replace(/\.[^/.]+$/, '') + '.vaultenc';
    res.download(absolutePath, downloadName);
  } catch (e) {
    console.error('[shares] public download error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not download this file.'] });
  }
});

export default router;
