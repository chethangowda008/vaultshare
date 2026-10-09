/**
 * VaultShare — account.js
 *   POST /api/account/password   { currentPassword, newPassword }
 * Changing the password signs out every OTHER session and logs the event
 * (never the password itself).
 * NOTE: vault files are encrypted with their own per-file passwords in the
 * browser, so changing the ACCOUNT password does not touch file encryption.
 */
'use strict';
import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import db, { logActivity } from './db.js';
import { requireAuthApi } from './auth.js';
import { destroyOtherSessionsForUser } from './session-store.js';

const router = express.Router();
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, errors: ['Too many attempts. Please wait and try again.'] } });

router.post('/api/account/password', requireAuthApi, limiter, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { currentPassword, newPassword } = req.body || {};
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ ok: false, errors: ['Current and new password are required.'] });
    }
    if (newPassword.length < 8 || newPassword.length > 200 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({ ok: false, errors: ['New password must be at least 8 characters with a letter and a number.'] });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!(await bcrypt.compare(currentPassword, user.password_hash))) {
      logActivity(userId, 'PASSWORD_CHANGE_FAILED', { ip: req.ip, userAgent: req.get('user-agent') });
      return res.status(401).json({ ok: false, errors: ['Current password is incorrect.'] });
    }
    const hash = await bcrypt.hash(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
    const ended = destroyOtherSessionsForUser(userId, req.sessionID);
    logActivity(userId, 'PASSWORD_CHANGE', { ip: req.ip, userAgent: req.get('user-agent') });
    res.json({ ok: true, otherSessionsEnded: ended });
  } catch (e) {
    console.error('[account] password error:', e.message);
    res.status(500).json({ ok: false, errors: ['Could not change password.'] });
  }
});

export default router;
