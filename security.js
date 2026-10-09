/**
 * VaultShare — security.js
 * =====================================================================
 * Feature 10: Security Dashboard.
 *
 * Exposes:
 *   GET /api/security
 *
 * The "capability" flags below (encryption, hashing, etc.) describe
 * what this codebase actually implements — they are not hard-coded
 * marketing checkmarks, they're a direct list of the security
 * measures wired into auth.js / vault.js / shares.js / server.js.
 * The counts underneath them come straight from the database.
 *
 * NOTE: Two-Factor Authentication and Security Incidents were removed
 * from the product, so the security score below no longer has factors
 * for either — the points that used to belong to 2FA (25) and recovery
 * codes (10) were redistributed across the remaining factors so the
 * score still totals 100 and still reflects only controls that
 * genuinely exist in this build.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { requireAuthApi } from './auth.js';
import {
  getShareStatusCounts, getSecurityEventCount, getFailedLoginCount,
  getRecentActivity, findUserById,
} from './db.js';
import { listSessionsForUser } from './session-store.js';
import { recentLogins, recentSuspicious } from './loginmonitor.js';
import db from './db.js';

/**
 * Real, explainable security score out of 100. Every point comes from an
 * actual control that is (or isn't) currently in effect for this account.
 *
 *   Password protection (bcrypt-hashed)      30  always enforced
 *   Session hygiene (fewer open sessions)    25
 *   Failed login attempts on record          25
 *   No suspicious logins in last 30 days     20
 */
function computeSecurityScore({ activeSessionCount, failedLogins, suspiciousRecent }) {
  const breakdown = [];

  breakdown.push({ label: 'Password protection (bcrypt)', points: 30, max: 30, detail: 'Your password is stored only as a bcrypt hash.' });

  let sessionPoints;
  if (activeSessionCount <= 1) sessionPoints = 25;
  else if (activeSessionCount === 2) sessionPoints = 18;
  else if (activeSessionCount === 3) sessionPoints = 10;
  else sessionPoints = 3;
  breakdown.push({ label: 'Session hygiene', points: sessionPoints, max: 25, detail: `${activeSessionCount} active session(s) right now.` });

  let loginPoints;
  if (failedLogins === 0) loginPoints = 25;
  else if (failedLogins <= 2) loginPoints = 18;
  else if (failedLogins <= 5) loginPoints = 8;
  else loginPoints = 0;
  breakdown.push({ label: 'Failed login attempts', points: loginPoints, max: 25, detail: `${failedLogins} failed login attempt(s) on record.` });

  breakdown.push({
    label: 'Suspicious login activity', points: suspiciousRecent === 0 ? 20 : (suspiciousRecent === 1 ? 10 : 0), max: 20,
    detail: `${suspiciousRecent} suspicious login(s) flagged in the last 30 days.`,
  });

  const total = breakdown.reduce((sum, b) => sum + b.points, 0);
  return { total, breakdown };
}

const router = express.Router();

const ACTION_LABELS = {
  REGISTER:      { label: 'Account created',           icon: '✓' },
  LOGIN:         { label: 'Successful login',           icon: '✓' },
  LOGOUT:        { label: 'Logged out',                  icon: '✓' },
  FAILED_LOGIN:  { label: 'Failed login attempt',         icon: '⚠' },
  UPLOAD:        { label: 'File uploaded to vault',       icon: '✓' },
  ENCRYPT:       { label: 'File encrypted',               icon: '✓' },
  DOWNLOAD:      { label: 'File downloaded',              icon: '✓' },
  DECRYPT:       { label: 'File decrypted',               icon: '✓' },
  DELETE:        { label: 'File deleted from vault',      icon: '✓' },
  SHARE:         { label: 'Secure share created',         icon: '✓' },
  ACCESS_SHARE:  { label: 'Shared file accessed by recipient', icon: '✓' },
  REVOKE_SHARE:  { label: 'Share revoked',                 icon: '✓' },
  QR_GENERATED:  { label: 'QR code generated for a share', icon: '✓' },
  FILE_RESTORE:  { label: 'File restored from Recycle Bin', icon: '✓' },
  FILE_PURGE:    { label: 'File permanently deleted', icon: '⚠' },
  FILE_AUTO_PURGE: { label: 'File auto-purged from Recycle Bin', icon: '⚠' },
  FILE_AUTO_EXPIRED: { label: 'File auto-expired to Recycle Bin', icon: '⚠' },
  FILE_EXPIRATION_SET: { label: 'File expiration date set', icon: '✓' },
  RECYCLE_BIN_EMPTY: { label: 'Recycle Bin emptied', icon: '⚠' },
  VERSION_UPLOAD:  { label: 'New file version uploaded', icon: '✓' },
  VERSION_DOWNLOAD:{ label: 'Older version downloaded', icon: '✓' },
  VERSION_RESTORE: { label: 'Older version restored', icon: '✓' },
  VERSION_DELETE:  { label: 'Older version deleted', icon: '✓' },
  PASSWORD_CHANGE: { label: 'Password changed', icon: '⚠' },
  PASSWORD_CHANGE_FAILED: { label: 'Failed password change attempt', icon: '⚠' },
  SUSPICIOUS_LOGIN: { label: 'Suspicious login detected', icon: '⚠' },
  INTEGRITY_CHECK: { label: 'Quick integrity check run', icon: '✓' },
  INTEGRITY_VERIFY: { label: 'Full integrity verification run', icon: '✓' },
  SETTINGS_CHANGE: { label: 'Settings changed', icon: '✓' },
  SESSION_TERMINATE: { label: 'A session was ended', icon: '✓' },
  SESSION_TERMINATE_ALL_OTHERS: { label: 'All other sessions ended', icon: '✓' },
  SHARE_AUTH_FAILED: { label: 'Incorrect password entered on a shared link', icon: '⚠' },
};

router.get('/api/security', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const user = findUserById(userId);

    const shareCounts = getShareStatusCounts(userId);
    const securityEvents = getSecurityEventCount(userId);
    const failedLogins = getFailedLoginCount(userId);
    const activeSessionCount = listSessionsForUser(userId).length;

    const recent = getRecentActivity(userId, 10).map((row) => {
      const meta = ACTION_LABELS[row.action] || { label: row.action, icon: '•' };
      return { label: meta.label, icon: meta.icon, created_at: row.created_at };
    });

    const suspiciousRecent = db.prepare(
      "SELECT COUNT(*) AS n FROM login_history WHERE user_id = ? AND suspicious = 1 AND created_at >= datetime('now','-30 days')"
    ).get(userId).n;
    const score = computeSecurityScore({ activeSessionCount, failedLogins, suspiciousRecent });

    return res.json({
      ok: true,
      capabilities: [
        { name: 'Encryption',        detail: 'AES-256-GCM / CBC / CTR', enabled: true },
        { name: 'Password Hashing',  detail: 'bcrypt (12 rounds)',      enabled: true },
        { name: 'File Integrity',    detail: 'SHA-256',                 enabled: true },
        { name: 'Secure Sharing',    detail: 'Random tokens (crypto.randomBytes)', enabled: true },
        { name: 'Expiring Links',    detail: 'Server-enforced expiry',  enabled: true },
        { name: 'Download Limits',   detail: 'Server-enforced, not trusted from client', enabled: true },
        { name: 'Access Control',    detail: 'Ownership checked on every request', enabled: true },
        { name: 'Login Rate Limiting', detail: '10 attempts / 15 min per IP', enabled: true },
        { name: 'Password-Protected Shares', detail: 'bcrypt-hashed share passwords', enabled: true },
      ],
      account: { name: user ? user.name : '—', memberSince: user ? user.created_at : null },
      shares: shareCounts,
      securityEvents,
      failedLogins,
      activeSessionCount,
      recentLogins: recentLogins(userId, 8),
      suspiciousLogins: recentSuspicious(userId, 5),
      securityScore: score.total,
      securityScoreBreakdown: score.breakdown,
      recentEvents: recent,
    });
  } catch (e) {
    console.error('[security] error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load security overview.'] });
  }
});

export default router;
