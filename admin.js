/**
 * VaultShare — admin.js
 * =====================================================================
 * Feature 18: Admin / Security View.
 *
 * Exposes:
 *   GET /api/admin/stats   (protected by requireAdminApi — re-checks
 *                            is_admin against the database on every
 *                            request; a client-sent flag is never
 *                            trusted)
 *
 * A read-only, platform-wide stats view for an admin account. Every
 * number here comes straight from a real database query — nothing is
 * hard-coded. There is no encryption password to expose in the first
 * place (VaultShare never stores one), and password_hash is never
 * selected or sent to the browser.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { requireAdminSessionApi as requireAdminApi } from './admin-auth.js';
import db, { getPlatformStats, getRecentActivityAllUsers } from './db.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const router = express.Router();

const ACTION_LABELS = {
  REGISTER:      { label: 'Account created',                  icon: '✓' },
  LOGIN:         { label: 'Successful login',                 icon: '✓' },
  LOGOUT:        { label: 'Logged out',                        icon: '✓' },
  FAILED_LOGIN:  { label: 'Failed login attempt',              icon: '⚠' },
  UPLOAD:        { label: 'File uploaded to vault',            icon: '✓' },
  ENCRYPT:       { label: 'File encrypted',                    icon: '✓' },
  DOWNLOAD:      { label: 'File downloaded',                   icon: '✓' },
  DECRYPT:       { label: 'File decrypted',                    icon: '✓' },
  DELETE:        { label: 'File deleted from vault',           icon: '✓' },
  SHARE:         { label: 'Secure share created',              icon: '✓' },
  ACCESS_SHARE:  { label: 'Shared file accessed by recipient',  icon: '✓' },
  REVOKE_SHARE:  { label: 'Share revoked',                      icon: '✓' },
  QR_GENERATED:  { label: 'QR code generated for a share',      icon: '✓' },
  FILE_RESTORE:  { label: 'File restored from Recycle Bin', icon: '✓' },
  FILE_PURGE:    { label: 'File permanently deleted', icon: '⚠' },
  VERSION_UPLOAD: { label: 'New file version uploaded', icon: '✓' },
  SUSPICIOUS_LOGIN: { label: 'Suspicious login flagged', icon: '⚠' },
  PASSWORD_CHANGE: { label: 'Password changed', icon: '✓' },
  SESSION_TERMINATE: { label: 'Session ended', icon: '✓' },
};

router.get('/api/admin/stats', requireAdminApi, (req, res) => {
  try {
    const stats = getPlatformStats();

    const recentEvents = getRecentActivityAllUsers(15).map((row) => {
      const meta = ACTION_LABELS[row.action] || { label: row.action, icon: '•' };
      return {
        label: meta.label,
        icon: meta.icon,
        created_at: row.created_at,
        user: row.user_name || row.user_email || 'Unknown user',
      };
    });

    // Extra platform metrics. These are AGGREGATE COUNTS ONLY: an admin can see
    // how much is stored, never what is inside (files are encrypted in the
    // browser and the admin has no keys — zero-knowledge is preserved).
    const one = (sql, ...p) => db.prepare(sql).get(...p).n;
    const dbFile = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data', 'vaultshare.db');
    let dbBytes = 0; try { dbBytes = fs.statSync(dbFile).size; } catch { /* ignore */ }
    const extra = {
      activeUsers24h: one("SELECT COUNT(DISTINCT user_id) AS n FROM activity_logs WHERE action = 'LOGIN' AND created_at >= datetime('now','-1 day')"),
      storageBytes: db.prepare('SELECT COALESCE(SUM(file_size),0) AS n FROM files WHERE deleted_at IS NULL').get().n,
      filesInRecycleBin: one('SELECT COUNT(*) AS n FROM files WHERE deleted_at IS NOT NULL'),
      failedLogins24h: one("SELECT COUNT(*) AS n FROM activity_logs WHERE action = 'FAILED_LOGIN' AND created_at >= datetime('now','-1 day')"),
      failedLoginsTotal: one("SELECT COUNT(*) AS n FROM activity_logs WHERE action = 'FAILED_LOGIN'"),
      suspiciousLogins30d: one("SELECT COUNT(*) AS n FROM login_history WHERE suspicious = 1 AND created_at >= datetime('now','-30 days')"),
      securityEvents: one("SELECT COUNT(*) AS n FROM activity_logs WHERE action IN ('FAILED_LOGIN','REVOKE_SHARE','SUSPICIOUS_LOGIN','SHARE_AUTH_FAILED','PASSWORD_CHANGE')"),
      health: {
        status: 'ok',
        uptimeSeconds: Math.round(process.uptime()),
        nodeVersion: process.version,
        databaseBytes: dbBytes,
        environment: process.env.NODE_ENV || 'development',
      },
    };

    return res.json({
      ok: true,
      ...extra,
      totalUsers: stats.totalUsers,
      totalFiles: stats.totalFiles,
      totalShares: stats.totalShares,
      totalDownloads: stats.totalDownloads,
      shares: stats.shares,
      recentEvents,
    });
  } catch (e) {
    console.error('[admin] error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load admin stats.'] });
  }
});

export default router;

// ══════════════════════════════════════════════════════════════════════
// VaultShare 3.0 additions: user management, storage quotas, and the
// system-wide security audit dashboard. All admin-only (requireAdminApi
// re-checks is_admin against the DB on every call).
// ══════════════════════════════════════════════════════════════════════
import {
  listUsersForAdmin, setUserStatus, setUserQuota, getDefaultQuotaBytes, setAppSetting,
  eventsByDay, eventsByType, loginSuccessVsFailByDay, logActivity,
} from './db.js';
import { destroyOtherSessionsForUser } from './session-store.js';

// ── GET /api/admin/users — full user list with stats (Feature 9) ──────
router.get('/api/admin/users', requireAdminApi, (req, res) => {
  res.json({ ok: true, users: listUsersForAdmin(), defaultQuotaBytes: getDefaultQuotaBytes() });
});

// ── PUT /api/admin/users/:id/status — suspend / unsuspend ─────────────
router.put('/api/admin/users/:id/status', requireAdminApi, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { status } = req.body || {};
  if (!Number.isInteger(id) || !['active', 'suspended'].includes(status)) {
    return res.status(400).json({ ok: false, errors: ['Invalid request.'] });
  }
  if (id === req.session.userId && status === 'suspended') {
    return res.status(400).json({ ok: false, errors: ["You can't suspend your own account."] });
  }
  if (!setUserStatus(id, status)) return res.status(404).json({ ok: false, errors: ['User not found.'] });
  if (status === 'suspended') destroyOtherSessionsForUser(id, null); // kick them out immediately
  logActivity(req.session.userId, 'ADMIN_USER_STATUS_CHANGE', { ip: req.ip, userAgent: req.get('user-agent') });
  res.json({ ok: true });
});

// ── POST /api/admin/users/:id/reset-sessions — force logout everywhere ──
router.post('/api/admin/users/:id/reset-sessions', requireAdminApi, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ ok: false, errors: ['Invalid user id.'] });
  const count = destroyOtherSessionsForUser(id, null);
  logActivity(req.session.userId, 'ADMIN_RESET_SESSIONS', { ip: req.ip, userAgent: req.get('user-agent') });
  res.json({ ok: true, count });
});

// ── PUT /api/admin/users/:id/quota — set an individual quota (bytes) ──
router.put('/api/admin/users/:id/quota', requireAdminApi, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const bytes = req.body?.quotaBytes === null ? null : parseInt(req.body?.quotaBytes, 10);
  if (!Number.isInteger(id) || (bytes !== null && (!Number.isInteger(bytes) || bytes < 0))) {
    return res.status(400).json({ ok: false, errors: ['Invalid request.'] });
  }
  setUserQuota(id, bytes);
  logActivity(req.session.userId, 'ADMIN_QUOTA_CHANGE', { ip: req.ip, userAgent: req.get('user-agent') });
  res.json({ ok: true });
});

// ── PUT /api/admin/settings/default-quota — server-wide default quota ──
router.put('/api/admin/settings/default-quota', requireAdminApi, (req, res) => {
  const bytes = parseInt(req.body?.quotaBytes, 10);
  if (!Number.isInteger(bytes) || bytes < 1024) return res.status(400).json({ ok: false, errors: ['Invalid quota.'] });
  setAppSetting('default_quota_bytes', bytes);
  logActivity(req.session.userId, 'ADMIN_QUOTA_CHANGE', { ip: req.ip, userAgent: req.get('user-agent') });
  res.json({ ok: true });
});

// ── GET /api/admin/audit — system-wide security audit dashboard (Feature 10) ──
router.get('/api/admin/audit', requireAdminApi, (req, res) => {
  const days = Math.min(90, Math.max(7, parseInt(req.query.days, 10) || 14));
  const SECURITY_ACTIONS = [
    'FAILED_LOGIN', 'LOGIN', 'SUSPICIOUS_LOGIN',
    'PASSWORD_CHANGE', 'SHARE_AUTH_FAILED', 'REVOKE_SHARE', 'INTEGRITY_VERIFY', 'ADMIN_USER_STATUS_CHANGE',
  ];
  res.json({
    ok: true,
    eventsByDay: eventsByDay(SECURITY_ACTIONS, days),
    eventsByType: eventsByType(15),
    loginSuccessVsFail: loginSuccessVsFailByDay(days),
  });
});

