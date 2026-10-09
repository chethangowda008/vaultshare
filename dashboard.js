/**
 * VaultShare — dashboard.js
 * =====================================================================
 * Feature 2: User Dashboard.
 *
 * Exposes:
 *   GET /api/dashboard
 *
 * Returns the logged-in user's REAL statistics and recent activity,
 * pulled from the SQLite database (users / files / shares /
 * activity_logs). Nothing here is hard-coded or fake — until Personal
 * Vault (Feature 4) and Secure Sharing (Feature 5) are implemented in
 * later steps, myFiles / sharedFiles / downloads / activeShares will
 * correctly show 0, and Recent Activity will show real login/logout/
 * register events.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { findUserById, getDashboardStats, getRecentActivity } from './db.js';
import { requireAuthApi } from './auth.js';

const router = express.Router();

// Human-readable label + icon for each activity_logs.action value.
const ACTION_LABELS = {
  REGISTER:      { label: 'Account created',        icon: '✓' },
  LOGIN:         { label: 'Successful login',        icon: '✓' },
  LOGOUT:        { label: 'Logged out',               icon: '✓' },
  FAILED_LOGIN:  { label: 'Failed login attempt',      icon: '⚠' },
  UPLOAD:        { label: 'File uploaded',             icon: '✓' },
  ENCRYPT:       { label: 'File encrypted',            icon: '✓' },
  DOWNLOAD:      { label: 'File downloaded',           icon: '✓' },
  DECRYPT:       { label: 'File decrypted',            icon: '✓' },
  SHARE:         { label: 'Secure share created',      icon: '✓' },
  ACCESS_SHARE:  { label: 'Shared file accessed',      icon: '✓' },
  REVOKE_SHARE:  { label: 'Share revoked',              icon: '✓' },
  DELETE:        { label: 'File deleted',               icon: '✓' },
  QR_GENERATED:  { label: 'QR code generated',          icon: '✓' },
};

router.get('/api/dashboard', requireAuthApi, (req, res) => {
  try {
    const user = findUserById(req.session.userId);
    if (!user) {
      return res.status(401).json({ ok: false, errors: ['Not logged in.'] });
    }

    const stats = getDashboardStats(user.id);
    const activityRows = getRecentActivity(user.id, 8);

    const activity = activityRows.map((row) => {
      const meta = ACTION_LABELS[row.action] || { label: row.action, icon: '•' };
      return {
        id: row.id,
        action: row.action,
        label: meta.label,
        icon: meta.icon,
        created_at: row.created_at,
      };
    });

    return res.json({
      ok: true,
      user: { id: user.id, name: user.name, email: user.email },
      stats,
      activity,
    });
  } catch (err) {
    console.error('[dashboard] error:', err.message);
    return res.status(500).json({ ok: false, errors: ['Could not load dashboard.'] });
  }
});

export default router;
