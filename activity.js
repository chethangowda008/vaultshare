/**
 * VaultShare — activity.js
 * =====================================================================
 * Feature 9: Activity Log.
 *
 * Exposes:
 *   GET /api/activity?filter=All|Uploads|Downloads|Shares|Security|Login
 *
 * Filtering happens here, in one place, so the meaning of each filter
 * bucket is defined once and reused by both the Activity page and (if
 * needed later) anywhere else that wants the same grouping.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { requireAuthApi } from './auth.js';
import { listActivityForUser } from './db.js';

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
};

// Which raw action values belong to each frontend filter bucket.
const FILTER_GROUPS = {
  All:       null, // no filtering
  Uploads:   ['UPLOAD', 'ENCRYPT'],
  Downloads: ['DOWNLOAD', 'DECRYPT'],
  Shares:    ['SHARE', 'ACCESS_SHARE', 'REVOKE_SHARE', 'QR_GENERATED'],
  Security:  ['FAILED_LOGIN'],
  Login:     ['LOGIN', 'LOGOUT', 'REGISTER'],
};

router.get('/api/activity', requireAuthApi, (req, res) => {
  try {
    const filter = FILTER_GROUPS.hasOwnProperty(req.query.filter) ? req.query.filter : 'All';
    const allowedActions = FILTER_GROUPS[filter];

    // Pull a generous window, then filter in JS — the table is tiny for
    // a student demo project, so this keeps the SQL simple and honest.
    const rows = listActivityForUser(req.session.userId, 500)
      .filter((row) => !allowedActions || allowedActions.includes(row.action))
      .slice(0, 100);

    const activity = rows.map((row) => {
      const meta = ACTION_LABELS[row.action] || { label: row.action, icon: '•' };
      return {
        id: row.id,
        action: row.action,
        label: meta.label,
        icon: meta.icon,
        file_id: row.file_id,
        created_at: row.created_at,
      };
    });

    return res.json({ ok: true, filter, activity });
  } catch (e) {
    console.error('[activity] error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load activity.'] });
  }
});

export default router;
