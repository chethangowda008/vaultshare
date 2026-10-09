/**
 * VaultShare — settings.js
 *   GET /api/settings   -> { recycleDays, defaultShareExpiry, defaultShareLimit, storageBytes, fileCount, serverDefaults }
 *   PUT /api/settings   -> update any of the above (validated)
 */
'use strict';
import express from 'express';
import db, { logActivity } from './db.js';
import { requireAuthApi } from './auth.js';
import { RECYCLE_BIN_RETENTION_DAYS } from './recyclebin.js';

const router = express.Router();
const EXPIRIES = ['1h', '24h', '7d', '30d', 'never'];
const LIMITS = ['1', '5', '10', 'unlimited'];

function read(userId) {
  const s = db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(userId) || {};
  const usage = db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(file_size),0) AS b FROM files WHERE owner_id = ? AND deleted_at IS NULL').get(userId);
  return {
    recycleDays: s.recycle_days || RECYCLE_BIN_RETENTION_DAYS,
    defaultShareExpiry: s.default_share_expiry || '24h',
    defaultShareLimit: s.default_share_limit || '5',
    storageBytes: usage.b, fileCount: usage.n,
    serverDefaults: { recycleDays: RECYCLE_BIN_RETENTION_DAYS },
  };
}

router.get('/api/settings', requireAuthApi, (req, res) => res.json({ ok: true, settings: read(req.session.userId) }));

router.put('/api/settings', requireAuthApi, (req, res) => {
  const userId = req.session.userId;
  const { recycleDays, defaultShareExpiry, defaultShareLimit } = req.body || {};
  const cur = read(userId);
  const days = recycleDays === undefined ? cur.recycleDays : parseInt(recycleDays, 10);
  const exp = defaultShareExpiry === undefined ? cur.defaultShareExpiry : defaultShareExpiry;
  const lim = defaultShareLimit === undefined ? cur.defaultShareLimit : String(defaultShareLimit);
  if (!Number.isInteger(days) || days < 1 || days > 365 || !EXPIRIES.includes(exp) || !LIMITS.includes(lim)) {
    return res.status(400).json({ ok: false, errors: ['Invalid settings.'] });
  }
  db.prepare(`INSERT INTO user_settings (user_id, recycle_days, default_share_expiry, default_share_limit) VALUES (?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET recycle_days=excluded.recycle_days, default_share_expiry=excluded.default_share_expiry, default_share_limit=excluded.default_share_limit`)
    .run(userId, days, exp, lim);
  logActivity(userId, 'SETTINGS_CHANGE', { ip: req.ip, userAgent: req.get('user-agent') });
  res.json({ ok: true, settings: read(userId) });
});

export default router;
