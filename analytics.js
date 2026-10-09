/**
 * VaultShare 2.0 — analytics.js
 * =====================================================================
 * Feature: Advanced Analytics Dashboard.
 *
 *   GET /api/analytics?days=14
 *
 * Every number here comes straight out of a real query against this
 * user's own rows — no hardcoded or randomly-generated statistics.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { requireAuthApi } from './auth.js';
import db from './db.js';

const router = express.Router();

/** Builds an array of the last `days` calendar dates as 'YYYY-MM-DD', oldest first. */
function lastNDates(days) {
  const out = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    out.push(d.toISOString().slice(0, 10));
  }
  return out;
}

/** Turns [{d, n}] rows into a value per date in `dates`, filling gaps with 0. */
function fillSeries(rows, dates) {
  const map = new Map(rows.map((r) => [r.d, r.n]));
  return dates.map((d) => map.get(d) || 0);
}

router.get('/api/analytics', requireAuthApi, (req, res) => {
  try {
    const userId = req.session.userId;
    const days = Math.min(90, Math.max(7, parseInt(req.query.days, 10) || 14));
    const dates = lastNDates(days);

    // ── Totals ──
    const totalFiles = db.prepare(`SELECT COUNT(*) AS n FROM files WHERE owner_id = ? AND deleted_at IS NULL`).get(userId).n;
    const totalStorageBytes = db.prepare(`SELECT COALESCE(SUM(file_size),0) AS n FROM files WHERE owner_id = ? AND deleted_at IS NULL`).get(userId).n;
    const totalRecycleBin = db.prepare(`SELECT COUNT(*) AS n FROM files WHERE owner_id = ? AND deleted_at IS NOT NULL`).get(userId).n;

    const shareCounts = db.prepare(`
      SELECT status, COUNT(*) AS n FROM shares WHERE owner_id = ? GROUP BY status
    `).all(userId).reduce((acc, r) => ({ ...acc, [r.status]: r.n }), { active: 0, expired: 0, revoked: 0, completed: 0 });

    const totalDownloads = db.prepare(`SELECT COUNT(*) AS n FROM activity_logs WHERE user_id = ? AND action = 'DOWNLOAD'`).get(userId).n;

    // ── Time series (uploads / downloads / shares per day) ──
    const uploadRows = db.prepare(`
      SELECT date(created_at) AS d, COUNT(*) AS n FROM files
      WHERE owner_id = ? AND date(created_at) >= date('now', '-' || ? || ' days')
      GROUP BY d
    `).all(userId, days - 1);

    const downloadRows = db.prepare(`
      SELECT date(created_at) AS d, COUNT(*) AS n FROM activity_logs
      WHERE user_id = ? AND action = 'DOWNLOAD' AND date(created_at) >= date('now', '-' || ? || ' days')
      GROUP BY d
    `).all(userId, days - 1);

    const shareRows = db.prepare(`
      SELECT date(created_at) AS d, COUNT(*) AS n FROM shares
      WHERE owner_id = ? AND date(created_at) >= date('now', '-' || ? || ' days')
      GROUP BY d
    `).all(userId, days - 1);

    const loginRows = db.prepare(`
      SELECT date(created_at) AS d, COUNT(*) AS n FROM activity_logs
      WHERE user_id = ? AND action IN ('LOGIN','FAILED_LOGIN') AND date(created_at) >= date('now', '-' || ? || ' days')
      GROUP BY d
    `).all(userId, days - 1);

    // ── File type distribution (computed from filenames — no extra column needed) ──
    const allFiles = db.prepare(`SELECT original_filename, file_size FROM files WHERE owner_id = ? AND deleted_at IS NULL`).all(userId);
    const typeBuckets = {};
    for (const f of allFiles) {
      const match = /\.([a-z0-9]+)$/i.exec(f.original_filename || '');
      const ext = match ? match[1].toLowerCase() : 'other';
      if (!typeBuckets[ext]) typeBuckets[ext] = { count: 0, bytes: 0 };
      typeBuckets[ext].count += 1;
      typeBuckets[ext].bytes += f.file_size;
    }
    const fileTypeDistribution = Object.entries(typeBuckets)
      .map(([extension, v]) => ({ extension, count: v.count, bytes: v.bytes }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return res.json({
      ok: true,
      totals: {
        totalFiles, totalStorageBytes, totalRecycleBin,
        totalShares: shareCounts.active + shareCounts.expired + shareCounts.revoked + shareCounts.completed,
        activeShares: shareCounts.active,
        expiredShares: shareCounts.expired,
        revokedShares: shareCounts.revoked,
        totalDownloads,
      },
      series: {
        dates,
        uploadsPerDay: fillSeries(uploadRows, dates),
        downloadsPerDay: fillSeries(downloadRows, dates),
        sharesPerDay: fillSeries(shareRows, dates),
        loginActivityPerDay: fillSeries(loginRows, dates),
      },
      fileTypeDistribution,
    });
  } catch (e) {
    console.error('[analytics] error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load analytics.'] });
  }
});

export default router;
