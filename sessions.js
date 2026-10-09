/**
 * VaultShare 2.0 — sessions.js
 * =====================================================================
 * Feature: Active Session / Device Management.
 *
 *   GET    /api/sessions                — list this user's active sessions
 *   POST   /api/sessions/:sid/logout    — end ONE other session
 *   POST   /api/sessions/logout-others  — end every session except this one
 *
 * A session's sid is only ever compared against sessions already
 * confirmed to belong to req.session.userId — never trusted bare.
 * =====================================================================
 */

'use strict';

import express from 'express';
import { requireAuthApi } from './auth.js';
import { listSessionsForUser, destroySessionForUser, destroyOtherSessionsForUser } from './session-store.js';
import { logActivity } from './db.js';

const router = express.Router();

/** Very small, dependency-free User-Agent summary — good enough for a security page, not a full parser. */
function describeUserAgent(ua) {
  if (!ua) return { browser: 'Unknown browser', os: 'Unknown device' };

  let browser = 'Unknown browser';
  if (/edg\//i.test(ua)) browser = 'Microsoft Edge';
  else if (/chrome\//i.test(ua) && !/chromium/i.test(ua)) browser = 'Chrome';
  else if (/firefox\//i.test(ua)) browser = 'Firefox';
  else if (/safari\//i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
  else if (/opr\//i.test(ua)) browser = 'Opera';

  let os = 'Unknown device';
  if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os x/i.test(ua)) os = 'macOS';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad/i.test(ua)) os = 'iOS';
  else if (/linux/i.test(ua)) os = 'Linux';

  return { browser, os };
}

// ── GET /api/sessions ────────────────────────────────────────────────
router.get('/api/sessions', requireAuthApi, (req, res) => {
  try {
    const sessions = listSessionsForUser(req.session.userId).map((s) => {
      const { browser, os } = describeUserAgent(s.userAgent);
      return {
        sid: s.sid,
        isCurrent: s.sid === req.sessionID,
        browser,
        os,
        ip: s.ip,
        loginTime: s.createdAt ? new Date(s.createdAt).toISOString() : null,
        expiresAt: new Date(s.expire).toISOString(),
      };
    });
    return res.json({ ok: true, sessions });
  } catch (e) {
    console.error('[sessions] list error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not load active sessions.'] });
  }
});

// ── POST /api/sessions/:sid/logout — end ONE other session ────────────
router.post('/api/sessions/:sid/logout', requireAuthApi, (req, res) => {
  try {
    const { sid } = req.params;
    if (sid === req.sessionID) {
      return res.status(400).json({ ok: false, errors: ['Use /api/logout to end your current session.'] });
    }
    const ok = destroySessionForUser(sid, req.session.userId);
    if (!ok) return res.status(404).json({ ok: false, errors: ['Session not found.'] });

    logActivity(req.session.userId, 'SESSION_TERMINATE', { ip: req.ip, userAgent: req.get('user-agent') });
    return res.json({ ok: true });
  } catch (e) {
    console.error('[sessions] terminate error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not end that session.'] });
  }
});

// ── POST /api/sessions/logout-others — end every OTHER session ────────
router.post('/api/sessions/logout-others', requireAuthApi, (req, res) => {
  try {
    const count = destroyOtherSessionsForUser(req.session.userId, req.sessionID);
    logActivity(req.session.userId, 'SESSION_TERMINATE_ALL_OTHERS', { ip: req.ip, userAgent: req.get('user-agent') });
    return res.json({ ok: true, count });
  } catch (e) {
    console.error('[sessions] terminate-others error:', e.message);
    return res.status(500).json({ ok: false, errors: ['Could not end other sessions.'] });
  }
});

export default router;
