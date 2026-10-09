/**
 * VaultShare 2.0 — loginmonitor.js
 * =====================================================================
 * RULE-BASED suspicious-login detection. This is NOT artificial
 * intelligence or machine learning — it is a small set of transparent
 * rules that anyone can read and explain in a viva:
 *
 *   R1 new_device      the browser/OS signature was never seen for this account
 *   R2 new_network     the IP network (/24 IPv4) differs from the last login
 *                      (we do NOT claim a physical location)
 *   R3 failed_attempts 3+ failed passwords in the last 15 minutes
 *   R4 rapid_logins    5+ logins in the last 10 minutes
 *   R5 many_sessions   4+ sessions open at once
 *   R6 unusual_time    login hour is 3+ hours away from every earlier login
 *                      (only once 5+ earlier logins exist; uses server UTC)
 *
 * A login is flagged "suspicious" when R3, R4, R5, R6 hold, or when R1 and
 * R2 hold together. Flagged logins are recorded in login_history (visible
 * on the Security Center page) and in the activity log.
 * The first login ever recorded for an account is a baseline (no alert).
 * =====================================================================
 */
'use strict';
import crypto from 'crypto';
import db, { logActivity } from './db.js';
import { listSessionsForUser } from './session-store.js';

function deviceHash(ua) {
  return crypto.createHash('sha256').update(String(ua || 'unknown')).digest('hex').slice(0, 32);
}
function netPrefix(ip) {
  const v4 = /(\d+\.\d+\.\d+)\.\d+$/.exec(String(ip || ''));
  if (v4) return v4[1];
  return String(ip || 'unknown').split(':').slice(0, 3).join(':');
}
function circularHourGap(a, b) {
  const d = Math.abs(a - b) % 24;
  return Math.min(d, 24 - d);
}

/** Store a login without raising any alert (used at registration). */
export function recordBaselineLogin(userId, req) {
  const ua = req.get('user-agent') || '';
  db.prepare('INSERT INTO login_history (user_id, ip, user_agent, device_hash, net_prefix) VALUES (?, ?, ?, ?, ?)')
    .run(userId, req.ip, ua.slice(0, 300), deviceHash(ua), netPrefix(req.ip));
}

/** Analyse + record a successful login. Never throws. */
export async function analyzeLogin(user, req) {
  try {
    const ua = (req.get('user-agent') || '').slice(0, 300);
    const dh = deviceHash(ua);
    const np = netPrefix(req.ip);
    const prior = db.prepare('SELECT * FROM login_history WHERE user_id = ? ORDER BY id DESC').all(user.id);

    const reasons = [];
    let newDevice = false, newNetwork = false;

    if (prior.length > 0) {
      newDevice = !prior.some((p) => p.device_hash === dh);
      newNetwork = prior[0].net_prefix !== np;
      const failed = db.prepare("SELECT COUNT(*) AS n FROM activity_logs WHERE user_id = ? AND action = 'FAILED_LOGIN' AND created_at >= datetime('now','-15 minutes')").get(user.id).n;
      const recent = db.prepare("SELECT COUNT(*) AS n FROM login_history WHERE user_id = ? AND created_at >= datetime('now','-10 minutes')").get(user.id).n;
      const sessions = listSessionsForUser(user.id).length;

      if (newDevice) reasons.push('new_device');
      if (newNetwork) reasons.push('new_network');
      if (failed >= 3) reasons.push('failed_attempts');
      if (recent >= 5) reasons.push('rapid_logins');
      if (sessions >= 4) reasons.push('many_sessions');
      if (prior.length >= 5) {
        const hour = new Date().getUTCHours();
        const hours = prior.map((p) => new Date(p.created_at.replace(' ', 'T') + 'Z').getUTCHours());
        if (hours.every((h) => circularHourGap(h, hour) >= 3)) reasons.push('unusual_time');
      }
    }

    const suspicious = ['failed_attempts', 'rapid_logins', 'many_sessions', 'unusual_time'].some((r) => reasons.includes(r))
      || (newDevice && newNetwork);

    db.prepare('INSERT INTO login_history (user_id, ip, user_agent, device_hash, net_prefix, suspicious, reasons) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(user.id, req.ip, ua, dh, np, suspicious ? 1 : 0, reasons.join(','));

    if (suspicious) {
      logActivity(user.id, 'SUSPICIOUS_LOGIN', { ip: req.ip, userAgent: ua });
    }
  } catch (e) {
    console.error('[loginmonitor] failed:', e.message);
  }
}

export function recentLogins(userId, limit = 10) {
  return db.prepare('SELECT ip, user_agent, suspicious, reasons, created_at FROM login_history WHERE user_id = ? ORDER BY id DESC LIMIT ?').all(userId, limit);
}
export function recentSuspicious(userId, limit = 5) {
  return db.prepare('SELECT ip, reasons, created_at FROM login_history WHERE user_id = ? AND suspicious = 1 ORDER BY id DESC LIMIT ?').all(userId, limit);
}
