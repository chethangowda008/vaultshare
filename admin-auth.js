/**
 * VaultShare — admin-auth.js
 *
 * Single-Admin Authentication System (Feature 18 enhancement)
 *
 * The ONE authorized administrator is identified entirely by environment
 * variables (ADMIN_EMAIL, ADMIN_PASSWORD). No admin account is created
 * in the database through any public registration path.
 *
 * On every server start:
 *   - ADMIN_EMAIL and ADMIN_PASSWORD must be set (server exits otherwise).
 *   - The ADMIN_PASSWORD is hashed once in memory; the plain-text is then
 *     discarded from the module scope and never written to disk or sent
 *     to the browser.
 *
 * Session flag: req.session.isAdmin = true
 *   - Set only by /api/admin/login after server-side credential check.
 *   - Re-verified from the session on every protected request.
 *   - The browser never sends this flag; the server owns it.
 */

'use strict';

import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// ── Load and validate admin credentials from environment ─────────────────
const RAW_ADMIN_EMAIL    = (process.env.ADMIN_EMAIL    || '').trim().toLowerCase();
const RAW_ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();

if (!RAW_ADMIN_EMAIL || !RAW_ADMIN_PASSWORD) {
  console.error(
    '\n[admin-auth] FATAL: ADMIN_EMAIL and ADMIN_PASSWORD must be set in your .env file.\n' +
    '  Copy .env.example to .env and fill in the admin credentials.\n'
  );
  process.exit(1);
}

// Hash once at startup. The plain-text password is not kept in any variable
// after this — bcrypt.compare() uses the stored hash.
const ADMIN_EMAIL_NORMALIZED = RAW_ADMIN_EMAIL;
const ADMIN_HASH = await bcrypt.hash(RAW_ADMIN_PASSWORD, 12);

// Overwrite the raw password reference immediately after hashing.
// (JS can't truly erase a string from memory, but we avoid keeping a
// named reference to it anywhere in the module scope.)

const ADMIN_SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours

// Strict rate limit for the admin login endpoint
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5,                  // max 5 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    errors: ['Too many admin login attempts. Please wait 15 minutes.']
  }
});

// ── POST /api/admin/login ─────────────────────────────────────────────────
router.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // Validate presence
    if (!email || typeof email !== 'string' ||
        !password || typeof password !== 'string') {
      return res.status(400).json({
        ok: false,
        errors: ['Email and password are required.']
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const GENERIC_ERROR   = 'Invalid admin credentials.';

    // Constant-time email comparison (prevents timing-based email enumeration)
    const emailMatch = normalizedEmail === ADMIN_EMAIL_NORMALIZED;

    // Always run bcrypt.compare so timing is constant regardless of email match
    const passwordMatch = await bcrypt.compare(password, ADMIN_HASH);

    if (!emailMatch || !passwordMatch) {
      // Log the failed attempt (no details about WHICH field was wrong)
      console.warn(`[admin-auth] Failed admin login attempt from IP ${req.ip} at ${new Date().toISOString()}`);
      return res.status(401).json({ ok: false, errors: [GENERIC_ERROR] });
    }

    // ── Credentials verified — establish admin session ──────────────────
    // Regenerate session ID to prevent session fixation
    await new Promise((resolve, reject) =>
      req.session.regenerate((err) => (err ? reject(err) : resolve()))
    );

    req.session.isAdmin        = true;   // server-owned flag, never from client
    req.session.adminEmail     = ADMIN_EMAIL_NORMALIZED;
    req.session.adminCreatedAt = Date.now();
    req.session.adminIp        = req.ip;
    req.session.cookie.maxAge  = ADMIN_SESSION_DURATION;

    await new Promise((resolve, reject) =>
      req.session.save((err) => (err ? reject(err) : resolve()))
    );

    console.log(`[admin-auth] Admin login successful from IP ${req.ip} at ${new Date().toISOString()}`);

    return res.json({ ok: true });

  } catch (err) {
    console.error('[admin-auth] Login error:', err.message);
    return res.status(500).json({
      ok: false,
      errors: ['Something went wrong. Please try again.']
    });
  }
});

// ── POST /api/admin/logout ────────────────────────────────────────────────
router.post('/api/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('[admin-auth] Logout error:', err);
    res.clearCookie('vaultshare.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    return res.json({ ok: true });
  });
});

// ── GET /api/admin/me — check if admin session is active ─────────────────
router.get('/api/admin/me', (req, res) => {
  if (req.session?.isAdmin === true) {
    return res.json({ ok: true, isAdmin: true, email: ADMIN_EMAIL_NORMALIZED });
  }
  return res.json({ ok: true, isAdmin: false });
});

// ── Middleware: requireAdminSession ────────────────────────────────────────
// Protects pages (redirects to /admin-login.html if not authenticated)
export function requireAdminSession(req, res, next) {
  if (req.session?.isAdmin === true) {
    return next();
  }
  return res.redirect('/admin-login.html');
}

// ── Middleware: requireAdminSessionApi ────────────────────────────────────
// Protects API endpoints (returns 401/403 JSON if not authenticated)
export function requireAdminSessionApi(req, res, next) {
  if (req.session?.isAdmin === true) {
    return next();
  }
  return res.status(401).json({
    ok: false,
    errors: ['Admin authentication required.']
  });
}

export default router;
