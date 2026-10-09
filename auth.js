/**
 * VaultShare — auth.js
 *
 * User Registration & Login
 *
 * Endpoints:
 * POST /api/register
 * POST /api/login
 * POST /api/logout
 * GET  /api/me
 */

'use strict';

import express from 'express';
import { analyzeLogin, recordBaselineLogin } from './loginmonitor.js';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';

import {
  createUser,
  findUserByEmail,
  findUserById,
  touchLastLogin,
  logActivity
} from './db.js';

const router = express.Router();

const BCRYPT_ROUNDS = 12;

const SESSION_DURATION =
  7 * 24 * 60 * 60 * 1000;

// Limits are configurable so automated tests can raise them; defaults are strict.
const LOGIN_LIMIT = parseInt(process.env.RATE_LIMIT_LOGIN_MAX, 10) || 10;
const REGISTER_LIMIT = parseInt(process.env.RATE_LIMIT_REGISTER_MAX, 10) || 10;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  limit: LOGIN_LIMIT,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    ok: false,
    errors: [
      'Too many login attempts. Please try again in a few minutes.'
    ]
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,

  limit: REGISTER_LIMIT,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    ok: false,
    errors: [
      'Too many accounts created from this network. Please try again later.'
    ]
  }
});

const EMAIL_RE =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegisterInput({
  name,
  email,
  password
}) {
  const errors = [];

  if (
    !name ||
    typeof name !== 'string' ||
    name.trim().length < 2
  ) {
    errors.push(
      'Name must be at least 2 characters long.'
    );
  }

  if (
    !email ||
    typeof email !== 'string' ||
    !EMAIL_RE.test(email.trim())
  ) {
    errors.push(
      'Please enter a valid email address.'
    );
  }

  if (
    !password ||
    typeof password !== 'string' ||
    password.length < 8
  ) {
    errors.push(
      'Password must be at least 8 characters long.'
    );
  } else if (
    !/[A-Za-z]/.test(password) ||
    !/[0-9]/.test(password)
  ) {
    errors.push(
      'Password must contain at least one letter and one number.'
    );
  }

  return errors;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

router.post(
  '/api/register',
  registerLimiter,
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body || {};

      const errors =
        validateRegisterInput({
          name,
          email,
          password
        });

      if (errors.length > 0) {
        return res.status(400).json({
          ok: false,
          errors
        });
      }

      const cleanEmail =
        email.trim().toLowerCase();

      const existing =
        findUserByEmail(cleanEmail);

      if (existing) {
        return res.status(409).json({
          ok: false,
          errors: [
            'An account with that email already exists.'
          ]
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          BCRYPT_ROUNDS
        );

      const user = createUser(
        name.trim(),
        cleanEmail,
        passwordHash
      );

      await regenerateSession(req);

      req.session.userId = user.id;

      req.session.createdAt =
        Date.now();

      req.session.ip = req.ip;
      req.session.userAgent = req.get('user-agent') || null;

      req.session.cookie.maxAge =
        SESSION_DURATION;

      await saveSession(req);

      recordBaselineLogin(user.id, req);

      logActivity(
        user.id,
        'REGISTER',
        {
          ip: req.ip,
          userAgent: req.get('user-agent')
        }
      );

      return res.status(201).json({
        ok: true,

        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });

    } catch (error) {
      console.error(
        '[auth] register error:',
        error
      );

      return res.status(500).json({
        ok: false,
        errors: [
          'Something went wrong. Please try again.'
        ]
      });
    }
  }
);

/**
 * Turns the current (fresh) session into a fully logged-in session.
 * Used by the login route to fully establish a session once credentials
 * are verified.
 */
export async function finishLogin(req, user) {
  await regenerateSession(req);
  req.session.userId = user.id;
  req.session.createdAt = Date.now();
  req.session.ip = req.ip;
  req.session.userAgent = req.get('user-agent') || null;
  req.session.cookie.maxAge = SESSION_DURATION;
  await saveSession(req);
  touchLastLogin(user.id);
  logActivity(user.id, 'LOGIN', { ip: req.ip, userAgent: req.get('user-agent') });
  await analyzeLogin(user, req);
}

router.post(
  '/api/login',
  loginLimiter,
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body || {};

      if (!email || !password) {
        return res.status(400).json({
          ok: false,
          errors: [
            'Email and password are required.'
          ]
        });
      }

      const genericError =
        'Invalid email or password.';

      const user =
        findUserByEmail(
          email.trim().toLowerCase()
        );

      if (!user) {
        logActivity(
          null,
          'FAILED_LOGIN',
          {
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        );

        return res.status(401).json({
          ok: false,
          errors: [genericError]
        });
      }

      const match =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (match && user.status === 'suspended') {
        logActivity(user.id, 'FAILED_LOGIN', { ip: req.ip, userAgent: req.get('user-agent') });
        return res.status(403).json({
          ok: false,
          errors: ['Your account has been suspended. Contact an administrator.']
        });
      }

      if (!match) {
        logActivity(
          user.id,
          'FAILED_LOGIN',
          {
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        );

        return res.status(401).json({
          ok: false,
          errors: [genericError]
        });
      }

      await finishLogin(req, user);

      return res.json({
        ok: true,

        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });

    } catch (error) {
      console.error(
        '[auth] login error:',
        error
      );

      return res.status(500).json({
        ok: false,
        errors: [
          'Something went wrong. Please try again.'
        ]
      });
    }
  }
);

router.post(
  '/api/logout',
  async (req, res) => {
    try {
      const userId =
        req.session?.userId;

      if (userId) {
        logActivity(
          userId,
          'LOGOUT',
          {
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        );
      }

      req.session.destroy(
        (error) => {
          if (error) {
            console.error(
              '[auth] logout error:',
              error
            );

            return res.status(500).json({
              ok: false,
              errors: [
                'Unable to log out.'
              ]
            });
          }

          res.clearCookie(
            'vaultshare.sid',
            {
              httpOnly: true,
              sameSite: 'lax',
              secure:
                process.env.NODE_ENV ===
                'production'
            }
          );

          return res.json({
            ok: true
          });
        }
      );

    } catch (error) {
      console.error(
        '[auth] logout error:',
        error
      );

      return res.status(500).json({
        ok: false,
        errors: [
          'Unable to log out.'
        ]
      });
    }
  }
);

router.get(
  '/api/me',
  async (req, res) => {
    try {
      if (!req.session?.userId) {
        return res.json({
          ok: true,
          user: null
        });
      }

      const user =
        findUserById(
          req.session.userId
        );

      if (!user) {
        req.session.destroy(
          () => {}
        );

        return res.json({
          ok: true,
          user: null
        });
      }

      return res.json({
        ok: true,

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          created_at: user.created_at,
          last_login: user.last_login,
          is_admin: !!user.is_admin
        }
      });

    } catch (error) {
      console.error(
        '[auth] /api/me error:',
        error
      );

      return res.status(500).json({
        ok: false,
        errors: [
          'Unable to check login status.'
        ]
      });
    }
  }
);

export function requireAuthPage(
  req,
  res,
  next
) {
  if (
    !req.session ||
    !req.session.userId
  ) {
    return res.redirect(
      '/login.html'
    );
  }

  const account = findUserById(req.session.userId);
  if (!account || account.status === 'suspended') {
    req.session.destroy(() => {});
    return res.redirect('/login.html?suspended=1');
  }

  next();
}

export function requireAuthApi(
  req,
  res,
  next
) {
  if (
    !req.session ||
    !req.session.userId
  ) {
    return res.status(401).json({
      ok: false,
      errors: [
        'Your session has expired. Please log in again.'
      ]
    });
  }

  // Feature 9: a suspended account loses API access immediately, even with
  // a still-valid session cookie (re-checked on every request, same pattern
  // as the admin guard below — never trust a cached flag).
  const account = findUserById(req.session.userId);
  if (!account || account.status === 'suspended') {
    req.session.destroy(() => {});
    return res.status(403).json({
      ok: false,
      errors: [
        'Your account has been suspended. Contact an administrator.'
      ]
    });
  }

  next();
}

/**
 * Feature 18 — Admin page guard.
 * Never trusts a client-sent flag: re-reads the user's is_admin
 * column from the database on every single request.
 */
export function requireAdminPage(
  req,
  res,
  next
) {
  if (
    !req.session ||
    !req.session.userId
  ) {
    return res.redirect(
      '/login.html'
    );
  }

  const user = findUserById(req.session.userId);

  if (!user || !user.is_admin) {
    return res.redirect(
      '/dashboard.html'
    );
  }

  next();
}

/**
 * Feature 18 — Admin API guard.
 * Never trusts a client-sent flag: re-reads the user's is_admin
 * column from the database on every single request.
 */
export function requireAdminApi(
  req,
  res,
  next
) {
  if (
    !req.session ||
    !req.session.userId
  ) {
    return res.status(401).json({
      ok: false,
      errors: [
        'Your session has expired. Please log in again.'
      ]
    });
  }

  const user = findUserById(req.session.userId);

  if (!user || !user.is_admin) {
    return res.status(403).json({
      ok: false,
      errors: [
        'Admin access required.'
      ]
    });
  }

  next();
}

export default router;