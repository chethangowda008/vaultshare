/**
 * VaultShare — server.js
 *
 * Express server with:
 * - Persistent SQLite sessions
 * - User authentication
 * - Single-Admin Authentication System (admin-auth.js)
 * - Security headers
 * - Dashboard
 * - Personal vault
 * - Secure sharing
 * - Activity logs
 * - Security dashboard
 */

'use strict';

import './env.js';
import express from 'express';
import session from 'express-session';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import helmet from 'helmet';

import authRouter, { requireAuthPage, requireAdminPage } from './auth.js';
import dashboardRouter from './dashboard.js';
import vaultRouter from './vault.js';
import sharesRouter from './shares.js';
import activityRouter from './activity.js';
import securityRouter from './security.js';
import adminRouter from './admin.js';
import recycleBinRouter, { startRecycleBinPurgeJob } from './recyclebin.js';
import analyticsRouter from './analytics.js';
import sessionsRouter from './sessions.js';
import accountRouter from './account.js';
import settingsRouter from './settings.js';
import fileopsRouter, { startExpirationJob } from './fileops.js';
import uploadsRouter, { purgeStaleUploads } from './uploads.js';
import { drainExpiredShares, expireStaleShares } from './db.js';

// ── Single-Admin Authentication System ────────────────────────────────────
import adminAuthRouter, {
  requireAdminSession,
  requireAdminSessionApi,
} from './admin-auth.js';

import sessionStore from './session-store.js';

import './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = process.env.PORT || 3000;
const ENV = process.env.NODE_ENV || 'development';

const dataDir = path.join(__dirname, 'data');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const secretFile = path.join(dataDir, 'session-secret.txt');

function getSessionSecret() {
  if (process.env.SESSION_SECRET) {
    return process.env.SESSION_SECRET;
  }

  if (fs.existsSync(secretFile)) {
    const existingSecret = fs.readFileSync(secretFile, 'utf8').trim();

    if (existingSecret.length >= 32) {
      return existingSecret;
    }
  }

  const newSecret = crypto.randomBytes(64).toString('hex');

  fs.writeFileSync(
    secretFile,
    newSecret,
    {
      encoding: 'utf8',
      mode: 0o600
    }
  );

  return newSecret;
}

const SESSION_SECRET = getSessionSecret();

app.disable('x-powered-by');

app.use(express.json({
  limit: '1mb'
}));

app.use(express.urlencoded({
  extended: true,
  limit: '1mb'
}));

// CSRF defence (on top of SameSite=Lax cookies): browsers always send Origin
// on cross-site state-changing requests, so a mismatching Origin is refused.
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin) {
      let ok = false;
      try { ok = new URL(origin).host === req.get('host'); } catch { ok = false; }
      if (!ok) return res.status(403).json({ ok: false, errors: ['Cross-site request blocked.'] });
    }
    if (req.get('sec-fetch-site') === 'cross-site') {
      return res.status(403).json({ ok: false, errors: ['Cross-site request blocked.'] });
    }
  }
  next();
});

app.use(
  session({
    name: 'vaultshare.sid',

    secret: SESSION_SECRET,

    store: sessionStore,

    resave: false,

    saveUninitialized: false,

    rolling: true,

    cookie: {
      httpOnly: true,

      sameSite: 'lax',

      secure: ENV === 'production',

      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        scriptSrc: ["'self'", "'unsafe-inline'"],

        scriptSrcAttr: ["'unsafe-inline'"],

        styleSrc: [
          "'self'",
          'https://fonts.googleapis.com'
        ],

        fontSrc: [
          "'self'",
          'https://fonts.gstatic.com'
        ],

        connectSrc: ["'self'"],

        imgSrc: [
          "'self'",
          'data:',
          'blob:'
        ],

        frameSrc: ["'self'", 'blob:'],

        workerSrc: ["'self'"],

        objectSrc: ["'none'"],

        baseUri: ["'self'"],

        formAction: ["'self'"]
      }
    },

    crossOriginOpenerPolicy: {
      policy: 'same-origin'
    },

    crossOriginEmbedderPolicy: {
      policy: 'require-corp'
    },

    referrerPolicy: {
      policy: 'no-referrer'
    },

    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  })
);

app.use((req, res, next) => {
  res.setHeader(
    'X-Content-Type-Options',
    'nosniff'
  );

  res.setHeader(
    'Permissions-Policy',
    'camera=(self), microphone=(), geolocation=(), payment=()'
  );

  next();
});

// ── Register routers ──────────────────────────────────────────────────────

// Single-Admin auth router — handles /api/admin/login, /api/admin/logout, /api/admin/me
app.use(adminAuthRouter);

app.use(authRouter);

app.use(dashboardRouter);

app.use(vaultRouter);

app.use(sharesRouter);

app.use(activityRouter);

app.use(securityRouter);

// Wrap all admin API routes with requireAdminSessionApi BEFORE registering adminRouter
// This ensures every /api/admin/* route requires a valid admin session.
app.use((req, res, next) => {
  // Only intercept admin API routes (not /api/admin/login|logout|me which are handled above)
  if (
    req.path.startsWith('/api/admin/') &&
    !['/api/admin/login', '/api/admin/logout', '/api/admin/me'].includes(req.path)
  ) {
    return requireAdminSessionApi(req, res, next);
  }
  next();
});

app.use(adminRouter);

app.use(recycleBinRouter);

app.use(analyticsRouter);

app.use(sessionsRouter);

app.use(accountRouter);

app.use(uploadsRouter);

app.use(settingsRouter);

app.use(fileopsRouter);

// ── Admin Login Page (public — no auth required to view it) ───────────────
// admin-login.html is served by express.static; we allow it through
// since the page itself is the login form.

// ── Admin-only HTML pages — protected by requireAdminSession ─────────────
// These are registered BEFORE express.static so the guard always runs.

app.get(
  '/admin.html',
  requireAdminSession,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  }
);

app.get(
  '/admin-users.html',
  requireAdminSession,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-users.html'));
  }
);

app.get(
  '/admin-audit.html',
  requireAdminSession,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-audit.html'));
  }
);

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VaultShare',
    version: '3.1.0',
    environment: ENV,
    sessionStore: 'sqlite',
    timestamp: new Date().toISOString()
  });
});

// Auth-guarded pages for regular users. Registered BEFORE express.static.
const PROTECTED_PAGES = [
  '/index.html', '/dashboard.html', '/profile.html', '/my-shares.html',
  '/shared-with-me.html', '/activity.html', '/security.html',
  '/recycle-bin.html', '/analytics.html', '/sessions.html', '/settings.html',
];
app.get(PROTECTED_PAGES, requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', req.path));
});

app.use(
  express.static(
    path.join(__dirname, 'public'),
    {
      index: false,
      maxAge: ENV === 'production' ? '1d' : 0,
      etag: true,
      lastModified: true
    }
  )
);

app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  res.redirect('/login.html');
});

app.get(
  '/dashboard.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'dashboard.html'
      )
    );
  }
);

app.get(
  '/index.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);

app.get(
  '/profile.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'profile.html'
      )
    );
  }
);

app.get(
  '/my-shares.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'my-shares.html'
      )
    );
  }
);

app.get(
  '/shared-with-me.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'shared-with-me.html'
      )
    );
  }
);

app.get(
  '/activity.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'activity.html'
      )
    );
  }
);

app.get(
  '/security.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'security.html'
      )
    );
  }
);

app.get(
  '/recycle-bin.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'recycle-bin.html'));
  }
);

app.get(
  '/analytics.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
  }
);

app.get(
  '/sessions.html',
  requireAuthPage,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sessions.html'));
  }
);

app.get(
  '/share/:token',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'share.html'
      )
    );
  }
);

app.use((req, res) => {
  res
    .status(404)
    .type('text')
    .send('404 — Not Found');
});

// Central error handler: log details on the server, never leak stack traces.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[server] unhandled error:', err && err.message);
  if (res.headersSent) return next(err);
  const status = err && (err.status || err.statusCode) >= 400 && (err.status || err.statusCode) < 600 ? (err.status || err.statusCode) : 500;
  const msg = status === 400 ? 'Bad request.' : status === 413 ? 'Request is too large.' : 'Something went wrong. Please try again.';
  if (req.path.startsWith('/api/')) return res.status(status).json({ ok: false, errors: [msg] });
  res.status(status).type('text').send(msg);
});

app.listen(PORT, () => {
  startRecycleBinPurgeJob();
  startExpirationJob();
  purgeStaleUploads();
  setInterval(purgeStaleUploads, 60 * 60 * 1000);

  // Expire stale shares every 30s
  setInterval(() => {
    try {
      expireStaleShares();
      drainExpiredShares();
    } catch (e) {
      console.error('[jobs] share expiry error:', e.message);
    }
  }, 30 * 1000);

  console.log(`
╔══════════════════════════════════════════╗
║            VaultShare Server             ║
║                                          ║
║   http://localhost:${PORT}                 ║
║                                          ║
║   Environment: ${ENV.padEnd(23)}║
║   Session Store: SQLite                  ║
║   Admin Login:  /admin-login.html        ║
║                                          ║
╚══════════════════════════════════════════╝
  `);
});

export default app;
