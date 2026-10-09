# VaultShare — Secure Cloud File Management and Sharing System

A final-year BCA project. Files are **encrypted in the browser** (AES-256-GCM, key from PBKDF2) before they are uploaded, so the server only ever stores ciphertext (**zero-knowledge**).

> **Note on this revision:** Folders, Search, Favorites, Security Incidents, Two-Factor Authentication, Notifications, and AI Tools have been **removed** from this build on request. See "What was removed" below for exactly what changed and why. Everything else — encryption, the vault, sharing, versioning, the Recycle Bin, analytics, the Security Center, sessions, and admin — is unchanged and fully working.

---

## 1. Project title
VaultShare — Secure Cloud File Management and Sharing System

## 2. Abstract
People store personal and academic documents on cloud drives whose operators can read them. VaultShare encrypts every file in the user's browser with a key derived from a password only the user knows, then manages, organises and shares the encrypted files with expiring, limited, optionally password-protected links — while the server itself is mathematically unable to read file contents.

## 3. Problem statement
Ordinary cloud storage (a) lets the provider read files, (b) shares files through links that never expire, and (c) offers little visibility into who logged in or from where. Students and small teams need a low-cost system where confidentiality does not depend on trusting the server.

## 4. Objectives
1. Encrypt/decrypt files on the client; never send passwords or plaintext to the server.
2. Provide safe sharing: expiry, download limits, revocation, share passwords, QR codes, multi-file shares.
3. Provide file management: versions, Recycle Bin, tagging, expiration, integrity verification.
4. Provide account security: sessions, suspicious-login detection, audit log, admin user management.
5. Provide transparency: analytics, a Security Center with an *explainable* score.
6. Keep everything runnable locally with no external services required.

## 5. Existing system
Register/login (bcrypt, sessions in SQLite), client-side AES-256-GCM/CBC/CTR encryption with PBKDF2 and SHA-256 integrity, personal vault, secure shares (expiry, download limits, revoke, QR generation/scanning), activity log, Security Center, admin dashboard, rate limiting, Helmet security headers.

## 6. Proposed system
Everything in §5 plus the features in §7.

## 7. Features
| Area | What it does |
|---|---|
| Vault | Upload, download, delete, client-side preview (images/PDF/text/CSV) |
| Version history | Upload new version, list, download old, non-destructive restore, delete old, per-version SHA-256 |
| Recycle bin | Soft delete, restore, delete forever, empty, per-user retention (default 30 days), auto-purge, blocked from normal download/share |
| Secure sharing | Expiry (1h/24h/7d/30d/custom/never), download limits, revocation, bcrypt-hashed share passwords (POST-only, never in a URL), multi-file shares (up to 20 files, one link/QR) |
| QR codes | Generate a QR for any share; scan a QR (camera or uploaded image) to open a share |
| Tagging | Add/remove/list tags on a file; strict validation (letters/numbers/spaces/-/_, 30 chars max) |
| File expiration | Optional auto-delete date (presets or custom); an hourly job moves due files to the Recycle Bin — never a hard delete |
| Integrity verification | A password-free **quick check** (existence/size/header) and a browser-side **full verify** (decrypt + compare SHA-256) |
| Storage quotas | Per-user quota (default 2 GB, admin-configurable); blocks over-quota uploads before any bytes are written |
| Duplicate detection | SHA-256 match within the same user's vault → warns before upload, "upload anyway" still available |
| Resumable upload | 4 MB chunks of the already-encrypted file; retry + resume; ordered offsets |
| Analytics | Totals, storage, uploads/downloads/shares/logins per day (SVG charts), file-type breakdown — all from real queries |
| Security Center | Explainable score out of 100, login history, failed logins, active sessions |
| Sessions | List devices/browsers/IP, end one or all others; ending is logged |
| Suspicious login detection | Transparent, rule-based (not AI) — see §13 |
| Settings | Account, Security, Privacy, Storage, Sharing defaults, Appearance |
| Dark/light/system theme | Persisted, flash-free (applied before paint) |
| Command palette | Ctrl+K / Cmd+K quick navigation |
| Admin | User management (suspend/unsuspend, reset sessions, quotas), storage/share/download stats, security event counts, system-wide audit dashboard, system health — aggregate counts only, never file content |

## 8. System architecture
```
Browser (crypto.js: AES-256-GCM, PBKDF2, SHA-256)          Node.js + Express server
  encrypt → .vaultenc bytes ───── HTTPS/JSON, multipart, ───► routers: auth, vault, uploads, fileops,
  decrypt/preview here             chunked PUT                 shares, analytics, sessions, security,
                                                                settings, account, admin
                                                               db.js (SQLite, node:sqlite) · session-store.js
                                                               loginmonitor.js
                                                               vault-storage/<userId>/<random-uuid>.vaultenc
```
The server never has the file password or plaintext. Admins have no keys, so they cannot decrypt files.

## 9. Technologies
Node.js 22+, Express, built-in `node:sqlite`, express-session (custom SQLite store), bcryptjs, Helmet, express-rate-limit, multer, qrcode, jsQR (self-hosted), Web Crypto API, vanilla HTML/CSS/JS, `node:test`.

## 10. Database design
SQLite file `data/vaultshare.db` (sessions in `data/sessions.db`). Foreign keys with `ON DELETE CASCADE`/`SET NULL` prevent orphans; indexes on owner/deleted/user columns.

| Table | Purpose |
|---|---|
| users | account, bcrypt hash, is_admin, status (active/suspended), storage_quota_bytes |
| files | current version of each file; deleted_at (recycle bin), version, expires_at, verification_status, tags via file_tags |
| file_versions | all older versions (storage path, size, hash, uploader) |
| file_tags | tags on a file |
| shares / share_items | share links (+ password_hash); extra files for multi-file shares |
| activity_logs | audit trail (user, action, file, ip, user-agent, time) |
| login_history | per-login device hash, network prefix, suspicious flag + reasons |
| upload_sessions | in-progress chunked uploads |
| user_settings | recycle-bin days, share defaults |
| app_settings | server-wide defaults (e.g. default storage quota) |

ER summary: `users 1—N files`, `files 1—N file_versions`, `files 1—N shares`, `files 1—N file_tags`, `shares 1—N share_items N—1 files`, `users 1—N login_history / activity_logs`.

## 11. Security architecture
Layers: (1) client-side encryption; (2) bcrypt(12) account passwords; (3) session cookies `HttpOnly`, `SameSite=Lax`, `Secure` in production, session regenerated at login; (4) ownership check on every query (`WHERE owner_id = ?`); (5) rate limiting on login, register, share password; (6) Helmet CSP (`script-src 'self'`), nosniff, HSTS, COOP/COEP; (7) CSRF Origin check + SameSite; (8) parameterised SQL only; (9) random storage names, storage outside `public/`, files served only through authenticated routes; (10) blocked executable filenames; (11) central error handler without stack traces; (12) audit log that never records passwords or keys; (13) account suspension re-checked server-side on every request.

## 12. Encryption workflow
1. User picks a file + password in the browser. 2. Browser generates random salt/IV, derives a 256-bit key with PBKDF2-SHA256 (310,000 iterations by default). 3. AES-256-GCM encrypts the file (authenticated). 4. SHA-256 of the original is embedded for integrity. 5. Only the `.vaultenc` package is uploaded. 6. To open, the browser re-derives the key from the password and decrypts; GCM tag + SHA-256 detect tampering.

## 13. Suspicious-login rules (not AI)
New device · new /24 network · ≥3 failures in 15 min · ≥5 logins in 10 min · ≥4 sessions · unusual hour (after ≥5 logins). Flagged when any of the last four hold, or when new device and new network occur together. Flags are recorded in `login_history` and shown on the Security Center page. No physical location is claimed.

## 14. File-sharing workflow
Owner picks file(s) → expiry, download limit, optional password → server creates an unguessable token (24 random bytes) → link + QR. Recipient opens `/share/<token>` (or scans the QR) → server checks status, expiry, limit, password → streams the *encrypted* file. The recipient still needs the file password (shared out-of-band) to decrypt in the browser. Revocation/expiry/limit are enforced server-side; soft-deleted files cannot be downloaded through shares.

## 15. Version management
Uploading a new version copies the current storage info into `file_versions` and points `files` at the new upload. "Restore" copies old bytes to a new random filename and creates a **new** version (history is never rewritten). Each version keeps its own SHA-256.

## 16. Recycle bin
Delete sets `deleted_at`. Normal listing, download and sharing ignore such files. A purge job runs at start-up and every 6 h using each user's retention (default `RECYCLE_BIN_RETENTION_DAYS`=30). File expiration (§7) feeds into the same bin.

## 17. Integrity verification — honest design note
The server cannot recompute a plaintext SHA-256 itself (zero-knowledge: it never has the password). So there are two tiers: a **quick check** (server-side, no password — confirms the encrypted file exists, is the right size, and has a valid header) and a **full verify** (the browser downloads, decrypts, and compares SHA-256 — this is the only way to actually detect content tampering).

## 18. Analytics
`/api/analytics` runs aggregate SQL for the signed-in user only (files, bytes, shares by status, downloads, per-day series, extension distribution). Charts are inline SVG (no CDN → strict CSP kept).

## 19. Installation
```bash
# Requires Node.js 22 or newer (uses built-in node:sqlite)
npm install
```

## 20. Configuration
Copy `.env.example` to `.env`. Nothing is mandatory — the app runs with no `.env` at all.

## 21. Environment variables
See `.env.example` (PORT, NODE_ENV, SESSION_SECRET, RECYCLE_BIN_RETENTION_DAYS, RATE_LIMIT_*).
`DATABASE_URL` and `ENCRYPTION_CONFIG` are placeholders only: the DB is a local SQLite file and encryption is chosen per file in the browser.

## 22. Running
```bash
npm start            # http://localhost:3000
npm run dev          # auto-restart (nodemon)
```
The first account registered becomes the administrator. There are **no default users or passwords**.

## 23. Testing
```bash
npm test              # 28 integration tests (spawns its own server on port 3199, throw-away DB)
npm run test:crypto   # original 18 crypto tests
```
Covers auth, IDOR/ownership, versioning, recycle bin, password/multi-file shares, sessions, password change, suspicious login, resumable upload (resume, ordering, corruption), executable blocking, CSRF, error leakage, SQLi/traversal/XSS payloads, admin authorisation, settings, tags, quotas, duplicate detection, integrity verification. See `docs/TESTING.md` and `docs/SECURITY_TEST_REPORT.md`.

## 24. Security considerations & honest limitations
- Zero-knowledge holds for all stored files — there is no longer any feature that sends decrypted content off the client.
- The server sees **filenames, sizes and hashes** (metadata); the executable-type block relies on the filename the browser reports, since file *content* cannot be scanned (it's ciphertext).
- If a user forgets a file password, the file cannot be recovered (by design).
- Encryption/decryption happens in memory in one step, so very large files are limited by browser memory even though uploads are chunked.
- Camera QR scanning needs a real device; it was **not** exercised end-to-end in the development sandbox (see `docs/TESTING.md`).
- IP addresses are stored for security display — mention this in a privacy note if deployed.
- Single-server SQLite: not built for many thousands of users.

## 25. Future enhancements
Chunk-wise streaming encryption for multi-GB files; WebAuthn/passkeys; per-file DEK + key-wrapping architecture (see the design note in `docs/BCA_PROJECT_REPORT.md`); Postgres + S3-compatible storage; mobile app; i18n and a full WCAG audit.

---

## 26. What was removed (and why)

On request, the following features were **completely removed** — not hidden, not disabled — from both the UI and the backend: **Folders, Search, Favorites, Security Incidents, Two-Factor Authentication, Notifications (in-app and email), and AI Tools.**

| Removed feature | Frontend removed | Backend removed | Database |
|---|---|---|---|
| Folders | `folders.html`, `folders.js`, sidebar links, "Move to folder" UI | `folders.js` router, all folder DB helper functions, folder handling in upload routes | `folders` table and `files.folder_id`/`upload_sessions.folder_id` columns **kept but inert** (see below) |
| Search | `search.html`, `search.js` | `search.js` router | n/a (no dedicated table) |
| Favorites | `favorites.html`, `favorites.js`, star button/toggle in My Vault | Favorite routes removed from `fileops.js` | `files.is_favorite` column **kept but inert** (see below) |
| Security Incidents | `incidents.html`, `incidents.js`, incident banners | `incidents.js` router, all `createIncident()` call sites in auth/shares/loginmonitor/fileops, incident stats removed from the admin audit dashboard | `security_incidents` table **dropped** |
| Two-Factor Authentication | `2fa.html`, `2fa.js`, the login page's second step | `twofa.js`, `twofa-state.js`, the 2FA gate in the login route, 2FA score factor in the Security Center | `user_2fa`, `recovery_codes` tables **dropped** |
| Notifications (in-app + email) | `notifications.html`, `notifications.js`, notification settings in Settings | `notifications.js`, `notify.js`, `email.js`, every `notify()` call site across the app | `notifications`, `notification_prefs` tables **dropped** |
| AI Tools | `ai.html`, `ai.js`, `ai-local.js` | `ai.js` router, AI status fields removed from the admin dashboard | `ai_classifications`, `ai_summaries` tables **dropped** |

### Why two columns and one table were kept instead of dropped
`files.folder_id`, `files.is_favorite`, and the `folders` table itself are **no longer read or written by any route** — functionally, Folders and Favorites are completely gone. They were not physically dropped from the schema because:
- `files.folder_id` and `upload_sessions.folder_id` were declared with `REFERENCES folders(id)`. Testing confirmed that dropping the `folders` table while that reference still exists makes SQLite refuse to even *compile* ordinary `files`/`upload_sessions` queries at server startup (`no such table: main.folders`) — not just folder-specific ones. Rebuilding the live `files` table (real user data) to remove that one column was judged a bigger risk than leaving one small, permanently-empty table in place.
- `files.is_favorite` is a plain column on the shared `files` table; `ALTER TABLE ... DROP COLUMN` on a table holding real user data, for a feature that only needed removing in the application layer, was judged an unnecessary risk.

Both are confirmed **completely inert**: no API route reads or writes them, and a fresh grep of the whole codebase after the removal finds zero remaining references to Folders or Favorites functionality.

### Security Center score, rebalanced
The score used to include a Two-Factor Authentication factor (25 pts) and a Recovery Codes factor (10 pts). With 2FA removed, those 35 points were redistributed across the remaining real factors (password protection, session hygiene, failed logins, suspicious login activity) so the score still totals 100 and still reflects only controls that genuinely exist in this build.

### Verified, not assumed
A database was seeded using the **original, pre-removal** code — a user with an enabled-2FA setup row, a folder, an uploaded file, and that file marked as a favorite — then this cleaned build was booted directly on top of it. Login, file listing, byte-identical download, the security score, settings, and the Recycle Bin all worked with zero errors, and every removed endpoint correctly returned 404 instead of crashing.

---

### Folder structure
```
server.js  env.js  db.js  auth.js  vault.js  uploads.js  fileops.js  recyclebin.js
shares.js  analytics.js  sessions.js  session-store.js  security.js  loginmonitor.js
settings.js  account.js  admin.js  dashboard.js  activity.js
public/  (HTML pages, css/, js/, js/vendor/jsQR.js)      tests/  docs/  deploy/  .env.example
```
