# VaultShare — Final-Year Project Documentation (Step 15)

**VaultShare: Secure Encrypted File Sharing and Access Management System**
BCA Final-Year Project

---

## 1. Final Project Architecture

```
Browser (client)                          Server (Node.js / Express)
─────────────────                         ───────────────────────────
crypto.js   → AES-256 encrypt/decrypt      server.js   → routing, security headers
              (Web Crypto API, PBKDF2)      auth.js     → register/login/logout, sessions
app.js      → encrypt/decrypt UI logic      db.js       → SQLite (users, files, shares,
vault.js    → My Vault + Share modal                      activity_logs)
ui.js       → tabs, toasts, formatting      vault.js    → store/list/download/delete files
auth.js     → session-aware nav bar         shares.js   → create/list/revoke shares, QR
                                             activity.js → activity log API
                                             security.js → security overview API
        │                                          │
        └──────────── HTTPS/JSON + multipart ───────┘
                    (cookies for session auth)
```

**Key principle — zero-knowledge encryption:** the password never
leaves the browser. The server only ever sees and stores
already-encrypted `.vaultenc` bytes.

## 2. Module Explanation

| # | Module | What it does |
|---|--------|---------------|
| 1 | User Authentication | Register/login/logout, bcrypt password hashing, sessions, rate limiting |
| 2 | Personal Vault | Upload, list, download, delete encrypted files (server never decrypts) |
| 3 | Encryption & Integrity | AES-256-GCM/CBC/CTR, PBKDF2-SHA256 key derivation, SHA-256 integrity hash |
| 4 | Secure File Sharing | Random-token links, expiry, download limits, revoke — all enforced server-side |
| 5 | Security Monitoring | Activity log (filterable) + Security Dashboard (real DB-derived stats) |
| 6 | Dashboards | User Dashboard (My Files/Shared/Downloads/Active Shares) — all real queries, no fake numbers |
| 7 | QR Code Sharing | Server-generated QR (npm `qrcode`) encoding only the share URL |

## 3. Database ER Diagram (description)

```
users (1) ──< files (owner_id)
users (1) ──< shares (owner_id)       [shares a file the user owns]
users (1) ──< shares (recipient_id)   [shares sent TO the user, nullable]
files (1) ──< shares (file_id)
users (1) ──< activity_logs (user_id, nullable — anonymous share access)
files (1) ──< activity_logs (file_id, nullable)
```

- `users`: id, name, email (unique), password_hash, created_at, last_login
- `files`: id, owner_id→users, original_filename, encrypted_filename, file_path, file_size, algorithm, file_hash, created_at, updated_at
- `shares`: id, file_id→files, owner_id→users, recipient_id→users (nullable), share_token (unique, random), expires_at, download_limit, download_count, status, created_at, last_accessed_at
- `activity_logs`: id, user_id→users (nullable), file_id→files (nullable), action, ip_address, user_agent, created_at

## 4. Data Flow (encrypt → share → decrypt)

1. User selects a file + password in the browser
2. `crypto.js` derives a key with PBKDF2-SHA256, encrypts with AES-256-GCM, computes a SHA-256 hash of the original file, and packages everything into a `.vaultenc` blob — **entirely client-side**
3. "Save to Vault" uploads the encrypted blob + metadata (never the password) to `POST /api/vault/upload`
4. Server validates it's really a `.vaultenc` package, stores it under a random UUID filename, records metadata in `files`
5. Owner shares it: `POST /api/shares` creates a `crypto.randomBytes` token, optional recipient/expiry/limit, inserted into `shares`
6. Recipient opens `/share/:token` (no login required) → server checks status/expiry/limit on every access, streams the file if valid, logs `ACCESS_SHARE`/`DOWNLOAD`
7. Recipient decrypts locally in the browser with the password (shared out-of-band) — server was never involved in decryption

## 5. Security Architecture

- **Password storage:** bcrypt, 12 rounds — never plaintext, never in API responses
- **Encryption keys:** derived per-file via PBKDF2-SHA256 with a random salt; the password itself is never transmitted or stored
- **Session auth:** `express-session`, HTTP-only cookies
- **Authorization:** every file/share lookup filters by `owner_id` in the SQL query itself — a client-supplied id alone is never sufficient
- **Share tokens:** `crypto.randomBytes(24)`, not sequential/guessable
- **Server-side enforcement:** expiry and download limits are checked on the server on every access, never trusted from the frontend
- **Rate limiting:** login (10/15min) and registration (10/hour) per IP
- **File safety:** random UUID filenames on disk, magic-byte validation of uploads, files stored outside `public/` so they're unreachable except through the authenticated/validated routes
- **HTTP hardening:** Helmet (CSP, security headers), generic error messages (no stack traces or SQL leaked to the client)

## 6. Project Workflow

Register → Login → Dashboard → Encrypt a file → Save to Vault →
Share Securely (set expiry/limit, optionally a recipient) → Copy
link or generate QR → Recipient opens link/scans QR → Downloads →
Decrypts locally with the shared password → Owner can revoke
anytime from My Shares → all of the above shows up in Activity and
Security.

## 7. Technologies Used

Node.js, Express.js, `node:sqlite` (built-in), bcryptjs, express-session,
express-rate-limit, multer, qrcode, Helmet, HTML/CSS/vanilla JS,
Web Crypto API (AES-256-GCM/CBC/CTR, PBKDF2, SHA-256).

## 8. Advantages

- Zero-knowledge design — server operator can never read user files
- No paid/cloud dependency — runs fully locally with SQLite
- Every dashboard number is a real query, not a mock
- Defense-in-depth: ownership checks, rate limiting, path-traversal protection, magic-byte validation

## 9. Limitations

- Single-server SQLite — not built for horizontal scaling
- No email delivery for share notifications (link/QR must be shared manually)
- No 2FA yet
- QR/share links rely on the recipient already having the password through a separate channel (by design, but worth noting in a viva)

## 10. Future Enhancements

- Two-factor authentication (TOTP)
- Email notifications when a share is accessed or about to expire
- Admin panel with platform-wide stats (Feature 18 — partially deferred)
- Client-side QR scanning to auto-fill share links
- File versioning / folders

## 11. Sample Viva Questions & Answers

**Q: Where is the encryption password stored?**
A: Nowhere on the server — it never leaves the browser. Only the AES-encrypted bytes are stored.

**Q: How do you stop User B from downloading User A's file by guessing an ID?**
A: Every file/share query includes `WHERE owner_id = ?` (or `recipient_id`) bound to the logged-in session — an id alone is never enough.

**Q: How are share links kept unguessable?**
A: `crypto.randomBytes(24)` — cryptographically secure randomness, not a sequential or timestamp-based id.

**Q: What happens when a download limit is reached?**
A: The server increments `download_count` on every successful download and flips `status` to `'completed'` once it reaches `download_limit`; this is checked server-side on every request, not just hidden client-side.

**Q: Why SQLite instead of MySQL/PostgreSQL?**
A: Zero setup for a student demo/viva, file-based, and Node's built-in `node:sqlite` needs no extra native dependency.

**Q: How does the QR code stay safe?**
A: It encodes only the share URL — the same server-side expiry/limit/revoke checks apply whether the link is opened by typing it, clicking it, or scanning the QR.

## 12. Project Demonstration Flow (for viva)

1. Register two accounts (User A, User B)
2. Log in as A → show Dashboard (real zero stats)
3. Encrypt a file → Save to Vault → show it appear in My Vault
4. Share it with B's email, 1-hour expiry, 5 downloads
5. Show the QR code, scan it on a phone
6. Log in as B → show it under Shared With Me → download → decrypt with the password
7. Back as A → My Shares → show download count went up → Revoke it
8. Reload B's link → show "revoked"
9. Show Activity page filtered by "Shares"
10. Show Security page — real share counts and event count

## 13. Resume Project Description

*VaultShare — Secure Encrypted File Sharing and Access Management System.*
Built a full-stack file-sharing platform (Node.js/Express, SQLite) with
client-side AES-256-GCM/CBC/CTR encryption, bcrypt authentication,
cryptographically random expiring share links with server-enforced
download limits, QR-code sharing, and real-time activity/security
dashboards — designed around a zero-knowledge model where the server
never has access to plaintext files or passwords.

## 14. 2-Minute Project Explanation

"VaultShare lets a user encrypt a file entirely in their browser using
AES-256, then optionally store that encrypted copy in a personal vault
on the server. From there they can generate a secure share link — with
an expiry time and a download limit — that a recipient can open even
without an account, download from, and decrypt locally using a
password shared separately. Every part of that flow — who owns what,
whether a link has expired, how many downloads are left — is checked
on the server, never trusted from the browser. The whole thing is
zero-knowledge: the server stores encrypted bytes and metadata, but
never sees a password or a plaintext file. On top of that there's a
dashboard, an activity log, and a security overview, all pulling real
numbers from the database instead of hard-coded placeholders."

## 15. 5-Minute Project Presentation (outline)

1. **Problem** (30s): sharing sensitive files safely, without trusting a third-party server with your data or your password.
2. **Core idea — zero-knowledge encryption** (60s): all crypto happens in the browser via the Web Crypto API; walk through `.vaultenc` package format (salt, IV, ciphertext, embedded SHA-256 hash).
3. **Live demo** (2 min): encrypt → save to vault → share with expiry/limit → QR code → open as recipient → decrypt → revoke.
4. **Security architecture** (60s): bcrypt, session auth, ownership-checked queries, random share tokens, server-enforced expiry/limits, rate limiting, Helmet headers.
5. **Dashboards are real data** (30s): show Dashboard/Activity/Security pulling from live DB, not mocked numbers.
6. **Wrap-up** (20s): tech stack, limitations, and what you'd add next (2FA, email notifications).
