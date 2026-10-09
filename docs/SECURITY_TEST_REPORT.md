# VaultShare — Security Testing Results

Method: automated attack-style requests against a live server (`tests/integration.test.mjs`, 28 tests) plus code review of every route. Not a professional penetration test.

## Threat model & attack surface
Actors: anonymous visitor, registered user, share recipient, administrator. Attack surface: the public HTTP API, the public share-download endpoint, the admin API, and the stored encrypted files on disk. The server never holds a file password or decryption key, so the file-content attack surface is limited to metadata (names, sizes, hashes) regardless of any other vulnerability.

| Threat | What was tried | Result |
|---|---|---|
| Broken access control / IDOR | User B calling A's file version/download/delete/tag/expiration/integrity/session-termination endpoints | All return 404 / no data |
| Unauthenticated access | Every API and protected HTML page without a cookie | 401 / redirect |
| Privilege escalation | Normal user calling `/api/admin/*` | 403 |
| Account suspension bypass | Suspended user's existing session re-used; suspended user tries to log back in | Session destroyed immediately on suspend (401 after); login blocked (403) even with the correct password |
| Self-suspension abuse | Admin tries to suspend their own account | 400, blocked explicitly |
| Brute force (login) | Rate limiter (10 / 15 min / IP by default) | Enforced (raised only for tests via env var) |
| Share password guessing | Wrong/missing password; rate limiter | Rejected; logged as `SHARE_AUTH_FAILED` |
| Session fixation | Session regenerated at login | Yes |
| CSRF | Cross-origin `Origin` header on a state-changing request | 403; SameSite=Lax cookies |
| SQL injection | Payloads in tag values and numeric-id routes | Parameterised queries throughout; strict tag validation; non-numeric ids rejected (404), never passed to SQL |
| Path traversal | `/vault-storage/...`, `..%2f`, `/db.js` | 404 / not served |
| XSS | Script payloads in tag values | Rejected by strict tag validator (letters/numbers/spaces/-/_ only) before reaching storage |
| File-upload abuse | `.exe/.bat` filenames; wrong magic header; oversize; out-of-order chunks | Refused |
| Storage quota bypass | Upload larger than an admin-set per-user quota | 400 before any bytes are written to disk |
| Duplicate-detection bypass as a DoS vector | Re-upload of identical content without confirmation | 409 with the existing file listed; explicit confirm required — never silently blocks forever |
| Insecure direct file access | Soft-deleted file via download and share link | 404 |
| Information leakage | Malformed JSON, generic errors | No stack traces; generic messages |
| Token leakage | Share passwords sent via POST body (never a URL); password hashes never returned in API responses | Verified |
| Secrets in code | No hard-coded keys/passwords; `.env` is git-ignored | Verified by grep |

## Feature removal — security review
Removing Folders, Search, Favorites, Security Incidents, 2FA, Notifications, and AI Tools was reviewed for security regressions, not just functional ones:
- **Every removed route returns 404**, confirmed with a live server (see `docs/TESTING.md`) — no removed endpoint was left reachable or silently broken into a 500.
- **No dangling code path** calls into a deleted module: a full-codebase grep for the removed features' identifiers, after cleanup, returns only inert comments and two intentionally-kept, functionally-dead database artifacts (see README §26).
- **Login no longer has a 2FA branch**, so the authentication flow is simpler: password → bcrypt compare → session. This was verified not to have regressed suspension enforcement, rate limiting, or generic error messages (all still tested and passing).
- **The Security Center score was rebalanced**, not left silently wrong — it no longer references a feature that doesn't exist, and still sums to 100 from real, present controls only (verified by test #9).
- **Dropping `user_2fa`, `recovery_codes`, `security_incidents`, `notifications`, `notification_prefs`, `ai_classifications`, `ai_summaries`** was done only for tables with **zero** other tables referencing them as a parent — confirmed by testing that a database seeded with real rows in all of these tables boots cleanly on this build with no foreign-key or schema errors.

## Known residual risks
- `req.ip` depends on proxy configuration; behind a reverse proxy set Express `trust proxy` correctly.
- Filename-based executable blocking can be bypassed by renaming (file content is ciphertext and cannot be inspected).
- Session cookies are `Secure` only when `NODE_ENV=production` (use HTTPS in production).
- `files.folder_id` and `files.is_favorite` remain as inert columns in the schema (see README §26) — confirmed unused by any route, so they carry no functional or access-control risk, only minor schema clutter.
- `npm audit` was not part of this pass; run it before deployment.

## Future improvements
WebAuthn/passkeys as a hardened second factor; a per-file DEK + key-wrapping architecture (see `docs/BCA_PROJECT_REPORT.md`); a full professional penetration test before any production deployment.
