# VaultShare — Testing

## Automated (run `npm test`, `npm run test:crypto`)
28 integration tests (own throwaway server + database) + 18 crypto tests. All passing.

| # | Test | Result |
|---|------|--------|
| 1 | Register two users | Pass |
| 2 | Unauthenticated API access rejected (analytics, sessions, recycle-bin) | Pass |
| 3 | Upload a file | Pass |
| 4 | IDOR: another user cannot download/version/delete someone else's file | Pass |
| 5 | Versioning: upload v2, list, download old, non-destructive restore, history preserved, delete old | Pass |
| 6 | Recycle bin: soft delete hides file, restore, purge, cross-user restore blocked | Pass |
| 7 | Password-protected share: missing/wrong/correct password; hash never exposed | Pass |
| 8 | Sessions: list, second login, end other, other user cannot end it | Pass |
| 9 | Analytics + explainable security score adds up to 100 | Pass |
| 10 | Protected pages redirect anonymous users; public pages (login/register) stay reachable | Pass |
| 11 | Soft-deleted file cannot be downloaded through its share link | Pass |
| 12 | Change password: wrong current rejected, other sessions ended, old password stops working | Pass |
| 13 | Suspicious login (repeated failures) flagged and visible in login history | Pass |
| 14 | Multi-file share: ownership enforced, per-item download | Pass |
| 15 | Resumable upload: resume offset, out-of-order rejected, incomplete rejected, byte-identical result, cross-user blocked, bad header rejected | Pass |
| 16 | Executable filenames refused (single + chunked upload) | Pass |
| 17 | Settings validation, per-user retention, custom share expiry | Pass |
| 18 | Admin authorisation and aggregate-only stats | Pass |
| 19 | CSRF cross-origin request blocked | Pass |
| 20 | Malformed JSON: no stack trace leaked | Pass |
| 21 | SQL injection / path traversal / XSS payloads handled safely | Pass |
| 22 | Duplicate detection: warns on identical content, allows upload-anyway, distinct content is fine | Pass |
| 23 | Storage quota: blocks oversized upload, admin can raise/clear it, quota endpoint reports usage | Pass |
| 24 | Tags: toggle, list, validation, ownership | Pass |
| 25 | File expiration: presets, custom date validation, invalid preset rejected | Pass |
| 26 | Integrity: quick-check passes for a healthy file, reported full-verify failure is recorded | Pass |
| 27 | Admin user management: list, suspend immediately blocks API+login, unsuspend restores, self-suspend blocked, reset-sessions force-logs-out | Pass |
| 28 | System-wide security audit dashboard: admin-only, returns real day/type/login aggregates | Pass |
| — | Original crypto suite (18 tests) | Pass |

## Feature-removal verification (manual, see also README §26)
A database was seeded with the **original pre-removal code**: a user, a folder, an uploaded file marked as a favorite, and a `user_2fa` setup row. This cleaned build was then booted directly on that database:
- Login, file listing, byte-identical download (250 bytes in / 250 bytes out), quota, settings, and Recycle Bin all worked.
- Security score computed correctly (100/100 on a clean account) with no crash from the missing 2FA data.
- Every removed endpoint (`/api/folders`, `/api/vault/favorites`, `/api/incidents/mine`, `/api/notifications`, `/api/ai/status`, `/api/login/2fa`, `/api/2fa/setup`) and every removed page (`folders.html`, `search.html`, `favorites.html`, `incidents.html`, `2fa.html`, `notifications.html`, `ai.html`) returned a clean 404 — no 500 errors anywhere in the server log.

## NOT tested in this sandbox (no browser/camera available)
| Feature | How to test manually |
|---|---|
| Every remaining page in a real browser (layout, buttons, modals) | Click through the manual checklist below |
| Camera QR scanning | Open `/scan.html`, allow camera, scan a share QR; "Upload QR image" also works without a camera |
| PDF/image preview rendering | Save a PDF, click 👁 Preview |
| Dark/light/system theme toggle, Ctrl+K command palette | Click the header toggle three times; press Ctrl+K on any page |

## Manual browser checklist
1. Register → Encrypt a file → Save to Vault (progress % shows; duplicate-content warning if you re-upload the same file).
2. My Vault: Preview, Versions (upload new, restore), tag a file, set an expiration, Verify (quick check), Share (password, custom expiry), Delete.
3. Recycle Bin: restore / delete forever.
4. Sessions: log in from a second browser, end it from the first.
5. Share link in a private window (password prompt, multi-file list, QR code).
6. Security Center score and login history.
7. Analytics charts.
8. Admin (first account): dashboard, Manage Users (suspend/unsuspend/quota/reset sessions), Security Audit.
9. Settings: storage/sharing defaults, appearance, change password (Profile).
10. **Confirm absent:** no Folders, Search, Favorites, Security Incidents, 2FA, Notifications, or AI links/pages/buttons anywhere.
