# VaultShare — BCA Final-Year Project Report

**Title:** VaultShare – Secure Cloud File Management and Sharing System
**Student:** Purshottam V &nbsp;|&nbsp; **Course:** BCA (Final Year) &nbsp;|&nbsp; **College:** Akash Global College of Management and Science

> This revision removes Folders, Search, Favorites, Security Incidents, Two-Factor Authentication, Notifications, and AI Tools from an earlier, larger version of the project (see §20, "Feature Removal"). Everything described in this report reflects the **current, working state** of the codebase — no removed feature is described here as available.

## 1. Abstract
VaultShare is a web-based file management and sharing system in which files are encrypted in the user's browser using AES-256-GCM with a key derived from a password by PBKDF2. The server stores only ciphertext, so even administrators cannot read user files. The system provides secure sharing (expiry, download limits, passwords, QR codes, multi-file shares), full version history, a Recycle Bin, tagging, file expiration, integrity verification, storage quotas, duplicate detection, analytics, a Security Center, session management, and an admin dashboard — built with Node.js, Express and SQLite, running locally without external services.

## 2. Introduction
Cloud storage is convenient but requires trust in the provider. Client-side ("zero-knowledge") encryption removes that trust for the file contents. VaultShare demonstrates this approach as a complete, usable storage manager.

## 3. Problem Statement
Existing consumer cloud services can read stored files and produce non-expiring share links. There is a need for an affordable system that keeps content confidential from the server while still offering organisation, sharing and security monitoring.

## 4. Existing System
Commercial options (Google Drive, Dropbox) offer rich features but no default zero-knowledge guarantee. Zero-knowledge services (Mega, Proton Drive) are closed/hosted, not a learnable, self-hostable codebase.

## 5. Proposed System
A self-hosted, zero-knowledge file vault with full lifecycle management (versions, Recycle Bin, tags, expiration, integrity checks) and strong, transparent account security (sessions, rule-based suspicious-login detection, an explainable security score, admin oversight) — all running on a single Node.js process with a local SQLite database.

## 6. Objectives
Confidential storage; controlled sharing; organised file lifecycle management; session security; visible security posture; simple local deployment; suitability for academic demonstration.

## 7. Scope
In scope: single-server web application for individuals and small groups, files up to 500 MB, modern browsers with Web Crypto. Out of scope: mobile native apps, multi-server scaling, multi-user key exchange, malware scanning of file contents (impossible under zero-knowledge).

## 8. Technologies Used
Node.js 22+, Express, built-in `node:sqlite`, express-session (custom SQLite store), bcryptjs, Helmet, express-rate-limit, multer, qrcode, jsQR (self-hosted), Web Crypto API, vanilla HTML/CSS/JS, Node's built-in test runner.

## 9. Hardware / Software Requirements
**Hardware:** any PC with 4 GB RAM. **Software:** Node.js 22+, a modern browser (Chrome/Edge/Firefox/Safari), VS Code (optional).

## 10. System Architecture
Three tiers: browser (UI + cryptography), Express API (auth, authorisation, business rules), storage (SQLite metadata + encrypted files on disk). See the diagram in README §8.

## 11. Module Description
Authentication (`auth.js`) · Vault & uploads (`vault.js`, `uploads.js`) · Tags/expiration/integrity (`fileops.js`) · Recycle bin (`recyclebin.js`) · Sharing (`shares.js`) · Analytics (`analytics.js`) · Security Center (`security.js`, `loginmonitor.js`) · Sessions (`sessions.js`, `session-store.js`) · Settings/Account (`settings.js`, `account.js`) · Admin (`admin.js`) · Front-end pages in `public/`.

## 12. Database Design
10 tables: `users`, `files`, `file_versions`, `file_tags`, `shares`, `share_items`, `activity_logs`, `login_history`, `upload_sessions`, `user_settings`, `app_settings`. Primary keys on every table, foreign keys with cascade, indexes on lookup columns, timestamps on all event tables. Full column list in README §10.

### ER diagram (description)
Entities: USER, FILE, FILE_VERSION, FILE_TAG, SHARE, SHARE_ITEM, ACTIVITY_LOG, LOGIN_HISTORY.
Relationships: USER owns many FILEs (1:N). FILE has many FILE_VERSIONs, many FILE_TAGs, and many SHAREs (all 1:N). A SHARE may list many FILEs through SHARE_ITEM (M:N).

## 13. Data Flow Diagrams (description)
**Level 0:** User ⇄ VaultShare system. Inputs: credentials, files (encrypted), settings. Outputs: encrypted files, share links, reports.
**Level 1 processes:** 1 Authenticate (User, Session store) · 2 Manage files (Files, Versions, Recycle bin, Tags) · 3 Share files (Shares, Share items) · 4 Monitor security (Login history, Activity log, Sessions) · 5 Analyse (Aggregates from Files/Shares/Activity).
**Encryption data flow:** Plain file → [browser: PBKDF2 → AES-256-GCM + SHA-256] → `.vaultenc` → [HTTPS] → server disk. Password never crosses the network.

## 14. Use Case Description
Actors: Registered User, Share Recipient, Administrator.
- User: encrypt & store, organise with tags, version, delete/restore, set expiration, verify integrity, share, scan QR, review sessions/security, manage settings.
- Recipient: open share link/QR, enter share password if set, download encrypted file, decrypt with the password given by the owner.
- Administrator: view aggregate statistics, manage user accounts (suspend/unsuspend, quotas, reset sessions), review system-wide security audit — cannot read or decrypt files.

## 15. Security Architecture
See README §11 and `docs/SECURITY_TEST_REPORT.md`.

## 16. Encryption Architecture
**AES-256-GCM:** a 256-bit-key block cipher in a mode that adds an authentication tag, so any tampering with the ciphertext is detected on decryption. A fresh random IV is used for every file.
**PBKDF2-HMAC-SHA256:** stretches a human password into a 256-bit key by repeating HMAC 310,000 times with a random salt.
**SHA-256:** a one-way hash of the original file, verified after decryption to confirm integrity.
**bcrypt:** slow, salted password hashing (cost 12) for account passwords and share passwords.

## 17. Authentication Architecture
Password (bcrypt compare) → session cookie (`HttpOnly`, `SameSite=Lax`, regenerated at login). Account suspension is re-checked from the database on every authenticated request — never a cached or client-trusted flag.

## 18. Admin Architecture
`requireAdminApi` re-reads `is_admin` from the database on every admin request. Admins see aggregate counts (users, storage, shares, security events) and can suspend/unsuspend accounts, reset sessions, and set quotas — they are never given a path to decrypt or view file contents, because they never hold any encryption key.

## 19. Feature List
See README §7 for the complete, current feature table.

## 20. Feature Removal
Folders, Search, Favorites, Security Incidents, Two-Factor Authentication, Notifications, and AI Tools were removed in full — from the UI, the backend routes, and (where safe) the database. Full detail, including exactly which files were deleted/edited and which two database artifacts were deliberately left in place as inert (and why), is in README §26. In summary:
- 9 backend files deleted outright (`folders.js`, `search.js`, `incidents.js`, `twofa.js`, `twofa-state.js`, `notifications.js`, `notify.js`, `email.js`, `ai.js`), plus a small `quota-warning.js` helper whose only job was sending a now-deleted notification.
- 7 HTML pages and 8 frontend JS files deleted.
- 7 database tables dropped (`user_2fa`, `recovery_codes`, `security_incidents`, `notifications`, `notification_prefs`, `ai_classifications`, `ai_summaries`); 2 columns and 1 table (`files.folder_id`, `files.is_favorite`, `folders`) kept but made permanently inert, because dropping them risked breaking live tables other kept features still write to (confirmed by testing — see §20.1).
- Every remaining file that imported or called into a removed module was edited, not deleted, preserving the features that depend on them (e.g. `fileops.js` kept Tags/Expiration/Integrity and only lost Favorites; `security.js` kept the whole Security Center and only lost its 2FA scoring factor; `admin-audit.html` kept its activity-log charts and only lost its incidents-by-severity widget).

### 20.1 A real bug this process caught
An early attempt dropped the `folders` table outright. Booting the server then failed immediately: SQLite refused to even *compile* the `files` table's own insert statement, because `files.folder_id` still declared `REFERENCES folders(id)`. This is why that one table was kept (empty, with no route ever touching it again) rather than dropped — a concrete example of why "do not blindly delete database tables" matters even when a table looks safe to remove.

## 21. Testing
`docs/TESTING.md` — 28 automated integration tests + 18 crypto tests, all passing, plus a manual migration test that seeded a database with the *original pre-removal* code (a folder, a favorited file, a 2FA setup row) and confirmed this cleaned build boots on it with zero data loss and zero errors.

## 22. Security Testing
`docs/SECURITY_TEST_REPORT.md` — IDOR, CSRF, SQLi, XSS, path traversal, brute force, quota bypass, and a dedicated review of the removal itself for security regressions.

## 23. Screenshots
*(Insert screenshots of: My Vault, Share modal, Recycle Bin, Security Center, Sessions, Admin → Manage Users, Admin → Security Audit, Settings, dark/light theme toggle.)*

## 24. Results
All 28 automated tests pass (28/28) plus 18/18 crypto tests. A database created by the pre-removal code was upgraded in place with no data loss, and every removed feature was confirmed absent from both the UI and the API (clean 404s, zero server errors).

## 25. Limitations
See README §24 (metadata visible to server, memory-bound encryption of huge files, forgotten passwords are unrecoverable, camera QR scanning needs a real device, single-server SQLite). Additionally: accessibility is a partial pass (Escape-closes-modals, aria-labels), not a full WCAG audit; a manual click-through in a real browser is still recommended before a live demo.

## 26. Future Scope
See README §25.

## 27. Conclusion
This project demonstrates both that useful cloud-style file management is possible without trusting the server with file contents, and that a codebase can be safely narrowed — removing seven features cleanly, with full database-safety review and regression testing — without breaking what remains. Both are realistic software-engineering skills beyond just adding features.

## 28. References
Node.js documentation (nodejs.org) · Express.js documentation (expressjs.com) · OWASP Top 10 (owasp.org) · RFC 2898 (PBKDF2) · NIST SP 800-38D (GCM mode) · MDN Web Crypto API documentation.

---

# VIVA PREPARATION

## Original topics (still answerable — architecture, encryption, authentication unchanged)
**1. What is VaultShare?** A website where files are encrypted in your own browser before upload, then organised and shared safely — the server never sees the password or plaintext.
**2. How does encryption work?** The browser derives a key from your password (PBKDF2) and locks the file with AES-256-GCM before uploading only the locked file.
**3. Why AES-256-GCM?** AES-256 is a global standard; GCM also detects tampering — editing the locked file breaks decryption.
**4. What is PBKDF2?** A method that turns a password into a key by repeating a calculation hundreds of thousands of times with random salt, making guessing slow.
**5. What is SHA-256 used for?** A fingerprint of the original file, recomputed after decryption to confirm nothing changed.
**6. Why bcrypt?** Slow, salted hashing for login (and share) passwords, so a stolen database is hard to crack.
**7. How does zero-knowledge work?** The password and key never leave the browser; the server stores only encrypted bytes.
**8. How does secure sharing work?** A random unguessable token, server-enforced expiry/limit/password, and the server only ever sends the still-encrypted file.
**9. How does version control work?** A new upload saves the old version instead of overwriting it; "restore" creates a new version from an old one — history is never lost.
**10. How does the recycle bin work?** Delete just marks a file with a deletion date; a background job permanently removes it after the retention period.
**11. How does suspicious-login detection work?** Transparent rules — new device, new network, repeated failures, rapid logins, many sessions, unusual hour — not AI, and it never claims a physical location.
**12. How are files protected on disk?** Random filenames outside the web-served folder, downloaded only through authenticated, ownership-checked routes.
**13. What are the limitations?** Server still sees filenames/sizes; a lost file password is unrecoverable; very large files are memory-bound in the browser.

## New topics: the removal itself
**14. Why remove features instead of just hiding them in the UI?** Hidden buttons still leave working, reachable APIs behind them — a real removal means the UI, the routes, and (where safe) the database entry are all gone, so there is no leftover attack surface or dead code.
**15. How did you make sure removing one feature didn't break another?** By inspecting dependencies before deleting anything — e.g., `fileops.js` bundled Favorites with Tags, Expiration, and Integrity, so only the favorite-specific routes and functions were removed from that file, not the whole file.
**16. Give a concrete example where a shared file could NOT just be deleted.** `fileops.js`: Favorites was removed, but Tags, File Expiration, and Integrity Verification live in the same file and were not on the removal list, so the file was edited, not deleted.
**17. Why were some database tables dropped but not others?** Tables used *exclusively* by a removed feature, with nothing else referencing them (like `user_2fa`, `security_incidents`, `ai_summaries`), were safe to drop outright. Columns and one table where a *kept* table's schema still pointed at them (`files.folder_id` referencing `folders`) were left in place instead, because removing them risked breaking tables with real user data.
**18. What actually went wrong when you first tried to drop the `folders` table, and how did you find it?** The server failed to boot — SQLite refused to compile any statement touching the `files` table at all, because `files.folder_id` still had `REFERENCES folders(id)` pointing at a table that no longer existed. It was caught immediately by a boot test right after making the change, before it ever reached the test suite.
**19. Is an empty, unused `folders` table in the schema a problem?** No — it is confirmed to have zero routes, zero UI, and zero code paths that ever read or write to it again; it is schema clutter, not a functional or security issue.
**20. How did you verify nothing broke for EXISTING users who had used the removed features?** By seeding a database with the original, pre-removal code — creating a folder, a favorited file, and a 2FA setup row — then booting this cleaned build directly on that database and confirming login, file listing, downloads, and the security score all still worked with no errors.
**21. What happened to the Security Center's score after removing 2FA?** It used to award 25 points for 2FA and 10 for recovery codes. Those 35 points were redistributed across the remaining real factors (password, sessions, failed logins, suspicious activity) so the score still totals 100 and reflects only controls that actually exist now.
**22. Notifications used to send emails for several other features (sharing, password changes). What happened to those when Notifications was removed?** Every `notify()` call site across the codebase (shares.js, account.js, loginmonitor.js) was removed along with the notification system itself — those actions (sharing, password change) still work exactly as before, they just no longer trigger an email or in-app alert, since the whole notification mechanism is gone.
**23. How do you know you found every reference to a removed feature, not just the obvious ones (like the file names)?** By grepping the entire codebase for each feature's keywords (folder, favorite, incident, twofa, 2fa, notif, ai) after the initial deletions, which is exactly how the dangling `notify.js` import in `vault.js` and the folder-referencing JOIN in the Recycle Bin query were both caught and fixed.
**24. Why does the admin audit dashboard still exist if Security Incidents was removed?** They were two different things sharing one page: the audit dashboard's event-by-day and login-success-vs-fail charts come from the general activity log (a kept feature), while only its incidents-by-severity widget depended on the removed Security Incidents table — only that widget was removed.
**25. What's the difference between deleting a file and leaving a column inert?** Deleting is safe when nothing else depends on the structure (a whole table/file only the removed feature used). Leaving something inert is the safer choice when a *kept* feature's table schema still structurally depends on it (a foreign key reference) and rebuilding that live table was judged riskier than leaving one harmless, never-written column behind.
**26. Could you have redesigned the database to cleanly drop the `folders` table too?** Yes — by recreating the `files` and `upload_sessions` tables without the `folder_id` column (SQLite requires a full table rebuild to drop a column with a foreign key tied to it). That was deliberately not attempted on a live table holding real user data in this pass, in favour of the safer, verified option.
**27. What testing specifically targets the removal, rather than just the features that remain?** A dedicated smoke test hit every removed page and API endpoint and asserted a 404 (not a 500), confirming the removal is clean rather than broken; the migration test above additionally proves no removed feature's leftover data causes any crash on the first boot afterward.
**28. If a grader asks you to re-add Two-Factor Authentication next week, what would you need to rebuild?** The `user_2fa`/`recovery_codes` tables (dropped, so recreate them), the TOTP generation/verification logic, the login gate in `auth.js`, the 2FA settings page, and the Security Center score factor — essentially rebuilding feature #1 from this project's earlier scope from scratch, since nothing was left half-working to resume from.
**29. Why keep the `jsqr` and `qrcode` packages if AI and other features were removed?** QR generation and scanning are part of Sharing, not AI — they were never on the removal list and remain fully functional; only `nodemailer` (used solely by the deleted email service) was removed from `package.json`.
**30. What's the single biggest risk you had to manage during this removal, and how did you manage it?** Breaking a *kept* feature while removing a deleted one, because several features shared files/tables. It was managed by inspecting every cross-file dependency before deleting anything, editing shared files surgically instead of deleting them, and proving correctness with a full automated test run plus a real-data migration test after every major change — not just at the very end.
