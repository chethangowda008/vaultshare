# VaultShare — Testing Checklist (Step 14)

Run through this before your demo/viva. Two people work best: one as
"User A" (owner), one as "User B" (recipient) — or just use two
browser profiles / an incognito window for User B.

## 1. Authentication
- [ ] Register a new account → redirected to Dashboard
- [ ] Register again with the **same email** → clear error, no duplicate created
- [ ] Register with a weak/mismatched password → validation error shown
- [ ] Log out → protected pages (`/`, `/index.html`, `/dashboard.html`) redirect to `/login.html`
- [ ] Log in with correct credentials → success
- [ ] Log in with wrong password → generic "invalid credentials" error (not "wrong password" — don't leak which field was wrong)
- [ ] Log in incorrectly **11 times** in 15 minutes → rate limiter blocks further attempts
- [ ] Check `data/vaultshare.db` → `password_hash` is a bcrypt hash, never plaintext

## 2. Authorization
- [ ] User B cannot see User A's files via `GET /api/vault/files`
- [ ] User B cannot download User A's file by guessing a file id (`/api/vault/download/<A's id>`) → 404
- [ ] User B cannot delete User A's file by id → 404
- [ ] User B cannot revoke a share they don't own → 404

## 3. Encryption / Decryption (unchanged core logic)
- [ ] Encrypt a file with AES-256-GCM, a password → download succeeds
- [ ] Decrypt it with the correct password → original file recovered, hash matches
- [ ] Decrypt with the **wrong** password → clear failure, no data corruption
- [ ] Repeat for AES-256-CBC and AES-256-CTR
- [ ] Verify tab: confirm hash-verification flow still works standalone

## 4. Personal Vault
- [ ] Encrypt a file → click "Save to Vault" → appears in My Vault list
- [ ] File size/algorithm/hash/date shown match what was encrypted
- [ ] Download from Vault → resulting `.vaultenc` decrypts correctly on the Decrypt tab
- [ ] Delete from Vault → disappears from list and from disk (`vault-storage/<userId>/`)
- [ ] Try uploading a random non-`.vaultenc` file directly to `/api/vault/upload` → rejected (magic-byte check)

## 5. Secure Sharing
- [ ] Share a file with no recipient email, 24h expiry, 5 downloads → link generated
- [ ] Open the link in a private/incognito window (logged out) → file info shown, no login required
- [ ] Download 5 times → 6th attempt shows "Download limit reached"
- [ ] Create another share with a **very short test window** (temporarily set `expiresIn: '1h'` and manually edit `expires_at` in the DB to the past, or just wait) → link shows "expired"
- [ ] Revoke an active share from **My Shares** → link immediately shows "revoked"
- [ ] Share to a recipient's registered email → that user sees it under **Shared With Me** after logging in

## 6. QR Code Sharing
- [ ] Generate a share → click "Generate QR" → image appears
- [ ] Scan the QR with a phone → opens the same `/share/<token>` link
- [ ] Confirm the QR encodes **only the URL** (open it in any QR decoder — no password, no extra data)
- [ ] Revoke the share → the QR (same URL) now shows "revoked" when scanned

## 7. Dashboard / Activity / Security pages
- [ ] Dashboard stat cards match reality (upload 2 files → "My Files" shows 2, not a hard-coded number)
- [ ] Activity page: filter by "Uploads", "Shares", "Login", etc. — each shows only matching events
- [ ] Security page: share counts (active/expired/revoked) match what's actually in **My Shares**
- [ ] Security page: "Security Events" count increases after each new login/upload/share

## 8. General security hygiene
- [ ] Try a path-traversal-style filename on upload (e.g. rename a file to `../../evil.vaultenc` before selecting it) → server stores it under a random UUID regardless, original path never touches the filesystem
- [ ] Check server console during a forced error (e.g. stop the DB mid-request) → error shown to the client is generic, no stack trace or SQL leaked
- [ ] Confirm `helmet` security headers are present (`Content-Security-Policy`, `X-Frame-Options`, etc.) via browser dev tools → Network tab → Headers
