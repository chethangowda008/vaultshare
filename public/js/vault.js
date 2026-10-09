/**
 * VaultShare — public/js/vault.js
 * =====================================================================
 * Frontend logic for Feature 4: Personal Vault.
 * Loaded on index.html only. Depends on: ui.js (toast, fmtSize)
 * =====================================================================
 */

'use strict';

let _vaultFilesCache = []; // last list fetched by loadVaultFiles(), used by the Share modal
let _shareContext = null;  // { fileId } for the currently open Share modal

function escapeHtmlVault(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateVault(isoString) {
  // SQLite stores "YYYY-MM-DD HH:MM:SS" in UTC
  const d = new Date(isoString.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

/** Fetches the logged-in user's files and renders the vault list. */
async function loadVaultFiles() {
  const container = document.getElementById('vault-list');
  container.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch('/api/vault/files');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      container.innerHTML = '<div class="empty-state">Could not load your files.</div>';
      return;
    }

    if (data.files.length === 0) {
      container.innerHTML = '<div class="empty-state">Your vault is empty. Encrypt a file, then click "Save to Vault".</div>';
      return;
    }

    _vaultFilesCache = data.files;

    container.innerHTML = data.files.map((f) => `
      <div class="vault-row" data-file-id="${f.id}">
        <label class="vault-select" title="Select for multi-file share"><input type="checkbox" class="vault-check" value="${f.id}" aria-label="Select ${escapeHtmlVault(f.original_filename)}"/></label>
        <div class="vault-file-icon">🔒</div>
        <div class="vault-meta">
          <div class="vault-name">${escapeHtmlVault(f.original_filename)}</div>
          <div class="vault-sub">
            <span class="vault-algo-badge">${escapeHtmlVault(f.algorithm)}</span>
            <span>${fmtSize(f.file_size)}</span>
            <span>${fmtDateVault(f.created_at)}</span>
            ${verificationBadge(f.verification_status)}
            ${f.expires_at ? `<span title="Auto-deletes on this date">⏳ ${f.expires_at.slice(0, 10)}</span>` : ''}
          </div>
          <div class="vault-tags">${(f.tags || []).map((t) => `<span class="tag-chip">${escapeHtmlVault(t)} <a onclick="removeTagFromFile(${f.id}, '${escapeHtmlVault(t)}')">✕</a></span>`).join('')}
            <a class="tag-add-link" onclick="addTagToFile(${f.id})">+ tag</a></div>
          <div class="vault-hash" title="SHA-256 of original file">${escapeHtmlVault(f.file_hash)}</div>
        </div>
        <div class="vault-actions">
          <button onclick="downloadVaultFile(${f.id})">⬇ Download</button>
          <button onclick="openPreviewModal(${f.id}, '${escapeHtmlVault(f.original_filename).replace(/'/g, "\\'")}')">👁 Preview</button>
          <button onclick="openShareModal(${f.id})">🔗 Share</button>
          <button onclick="openVersionModal(${f.id}, '${escapeHtmlVault(f.original_filename).replace(/'/g, "\\'")}')">📜 Versions${f.version > 1 ? ` (v${f.version})` : ''}</button>
          <button onclick="quickIntegrityCheck(${f.id})">✅ Verify</button>
          <button onclick="setExpiration(${f.id})">⏳ Expire…</button>
          <button class="danger" onclick="deleteVaultFile(${f.id})">🗑 Delete</button>
        </div>
      </div>
    `).join('');

    loadQuotaMeter();
  } catch (err) {
    container.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

/** Downloads a stored file by id — the server checks ownership itself. */
function downloadVaultFile(fileId) {
  window.location.href = `/api/vault/download/${fileId}`;
}

/** Deletes a stored file after confirmation. */
async function deleteVaultFile(fileId) {
  if (!confirm('Delete this file from your vault? This cannot be undone.')) return;

  try {
    const res = await fetch(`/api/vault/files/${fileId}`, { method: 'DELETE' });
    const data = await res.json();

    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not delete file.', 'error');
      return;
    }

    toast('File deleted.', 'success');
    loadVaultFiles();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

// ── SHARE MODAL (Feature 5) ──────────────────────────────────────────────

function openShareModalMulti() {
  const ids = [...document.querySelectorAll('.vault-check:checked')].map((c) => parseInt(c.value, 10));
  if (ids.length === 0) { toast('Tick at least one file first.', 'error'); return; }
  openShareModal(ids[0]);
  _shareContext = { fileId: ids[0], fileIds: ids };
  document.getElementById('share-modal-filename').textContent = `${ids.length} files selected`;
}

function openShareModal(fileId) {
  const file = _vaultFilesCache.find((f) => f.id === fileId);
  _shareContext = { fileId };

  document.getElementById('share-modal-filename').textContent = file ? file.original_filename : `File #${fileId}`;
  document.getElementById('share-recipient').value = '';
  document.getElementById('share-expires').value = '24h';
  document.getElementById('share-limit').value = '5';
  document.getElementById('share-password').value = '';
  document.getElementById('share-form').style.display = '';
  document.getElementById('share-result').style.display = 'none';
  document.getElementById('share-qr-img').style.display = 'none';
  document.getElementById('share-qr-caption').style.display = 'none';
  document.getElementById('share-qr-download').style.display = 'none';
  document.getElementById('share-modal-overlay').classList.add('show');
  applyShareDefaults();
}

/** Pre-select the user's saved sharing defaults (Settings → Sharing defaults). */
async function applyShareDefaults() {
  try {
    const r = await fetch('/api/settings'); const d = await r.json();
    if (!d.ok) return;
    const exp = document.getElementById('share-expires'), lim = document.getElementById('share-limit');
    if ([...exp.options].some((o) => o.value === d.settings.defaultShareExpiry)) exp.value = d.settings.defaultShareExpiry;
    if ([...lim.options].some((o) => o.value === d.settings.defaultShareLimit)) lim.value = d.settings.defaultShareLimit;
  } catch { /* defaults are optional */ }
}

function closeShareModal() {
  document.getElementById('share-modal-overlay').classList.remove('show');
  _shareContext = null;
}

async function submitShare() {
  if (!_shareContext) return;

  const btn = document.getElementById('share-generate-btn');
  btn.disabled = true;
  btn.textContent = 'Generating…';

  try {
    const res = await fetch('/api/shares', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...(_shareContext.fileIds ? { fileIds: _shareContext.fileIds } : { fileId: _shareContext.fileId }),
        recipientEmail: document.getElementById('share-recipient').value.trim(),
        expiresIn: document.getElementById('share-expires').value,
        customHours: document.getElementById('share-custom-hours').value,
        downloadLimit: document.getElementById('share-limit').value,
        sharePassword: document.getElementById('share-password').value,
      }),
    });
    const data = await res.json();

    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not create share.', 'error');
      return;
    }

    document.getElementById('share-form').style.display = 'none';
    document.getElementById('share-result').style.display = '';
    document.getElementById('share-result-link').value = data.share.url;
    _shareContext.shareId = data.share.id;

    const note = data.share.recipientEmail
      ? (data.share.recipientHasAccount
          ? `${escapeHtmlVault(data.share.recipientEmail)} will see this in "Shared With Me" when they log in.`
          : `${escapeHtmlVault(data.share.recipientEmail)} doesn't have a VaultShare account yet — send them this link directly.`)
      : 'Anyone with this link can access the file until it expires, is revoked, or hits its download limit.';
    document.getElementById('share-result-note').textContent = note;

    toast('Secure share created!', 'success');
    loadVaultFiles(); // vault list doesn't change, but keeps things in sync
  } catch (err) {
    toast('Could not reach the server.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Secure Share';
  }
}

async function copyShareLink() {
  const input = document.getElementById('share-result-link');
  await navigator.clipboard.writeText(input.value);
  toast('Link copied to clipboard!', 'success');
}

// ── QR CODE (Feature 11) ──────────────────────────────────────────────────
function generateShareQr() {
  if (!_shareContext || !_shareContext.shareId) return;
  const src = `/api/shares/${_shareContext.shareId}/qr.png?t=${Date.now()}`;
  const img = document.getElementById('share-qr-img');
  const caption = document.getElementById('share-qr-caption');
  const dl = document.getElementById('share-qr-download');

  img.src = src;
  img.style.display = '';
  caption.style.display = '';
  dl.href = src;
  dl.style.display = '';
}

document.addEventListener('change', (e) => {
  if (e.target && e.target.id === 'share-expires') document.getElementById('share-custom-hours').style.display = e.target.value === 'custom' ? 'block' : 'none';
});

// ══════════════════════════════════════════════════════════════════════
// Additions: tags, expiration, integrity, quota.
// ══════════════════════════════════════════════════════════════════════

function verificationBadge(status) {
  if (status === 'ok') return '<span title="Last full verification passed" style="color:var(--accent3);">✓ verified</span>';
  if (status === 'failed') return '<span title="Last verification FAILED" style="color:var(--danger);">⚠ verify failed</span>';
  return '<span title="Never verified" style="color:var(--muted);">— unverified</span>';
}

async function addTagToFile(fileId) {
  const tag = prompt('Add a tag (letters, numbers, spaces, - or _, max 30 chars):');
  if (!tag || !tag.trim()) return;
  const res = await fetch(`/api/vault/files/${fileId}/tags`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tag: tag.trim() }) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { toast((data.errors && data.errors[0]) || 'Could not add tag.', 'error'); return; }
  loadVaultFiles();
}
async function removeTagFromFile(fileId, tag) {
  await fetch(`/api/vault/files/${fileId}/tags/${encodeURIComponent(tag)}`, { method: 'DELETE' });
  loadVaultFiles();
}

async function quickIntegrityCheck(fileId) {
  try {
    const res = await fetch(`/api/integrity/${fileId}/quick-check`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) { toast('Could not run the check.', 'error'); return; }
    if (data.status === 'ok') {
      toast('Quick check passed: file is intact on the server.', 'success');
    } else {
      toast(`Quick check FAILED: ${data.problems.join(' ')}`, 'error');
    }
  } catch { toast('Could not reach the server.', 'error'); }
}

async function setExpiration(fileId) {
  const choice = prompt('Auto-delete this file after: type "1d", "7d", "30d", a date (YYYY-MM-DD), or "none" to clear.');
  if (choice === null) return;
  const trimmed = choice.trim().toLowerCase();
  let body;
  if (trimmed === 'none' || trimmed === '') body = { preset: 'none' };
  else if (['1d', '7d', '30d'].includes(trimmed)) body = { preset: trimmed };
  else body = { preset: 'custom', customDate: choice.trim() };

  const res = await fetch(`/api/vault/files/${fileId}/expiration`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { toast((data.errors && data.errors[0]) || 'Could not set expiration.', 'error'); return; }
  toast(data.expiresAt ? `File will auto-delete on ${data.expiresAt.slice(0, 10)}.` : 'Expiration cleared.', 'success');
  loadVaultFiles();
}

async function loadQuotaMeter() {
  const el = document.getElementById('quota-meter');
  if (!el) return;
  try {
    const res = await fetch('/api/vault/quota');
    const data = await res.json();
    if (!data.ok) return;
    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;font-size:.72rem;color:var(--muted);margin-bottom:4px;">
        <span>Storage: ${fmtSize(data.usedBytes)} of ${fmtSize(data.limitBytes)} used</span><span>${data.percentUsed}%</span>
      </div>
      <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden;">
        <div style="height:100%;width:${data.percentUsed}%;background:${data.percentUsed >= 90 ? 'var(--danger)' : 'var(--accent)'};"></div>
      </div>`;
  } catch { /* quota meter is a nice-to-have; fail silently */ }
}
