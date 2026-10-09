/**
 * VaultShare — public/js/my-shares.js
 * Loaded on my-shares.html only.
 */

'use strict';

let _msToastTimer = null;
function toast(message, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(_msToastTimer);
  _msToastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

function escMS(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateMS(isoLike) {
  if (!isoLike) return 'Never';
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

async function loadMyShares() {
  const container = document.getElementById('my-shares-list');
  container.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch('/api/shares/mine');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      container.innerHTML = '<div class="empty-state">Could not load your shares.</div>';
      return;
    }

    if (data.shares.length === 0) {
      container.innerHTML = '<div class="empty-state">You haven\'t shared any files yet. Go to My Vault and click "Share" on a file.</div>';
      return;
    }

    container.innerHTML = data.shares.map((s) => `
      <div class="share-table-row">
        <div class="share-file">
          <div class="name">${escMS(s.original_filename)}</div>
          <div class="sub">
            ${s.recipient_email ? `Shared with: ${escMS(s.recipient_email)}` : 'Anyone with the link'}
            · Expires: ${fmtDateMS(s.expires_at)}
            · Downloads: ${s.download_count}${s.download_limit === null ? '' : ' / ' + s.download_limit}
            ${s.password_protected ? ' · 🔒 Password protected' : ''}
          </div>
        </div>
        <span class="status-badge ${s.status}">${s.status}</span>
        <div class="share-table-actions">
          <button onclick="copyMSLink(${JSON.stringify(s.url)})">📋 Copy Link</button>
          <button ${s.status !== 'active' ? 'disabled' : ''} onclick="showMSQr(${s.id})">🔳 QR</button>
          <button class="danger" ${s.status !== 'active' ? 'disabled' : ''} onclick="revokeShare(${s.id})">Revoke</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

async function copyMSLink(url) {
  await navigator.clipboard.writeText(url);
  toast('Link copied to clipboard!', 'success');
}

function showMSQr(shareId) {
  window.open(`/api/shares/${shareId}/qr.png?t=${Date.now()}`, '_blank');
}

async function revokeShare(shareId) {
  if (!confirm('Revoke this share? The link will stop working immediately.')) return;

  try {
    const res = await fetch(`/api/shares/${shareId}/revoke`, { method: 'POST' });
    const data = await res.json();

    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not revoke share.', 'error');
      return;
    }

    toast('Share revoked.', 'success');
    loadMyShares();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

loadMyShares();

const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}
