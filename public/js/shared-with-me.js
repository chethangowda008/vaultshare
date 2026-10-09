/**
 * VaultShare — public/js/shared-with-me.js
 * Loaded on shared-with-me.html only.
 */

'use strict';

let _swmToastTimer = null;
function toast(message, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(_swmToastTimer);
  _swmToastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

function escSWM(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateSWM(isoLike) {
  if (!isoLike) return 'Never';
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

async function loadReceivedShares() {
  const container = document.getElementById('received-shares-list');
  container.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch('/api/shares/received');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      container.innerHTML = '<div class="empty-state">Could not load your received shares.</div>';
      return;
    }

    if (data.shares.length === 0) {
      container.innerHTML = '<div class="empty-state">Nobody has shared a file with your account yet.</div>';
      return;
    }

    container.innerHTML = data.shares.map((s) => `
      <div class="share-table-row">
        <div class="share-file">
          <div class="name">${escSWM(s.original_filename)}</div>
          <div class="sub">
            Shared by: ${escSWM(s.owner_name)}
            · Expires: ${fmtDateSWM(s.expires_at)}
            · Downloads remaining: ${s.download_limit === null ? 'Unlimited' : Math.max(0, s.download_limit - s.download_count)}
          </div>
        </div>
        <span class="status-badge ${s.status}">${s.status}</span>
        <div class="share-table-actions">
          <button ${s.status !== 'active' ? 'disabled' : ''} onclick="window.location.href=${JSON.stringify(s.url)}">⬇ Access File</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

loadReceivedShares();

const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}
