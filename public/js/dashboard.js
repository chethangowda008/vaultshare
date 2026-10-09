/**
 * VaultShare — public/js/dashboard.js
 * =====================================================================
 * Frontend logic for Feature 2: User Dashboard.
 * Loaded on dashboard.html only.
 * =====================================================================
 */

'use strict';

function escapeHtmlDash(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function timeAgo(isoString) {
  // activity_logs.created_at is stored as UTC "YYYY-MM-DD HH:MM:SS"
  const then = new Date(isoString.replace(' ', 'T') + 'Z').getTime();
  const now = Date.now();
  const diffSec = Math.max(0, Math.round((now - then) / 1000));

  if (diffSec < 60) return 'just now';
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin} minute${diffMin === 1 ? '' : 's'} ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr} hour${diffHr === 1 ? '' : 's'} ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay} day${diffDay === 1 ? '' : 's'} ago`;
}

function renderActivity(rows) {
  const list = document.getElementById('activityList');
  if (!rows || rows.length === 0) {
    list.innerHTML = '<div class="empty-state">No activity yet — try encrypting or uploading a file.</div>';
    return;
  }
  list.innerHTML = rows.map((row) => `
    <div class="activity-row">
      <div class="activity-icon ${row.icon === '⚠' ? 'warn' : 'ok'}">${row.icon}</div>
      <div class="activity-label">${escapeHtmlDash(row.label)}</div>
      <div class="activity-time">${timeAgo(row.created_at)}</div>
    </div>
  `).join('');
}

async function loadDashboard() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      // Session expired or not logged in — server-side page protection
      // should already prevent this, but fail safe anyway.
      window.location.href = '/login.html';
      return;
    }

    document.getElementById('dashUserName').textContent = data.user.name;
    document.getElementById('statMyFiles').textContent = data.stats.myFiles;
    document.getElementById('statSharedFiles').textContent = data.stats.sharedFiles;
    document.getElementById('statDownloads').textContent = data.stats.downloads;
    document.getElementById('statActiveShares').textContent = data.stats.activeShares;

    renderActivity(data.activity);
  } catch (err) {
    document.getElementById('activityList').innerHTML =
      '<div class="empty-state">Could not reach the server.</div>';
  }
}

loadDashboard();

// ── SIDEBAR LOGOUT ───────────────────────────────────────────────────────
const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}

// ── "COMING SOON" SIDEBAR ITEMS ──────────────────────────────────────────
document.querySelectorAll('.side-link.disabled').forEach((el) => {
  el.addEventListener('click', () => {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = 'This module is coming in a future step.';
    toast.className = 'toast show';
    setTimeout(() => toast.classList.remove('show'), 2400);
  });
});
