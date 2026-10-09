/**
 * VaultShare — public/js/admin.js
 * Loaded on admin.html only.
 *
 * Uses /api/admin/me to verify admin session and show admin identity.
 * Uses /api/admin/logout to destroy the admin session on logout.
 */

'use strict';

function escAdmin(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateAdmin(isoLike) {
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

// ── Verify admin session and render admin identity bar ───────────────────
(async function initAdminPage() {
  try {
    const res  = await fetch('/api/admin/me');
    const data = await res.json();

    if (!data.ok || !data.isAdmin) {
      // Session expired or not admin — redirect to admin login
      window.location.href = '/admin-login.html';
      return;
    }

    // Show admin identity in the user-bar slot
    const slot = document.getElementById('user-bar-slot');
    if (slot) {
      slot.innerHTML = `
        <div class="user-bar">
          <span class="user-name">👑 Admin</span>
          <button class="logout-link" id="adminLogoutBtn">Logout</button>
        </div>
      `;
      document.getElementById('adminLogoutBtn').addEventListener('click', async () => {
        await fetch('/api/admin/logout', { method: 'POST' });
        window.location.href = '/admin-login.html';
      });
    }

    // Load stats now that we're confirmed admin
    loadAdminStats();
  } catch (err) {
    window.location.href = '/admin-login.html';
  }
})();

async function loadAdminStats() {
  try {
    const res = await fetch('/api/admin/stats');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      document.getElementById('admin-stats').innerHTML =
        '<div class="empty-state">Could not load admin stats.</div>';
      return;
    }

    document.getElementById('admin-stats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Total Users</div><div class="stat-value">${data.totalUsers}</div></div>
      <div class="stat-card"><div class="stat-label">Total Files</div><div class="stat-value">${data.totalFiles}</div></div>
      <div class="stat-card"><div class="stat-label">Total Shares</div><div class="stat-value">${data.totalShares}</div></div>
      <div class="stat-card"><div class="stat-label">Total Downloads</div><div class="stat-value">${data.totalDownloads}</div></div>
      <div class="stat-card"><div class="stat-label">Active Users (24h)</div><div class="stat-value">${data.activeUsers24h}</div></div>
      <div class="stat-card"><div class="stat-label">Storage Used</div><div class="stat-value">${fmtSize(data.storageBytes)}</div></div>
      <div class="stat-card"><div class="stat-label">In Recycle Bins</div><div class="stat-value">${data.filesInRecycleBin}</div></div>
      <div class="stat-card"><div class="stat-label">Security Events</div><div class="stat-value">${data.securityEvents}</div></div>
      <div class="stat-card"><div class="stat-label">Failed Logins (24h / all)</div><div class="stat-value">${data.failedLogins24h} / ${data.failedLoginsTotal}</div></div>
      <div class="stat-card"><div class="stat-label">Suspicious Logins (30d)</div><div class="stat-value">${data.suspiciousLogins30d}</div></div>
    `;

    const h = data.health;
    const up = h.uptimeSeconds >= 3600 ? Math.floor(h.uptimeSeconds / 3600) + ' h' : Math.floor(h.uptimeSeconds / 60) + ' min';
    const hb = document.getElementById('admin-health');
    if (hb) hb.innerHTML = `
      <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value">${escAdmin(h.status)}</div></div>
      <div class="stat-card"><div class="stat-label">Uptime</div><div class="stat-value">${up}</div></div>
      <div class="stat-card"><div class="stat-label">Database Size</div><div class="stat-value">${fmtSize(h.databaseBytes)}</div></div>
      <div class="stat-card"><div class="stat-label">Environment</div><div class="stat-value">${escAdmin(h.environment)}</div></div>
    `;

    const s = data.shares;
    document.getElementById('admin-share-status').innerHTML = `
      <div class="stat-card"><div class="stat-label">Active</div><div class="stat-value">${s.active}</div></div>
      <div class="stat-card"><div class="stat-label">Expired</div><div class="stat-value">${s.expired}</div></div>
      <div class="stat-card"><div class="stat-label">Revoked</div><div class="stat-value">${s.revoked}</div></div>
      <div class="stat-card"><div class="stat-label">Completed</div><div class="stat-value">${s.completed}</div></div>
    `;

    const events = document.getElementById('admin-events');
    if (data.recentEvents.length === 0) {
      events.innerHTML = '<div class="empty-state">No security events yet.</div>';
    } else {
      events.innerHTML = data.recentEvents.map((e) => `
        <div class="activity-row">
          <div class="activity-icon ${e.icon === '⚠' ? 'warn' : 'ok'}">${e.icon}</div>
          <div class="activity-label">${escAdmin(e.label)} <span style="color:var(--muted)">— ${escAdmin(e.user)}</span></div>
          <div class="activity-time">${fmtDateAdmin(e.created_at)}</div>
        </div>
      `).join('');
    }
  } catch (err) {
    document.getElementById('admin-stats').innerHTML =
      '<div class="empty-state">Could not reach the server.</div>';
  }
}

// Sidebar logout (uses admin logout endpoint)
const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/admin/logout', { method: 'POST' });
    window.location.href = '/admin-login.html';
  });
}
