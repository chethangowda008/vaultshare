/** VaultShare 3.0 — public/js/admin-users.js (admin-users.html). Depends on ui.js. */
'use strict';
function escAU(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function fmtDateAU(iso) { return iso ? new Date(iso.replace(' ', 'T') + 'Z').toLocaleDateString() : '—'; }

let _defaultQuota = 0;

async function loadUsers() {
  const tbody = document.querySelector('#users-table tbody');
  try {
    const res = await fetch('/api/admin/users');
    if (res.status === 403) { document.querySelector('main').innerHTML = '<div class="empty-state">Admin access required.</div>'; return; }
    const data = await res.json();
    _defaultQuota = data.defaultQuotaBytes;
    document.getElementById('default-quota-mb').value = Math.round(_defaultQuota / (1024 * 1024));

    document.querySelector('#users-table').innerHTML = `
      <thead><tr><th>User</th><th>Status</th><th>Joined</th><th>Last login</th><th>Files</th><th>Storage</th><th>Shares</th><th>Actions</th></tr></thead>
      <tbody>${data.users.map(rowHtml).join('')}</tbody>`;
  } catch { tbody.innerHTML = '<tr><td>Could not reach the server.</td></tr>'; }
}

function rowHtml(u) {
  const limit = u.storage_quota_bytes || _defaultQuota;
  const pct = limit ? Math.min(100, Math.round((u.storage_bytes / limit) * 100)) : 0;
  return `<tr>
    <td><b>${escAU(u.name)}</b><br><span style="color:var(--muted);">${escAU(u.email)}</span>${u.is_admin ? ' <span class="pill">admin</span>' : ''}</td>
    <td><span class="pill ${u.status}">${u.status}</span></td>
    <td>${fmtDateAU(u.created_at)}</td>
    <td>${fmtDateAU(u.last_login)}</td>
    <td>${u.file_count}</td>
    <td><span class="quota-bar"><span class="quota-fill" style="width:${pct}%"></span></span>${fmtSize(u.storage_bytes)}${u.storage_quota_bytes ? ` / ${fmtSize(u.storage_quota_bytes)}` : ''}</td>
    <td>${u.share_count}</td>
    <td>
      <button class="copy-btn" onclick="toggleStatus(${u.id}, '${u.status}')">${u.status === 'active' ? 'Suspend' : 'Unsuspend'}</button>
      <button class="copy-btn" onclick="resetSessions(${u.id})">Reset sessions</button>
      <button class="copy-btn" onclick="setQuota(${u.id})">Set quota</button>
    </td>
  </tr>`;
}

async function toggleStatus(id, current) {
  const next = current === 'active' ? 'suspended' : 'active';
  if (next === 'suspended' && !confirm('Suspend this user? They will be logged out immediately.')) return;
  const res = await fetch(`/api/admin/users/${id}/status`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: next }) });
  const data = await res.json().catch(() => ({}));
  toast(res.ok ? 'Updated.' : ((data.errors && data.errors[0]) || 'Could not update.'), res.ok ? 'success' : 'error');
  loadUsers();
}
async function resetSessions(id) {
  if (!confirm('Log this user out of every device?')) return;
  const res = await fetch(`/api/admin/users/${id}/reset-sessions`, { method: 'POST' });
  const data = await res.json().catch(() => ({}));
  toast(res.ok ? `Ended ${data.count} session(s).` : 'Could not reset sessions.', res.ok ? 'success' : 'error');
}
async function setQuota(id) {
  const mb = prompt('New quota in MB (leave blank to use the server default):');
  if (mb === null) return;
  const quotaBytes = mb.trim() === '' ? null : parseInt(mb, 10) * 1024 * 1024;
  const res = await fetch(`/api/admin/users/${id}/quota`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ quotaBytes }) });
  toast(res.ok ? 'Quota updated.' : 'Could not update quota.', res.ok ? 'success' : 'error');
  loadUsers();
}
async function saveDefaultQuota() {
  const mb = parseInt(document.getElementById('default-quota-mb').value, 10);
  if (!Number.isInteger(mb) || mb < 1) { toast('Enter a valid number of MB.', 'error'); return; }
  const res = await fetch('/api/admin/settings/default-quota', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ quotaBytes: mb * 1024 * 1024 }) });
  toast(res.ok ? 'Default quota saved.' : 'Could not save.', res.ok ? 'success' : 'error');
  loadUsers();
}
loadUsers();

// ── Admin session guard and logout (admin-users.html) ────────────────────
(async function adminUsersInit() {
  const res  = await fetch('/api/admin/me').catch(() => null);
  const data = res ? await res.json().catch(() => null) : null;
  if (!data || !data.isAdmin) {
    window.location.href = '/admin-login.html';
    return;
  }
  const slot = document.getElementById('user-bar-slot');
  if (slot) {
    slot.innerHTML = `<div class="user-bar"><span class="user-name">👑 Admin</span><button class="logout-link" id="adminLogoutBtn2">Logout</button></div>`;
    document.getElementById('adminLogoutBtn2').addEventListener('click', async () => {
      await fetch('/api/admin/logout', { method: 'POST' });
      window.location.href = '/admin-login.html';
    });
  }
})();
const sidebarLogoutBtnAU = document.getElementById('sidebarLogout');
if (sidebarLogoutBtnAU) {
  sidebarLogoutBtnAU.addEventListener('click', async () => {
    await fetch('/api/admin/logout', { method: 'POST' });
    window.location.href = '/admin-login.html';
  });
}
