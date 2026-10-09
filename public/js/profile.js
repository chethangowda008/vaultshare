/**
 * VaultShare — public/js/profile.js
 * Loaded on profile.html only. Reuses the existing /api/me endpoint.
 */

'use strict';

function escProfile(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

fetch('/api/me')
  .then((res) => res.json())
  .then((data) => {
    if (!data.ok || !data.user) {
      window.location.href = '/login.html';
      return;
    }
    const u = data.user;
    document.getElementById('profileFields').innerHTML = `
      <div class="activity-row"><div class="activity-label">Name</div><div class="activity-time">${escProfile(u.name)}</div></div>
      <div class="activity-row"><div class="activity-label">Email</div><div class="activity-time">${escProfile(u.email)}</div></div>
      <div class="activity-row"><div class="activity-label">Account created</div><div class="activity-time">${escProfile(u.created_at || '—')}</div></div>
      <div class="activity-row"><div class="activity-label">Last login</div><div class="activity-time">${escProfile(u.last_login || '—')}</div></div>
    `;
  })
  .catch(() => {
    document.getElementById('profileFields').innerHTML =
      '<div class="empty-state">Could not reach the server.</div>';
  });

const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}


// ── Change password (Feature: account security) ──
async function changePassword() {
  const currentPassword = document.getElementById('cp-current').value;
  const newPassword = document.getElementById('cp-new').value;
  try {
    const res = await fetch('/api/account/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword, newPassword }) });
    const data = await res.json();
    if (!res.ok || !data.ok) { toast((data.errors && data.errors[0]) || 'Could not change password.', 'error'); return; }
    document.getElementById('cp-current').value = ''; document.getElementById('cp-new').value = '';
    toast('Password updated. Other sessions were signed out.', 'success');
  } catch { toast('Could not reach the server.', 'error'); }
}
