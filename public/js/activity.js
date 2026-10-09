/**
 * VaultShare — public/js/activity.js
 * Loaded on activity.html only.
 */

'use strict';

let _actToastTimer = null;
function toast(message, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(_actToastTimer);
  _actToastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

function escAct(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateAct(isoLike) {
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

let _currentFilter = 'All';

async function loadActivity(filter) {
  const list = document.getElementById('activity-full-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch(`/api/activity?filter=${encodeURIComponent(filter)}`);
    const data = await res.json();

    if (!res.ok || !data.ok) {
      list.innerHTML = '<div class="empty-state">Could not load activity.</div>';
      return;
    }

    if (data.activity.length === 0) {
      list.innerHTML = '<div class="empty-state">No activity in this category yet.</div>';
      return;
    }

    list.innerHTML = data.activity.map((row) => `
      <div class="activity-row">
        <div class="activity-icon ${row.icon === '⚠' ? 'warn' : 'ok'}">${row.icon}</div>
        <div class="activity-label">${escAct(row.label)}</div>
        <div class="activity-time">${fmtDateAct(row.created_at)}</div>
      </div>
    `).join('');
  } catch (err) {
    list.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

document.getElementById('filter-row').addEventListener('click', (e) => {
  const btn = e.target.closest('.filter-chip');
  if (!btn) return;
  document.querySelectorAll('.filter-chip').forEach((c) => c.classList.remove('active'));
  btn.classList.add('active');
  _currentFilter = btn.dataset.filter;
  loadActivity(_currentFilter);
});

loadActivity(_currentFilter);

const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}
