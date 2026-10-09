/**
 * VaultShare 2.0 — public/js/sessions.js
 * Loaded on sessions.html only. Depends on ui.js (toast).
 */

'use strict';

function escapeHtmlSess(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateSess(isoString) {
  if (!isoString) return 'Unknown';
  return new Date(isoString).toLocaleString();
}

async function loadSessions() {
  const list = document.getElementById('session-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch('/api/sessions');
    const data = await res.json();
    if (!res.ok || !data.ok) {
      list.innerHTML = '<div class="empty-state">Could not load sessions.</div>';
      return;
    }

    list.innerHTML = data.sessions.map((s) => `
      <div class="session-row">
        <div class="s-icon">${s.os === 'Android' || s.os === 'iOS' ? '📱' : '💻'}</div>
        <div class="s-meta">
          <div>${escapeHtmlSess(s.browser)} on ${escapeHtmlSess(s.os)} ${s.isCurrent ? '<span class="current-badge">This device</span>' : ''}</div>
          <div class="s-sub">IP ${escapeHtmlSess(s.ip || 'unknown')} · Logged in ${fmtDateSess(s.loginTime)}</div>
        </div>
        ${s.isCurrent ? '' : `<button class="copy-btn" onclick="endSession('${s.sid}')">Log Out</button>`}
      </div>
    `).join('') || '<div class="empty-state">No active sessions.</div>';
  } catch (err) {
    list.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

async function endSession(sid) {
  if (!confirm('End this session? That device will be logged out immediately.')) return;
  try {
    const res = await fetch(`/api/sessions/${sid}/logout`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not end session.', 'error');
      return;
    }
    toast('Session ended.', 'success');
    loadSessions();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

async function logoutOthers() {
  if (!confirm('Log out every OTHER session? This device will stay logged in.')) return;
  try {
    const res = await fetch('/api/sessions/logout-others', { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not end other sessions.', 'error');
      return;
    }
    toast(`Ended ${data.count} other session(s).`, 'success');
    loadSessions();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

loadSessions();
