/**
 * VaultShare — public/js/security.js
 * Loaded on security.html only.
 */

'use strict';

function escSec(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateSec(isoLike) {
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

async function loadSecurity() {
  try {
    const res = await fetch('/api/security');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      document.getElementById('sec-capabilities').innerHTML = '<div class="empty-state">Could not load security overview.</div>';
      return;
    }

    document.getElementById('sec-capabilities').innerHTML = data.capabilities.map((c) => `
      <div class="sec-item">
        <div>
          <div class="name">${escSec(c.name)}</div>
          <div class="detail">${escSec(c.detail)}</div>
        </div>
        <div class="sec-check">${c.enabled ? '✓' : '✕'}</div>
      </div>
    `).join('');

    const s = data.shares;
    document.getElementById('sec-counts').innerHTML = `
      <div class="stat-card"><div class="stat-label">Active Shares</div><div class="stat-value">${s.active}</div></div>
      <div class="stat-card"><div class="stat-label">Expired Shares</div><div class="stat-value">${s.expired}</div></div>
      <div class="stat-card"><div class="stat-label">Revoked Shares</div><div class="stat-value">${s.revoked}</div></div>
      <div class="stat-card"><div class="stat-label">Security Events</div><div class="stat-value">${data.securityEvents}</div></div>
      <div class="stat-card"><div class="stat-label">Active Sessions</div><div class="stat-value">${data.activeSessionCount}</div></div>
      <div class="stat-card"><div class="stat-label">Failed Logins</div><div class="stat-value">${data.failedLogins}</div></div>
    `;

    const RS = { new_device: 'new device', new_network: 'new network', failed_attempts: 'repeated failed attempts', rapid_logins: 'rapid repeated logins', many_sessions: 'many open sessions', unusual_time: 'unusual login time' };
    if (data.suspiciousLogins && data.suspiciousLogins.length) {
      const s = data.suspiciousLogins[0];
      document.getElementById('sec-alert-text').textContent =
        `A recent login was flagged (${(s.reasons || '').split(',').filter(Boolean).map((r) => RS[r] || r).join(', ')}). If this wasn’t you, review your sessions and secure your account.`;
      document.getElementById('sec-alert').style.display = 'block';
    }
    document.getElementById('login-history').innerHTML = (data.recentLogins || []).map((l) => `
      <div class="sec-item" style="margin-bottom:6px;">
        <div><div class="name">${escSec(l.ip || 'unknown IP')} ${l.suspicious ? '⚠ flagged' : ''}</div>
        <div class="detail">${escSec((l.user_agent || 'Unknown browser').slice(0, 80))}</div></div>
        <div class="detail">${new Date(l.created_at.replace(' ', 'T') + 'Z').toLocaleString()}</div>
      </div>`).join('') || '<div class="empty-state">No logins recorded yet.</div>';

    document.getElementById('score-total').textContent = `${data.securityScore} / 100`;
    document.getElementById('score-breakdown').innerHTML = data.securityScoreBreakdown.map((b) => `
      <div class="sec-item" style="margin-bottom:8px;">
        <div>
          <div class="name">${escSec(b.label)}</div>
          <div class="detail">${escSec(b.detail)}</div>
        </div>
        <div class="sec-check" style="color:${b.points === b.max ? 'var(--accent3)' : (b.points === 0 ? 'var(--danger, #e55)' : 'var(--warn, #d90)')}">${b.points} / ${b.max}</div>
      </div>
    `).join('');

    const events = document.getElementById('sec-events');
    if (data.recentEvents.length === 0) {
      events.innerHTML = '<div class="empty-state">No security events yet.</div>';
    } else {
      events.innerHTML = data.recentEvents.map((e) => `
        <div class="activity-row">
          <div class="activity-icon ${e.icon === '⚠' ? 'warn' : 'ok'}">${e.icon}</div>
          <div class="activity-label">${escSec(e.label)}</div>
          <div class="activity-time">${fmtDateSec(e.created_at)}</div>
        </div>
      `).join('');
    }
  } catch (err) {
    document.getElementById('sec-capabilities').innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

loadSecurity();

const sidebarLogoutBtn = document.getElementById('sidebarLogout');
if (sidebarLogoutBtn) {
  sidebarLogoutBtn.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
}
