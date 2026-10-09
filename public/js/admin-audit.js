/** VaultShare — public/js/admin-audit.js (admin-audit.html). Depends on ui.js. Inline SVG bars — no external chart lib, keeps CSP intact. */
'use strict';
function escAA(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function drawBars(svgId, values, max) {
  const svg = document.getElementById(svgId);
  const w = 400, h = 180, padBottom = 20, barGap = 4;
  max = max || Math.max(1, ...values);
  const barWidth = (w / values.length) - barGap;
  let bars = '';
  values.forEach((v, i) => {
    const barHeight = ((h - padBottom - 10) * v) / max;
    const x = i * (barWidth + barGap) + barGap / 2, y = h - padBottom - barHeight;
    bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${barHeight.toFixed(1)}" rx="2" fill="var(--accent)"/>`;
  });
  svg.innerHTML = `<line x1="0" y1="${h - padBottom}" x2="${w}" y2="${h - padBottom}" stroke="var(--border)"/>` + bars;
}

function drawDualBars(svgId, success, fail) {
  const svg = document.getElementById(svgId);
  const w = 400, h = 180, padBottom = 20, groupGap = 6;
  const n = success.length, max = Math.max(1, ...success, ...fail);
  const groupWidth = (w / n) - groupGap, barWidth = (groupWidth - 2) / 2;
  let bars = '';
  for (let i = 0; i < n; i++) {
    const gx = i * (groupWidth + groupGap) + groupGap / 2;
    const sh = ((h - padBottom - 10) * success[i]) / max, fh = ((h - padBottom - 10) * fail[i]) / max;
    bars += `<rect x="${gx}" y="${h - padBottom - sh}" width="${barWidth}" height="${sh}" fill="var(--accent3)"/>`;
    bars += `<rect x="${gx + barWidth + 2}" y="${h - padBottom - fh}" width="${barWidth}" height="${fh}" fill="var(--danger)"/>`;
  }
  svg.innerHTML = `<line x1="0" y1="${h - padBottom}" x2="${w}" y2="${h - padBottom}" stroke="var(--border)"/>` + bars;
}

function fillByDay(rows, days) {
  const dates = []; for (let i = days - 1; i >= 0; i--) { const d = new Date(); d.setUTCDate(d.getUTCDate() - i); dates.push(d.toISOString().slice(0, 10)); }
  const map = new Map(rows.map((r) => [r.d, r.n]));
  return dates.map((d) => map.get(d) || 0);
}

async function loadAudit() {
  try {
    const res = await fetch('/api/admin/audit?days=14');
    if (res.status === 403) throw new Error('forbidden');
    const audit = await res.json();

    drawBars('chart-events', fillByDay(audit.eventsByDay, 14));

    const dates = []; for (let i = 13; i >= 0; i--) { const d = new Date(); d.setUTCDate(d.getUTCDate() - i); dates.push(d.toISOString().slice(0, 10)); }
    const successMap = new Map(), failMap = new Map();
    audit.loginSuccessVsFail.forEach((r) => { (r.action === 'LOGIN' ? successMap : failMap).set(r.d, r.n); });
    drawDualBars('chart-logins', dates.map((d) => successMap.get(d) || 0), dates.map((d) => failMap.get(d) || 0));

    const maxType = Math.max(1, ...audit.eventsByType.map((t) => t.n));
    document.getElementById('events-by-type').innerHTML = audit.eventsByType.map((t) => `
      <div class="type-bar-row"><div class="type-label">${escAA(t.action)}</div>
        <div class="type-bar-track"><div class="type-bar-fill" style="width:${(t.n / maxType) * 100}%"></div></div>
        <div style="width:40px;text-align:right;color:var(--muted);">${t.n}</div></div>`).join('');
  } catch (e) {
    document.querySelector('main').innerHTML = '<div class="empty-state">Admin access required.</div>';
  }
}
loadAudit();

// ── Admin session guard and logout (admin-audit.html) ────────────────────
(async function adminAuditInit() {
  const res  = await fetch('/api/admin/me').catch(() => null);
  const data = res ? await res.json().catch(() => null) : null;
  if (!data || !data.isAdmin) {
    window.location.href = '/admin-login.html';
    return;
  }
  const slot = document.getElementById('user-bar-slot');
  if (slot) {
    slot.innerHTML = `<div class="user-bar"><span class="user-name">👑 Admin</span><button class="logout-link" id="adminLogoutBtn3">Logout</button></div>`;
    document.getElementById('adminLogoutBtn3').addEventListener('click', async () => {
      await fetch('/api/admin/logout', { method: 'POST' });
      window.location.href = '/admin-login.html';
    });
  }
})();
const sidebarLogoutBtnAA = document.getElementById('sidebarLogout');
if (sidebarLogoutBtnAA) {
  sidebarLogoutBtnAA.addEventListener('click', async () => {
    await fetch('/api/admin/logout', { method: 'POST' });
    window.location.href = '/admin-login.html';
  });
}
