/**
 * VaultShare 2.0 — public/js/analytics.js
 * Loaded on analytics.html only. Depends on ui.js (toast, fmtSize).
 *
 * Charts are drawn as plain inline SVG bars — no external charting
 * library — so the server's existing Content-Security-Policy (script-src
 * 'self' only) doesn't need to be loosened for a third-party CDN.
 */

'use strict';

function escapeHtmlA(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function drawBarChart(svgId, values, dates) {
  const svg = document.getElementById(svgId);
  const max = Math.max(1, ...values);
  const w = 400, h = 180, padBottom = 20, padTop = 10;
  const barGap = 4;
  const barWidth = (w / values.length) - barGap;

  let bars = '';
  values.forEach((v, i) => {
    const barHeight = ((h - padBottom - padTop) * v) / max;
    const x = i * (barWidth + barGap) + barGap / 2;
    const y = h - padBottom - barHeight;
    bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${barHeight.toFixed(1)}" rx="2" fill="var(--accent)"><title>${dates[i]}: ${v}</title></rect>`;
  });

  const axisLine = `<line x1="0" y1="${h - padBottom}" x2="${w}" y2="${h - padBottom}" stroke="var(--border)" stroke-width="1"/>`;

  svg.innerHTML = axisLine + bars;
}

function renderTypeDistribution(rows) {
  const el = document.getElementById('type-dist');
  if (!rows || rows.length === 0) {
    el.innerHTML = '<div class="empty-state">No files yet.</div>';
    return;
  }
  const max = Math.max(...rows.map((r) => r.count));
  el.innerHTML = rows.map((r) => `
    <div class="type-bar-row">
      <div class="type-label">.${escapeHtmlA(r.extension)}</div>
      <div class="type-bar-track"><div class="type-bar-fill" style="width:${(r.count / max) * 100}%"></div></div>
      <div class="type-bar-count">${r.count} · ${fmtSize(r.bytes)}</div>
    </div>
  `).join('');
}

async function loadAnalytics() {
  try {
    const res = await fetch('/api/analytics?days=14');
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast('Could not load analytics.', 'error');
      return;
    }

    document.getElementById('a-total-files').textContent = data.totals.totalFiles;
    document.getElementById('a-storage').textContent = fmtSize(data.totals.totalStorageBytes);
    document.getElementById('a-active-shares').textContent = data.totals.activeShares;
    document.getElementById('a-downloads').textContent = data.totals.totalDownloads;
    document.getElementById('a-bin').textContent = data.totals.totalRecycleBin;

    drawBarChart('chart-uploads', data.series.uploadsPerDay, data.series.dates);
    drawBarChart('chart-downloads', data.series.downloadsPerDay, data.series.dates);
    drawBarChart('chart-shares', data.series.sharesPerDay, data.series.dates);

    renderTypeDistribution(data.fileTypeDistribution);
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

loadAnalytics();
