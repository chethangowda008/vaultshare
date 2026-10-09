/** VaultShare — public/js/settings.js (settings.html). */
'use strict';
const $s = (id) => document.getElementById(id);
function fmtBytes(n) { return typeof fmtSize === 'function' ? fmtSize(n) : n + ' B'; }

async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    const s = await res.json();
    if (!s.ok) return;
    const v = s.settings;
    $s('st-usage').textContent = `${v.fileCount} file(s) using ${fmtBytes(v.storageBytes)}.`;
    $s('st-days').value = v.recycleDays;
    $s('st-default').textContent = `Server default: ${v.serverDefaults.recycleDays} days.`;
    $s('st-exp').value = v.defaultShareExpiry; $s('st-lim').value = v.defaultShareLimit;
  } catch { toast('Could not reach the server.', 'error'); }
  $s('st-motion').checked = localStorage.getItem('vsReduceMotion') === '1';
}
async function saveSettings() {
  const body = { recycleDays: $s('st-days').value, defaultShareExpiry: $s('st-exp').value, defaultShareLimit: $s('st-lim').value };
  const res = await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return toast((data.errors && data.errors[0]) || 'Could not save settings.', 'error');
  if ($s('st-motion').checked) localStorage.setItem('vsReduceMotion', '1'); else localStorage.removeItem('vsReduceMotion');
  document.documentElement.classList.toggle('reduce-motion', $s('st-motion').checked);
  toast('Settings saved.', 'success');
}
loadSettings();
