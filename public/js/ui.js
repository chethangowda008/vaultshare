/**
 * VaultShare — ui.js
 * =====================================================================
 * All DOM manipulation, UI helpers, drag-and-drop, toast notifications,
 * progress bars, and utility functions. No crypto logic here.
 * =====================================================================
 */

'use strict';

// ── TOAST NOTIFICATIONS ────────────────────────────────────────────────

let _toastTimer = null;

/**
 * Displays a toast notification.
 * @param {string} message
 * @param {'info'|'success'|'error'} type
 */
function toast(message, type = 'info') {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className   = `toast show ${type}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

// ── PROGRESS BAR ───────────────────────────────────────────────────────

/**
 * Shows or updates the progress bar for a given panel prefix.
 * @param {'enc'|'dec'} prefix
 * @param {number}      pct   0–100
 * @param {string}      label Status text
 */
function setProgress(prefix, pct, label) {
  document.getElementById(`${prefix}-progress`).classList.add('show');
  document.getElementById(`${prefix}-prog-fill`).style.width = `${pct}%`;
  document.getElementById(`${prefix}-prog-label`).textContent = label;
}

/** Hides the progress bar for a given panel prefix. */
function hideProgress(prefix) {
  document.getElementById(`${prefix}-progress`).classList.remove('show');
}

// ── FILE SIZE FORMATTER ────────────────────────────────────────────────

/**
 * Formats bytes into a human-readable size string.
 * @param {number} bytes
 * @returns {string}
 */
function fmtSize(bytes) {
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(2)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

// ── DRAG AND DROP ─────────────────────────────────────────────────────

/**
 * Handles dragover event on a drop zone.
 * @param {DragEvent} e
 * @param {string}    dzId  Element ID of the drop zone
 */
function dzOver(e, dzId) {
  e.preventDefault();
  document.getElementById(dzId).classList.add('dragover');
}

/**
 * Handles dragleave event on a drop zone.
 * @param {string} dzId
 */
function dzLeave(dzId) {
  document.getElementById(dzId).classList.remove('dragover');
}

/**
 * Handles drop event — extracts the file and triggers file display.
 */
function dzDrop(e, dzId, inputId, infoId, nameId, sizeId) {
  e.preventDefault();
  dzLeave(dzId);

  const file = e.dataTransfer.files[0];
  if (!file) return;

  // Inject into the hidden file input so it behaves like a normal selection
  const input = document.getElementById(inputId);
  const dt    = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;

  showFileInfo(file, infoId, nameId, sizeId, dzId);

  // Trigger hash computation if on the verify tab
  if (inputId === 'ver-file-input') computeHash();
}

/**
 * Called when a file input's `change` event fires.
 */
function fileSelected(inputId, infoId, nameId, sizeId, dzId) {
  const input = document.getElementById(inputId);
  if (!input.files[0]) return;
  showFileInfo(input.files[0], infoId, nameId, sizeId, dzId);
}

/**
 * Displays file metadata and hides the drop zone prompt.
 * @param {File}   file
 * @param {string} infoId
 * @param {string} nameId
 * @param {string} sizeId
 * @param {string} dzId
 */
function showFileInfo(file, infoId, nameId, sizeId, dzId) {
  document.getElementById(nameId).textContent = file.name;
  document.getElementById(sizeId).textContent = fmtSize(file.size);
  document.getElementById(infoId).classList.add('show');
  document.getElementById(dzId).style.display  = 'none';
}

/**
 * Resets a file input and restores the drop zone.
 */
function clearFile(inputId, infoId, dzId) {
  document.getElementById(inputId).value = '';
  document.getElementById(infoId).classList.remove('show');
  document.getElementById(dzId).style.display = '';
}

// ── PASSWORD VISIBILITY ────────────────────────────────────────────────

/**
 * Toggles password field visibility.
 * @param {string}      inputId
 * @param {HTMLElement} btn     The eye button element
 */
function toggleEye(inputId, btn) {
  const inp = document.getElementById(inputId);
  inp.type  = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

// ── PASSWORD STRENGTH METER ────────────────────────────────────────────

/**
 * Updates the password strength bar and label based on heuristic scoring.
 * @param {string} value The current password value
 */
function updateStrength(value) {
  let score = 0;
  if (value.length >= 8)            score++;
  if (value.length >= 12)           score++;
  if (/[A-Z]/.test(value))          score++;
  if (/[0-9]/.test(value))          score++;
  if (/[^a-zA-Z0-9]/.test(value))   score++;

  const levels = [
    [0, '#6b7280', '—'],
    [1, '#ef4444', 'Weak'],
    [2, '#f59e0b', 'Fair'],
    [3, '#f59e0b', 'Good'],
    [4, '#10b981', 'Strong'],
    [5, '#00e5ff', 'Excellent'],
  ];

  const [, colour, label] = levels[score];
  const fill  = document.getElementById('strength-fill');
  const lbl   = document.getElementById('strength-label');

  fill.style.width      = `${score * 20}%`;
  fill.style.background = colour;
  lbl.textContent       = label;
  lbl.style.color       = colour;
}

// ── ALGORITHM SELECTOR ─────────────────────────────────────────────────

/** Tracks the currently selected algorithm. Module-level. */
let _selectedAlgo = 'gcm';

/**
 * Highlights the selected algorithm card and updates `_selectedAlgo`.
 * @param {'gcm'|'cbc'|'ctr'} key
 */
function selectAlgo(key) {
  _selectedAlgo = key;
  ['gcm', 'cbc', 'ctr'].forEach(k => {
    document.getElementById(`alg-${k}`).classList.remove('selected', 'purple');
  });
  const card = document.getElementById(`alg-${key}`);
  card.classList.add('selected');
  if (key !== 'gcm') card.classList.add('purple');
}

/** Returns the currently selected algorithm key. */
function getSelectedAlgo() {
  return _selectedAlgo;
}

// ── TAB SWITCHING ──────────────────────────────────────────────────────

/**
 * Switches the visible panel and updates nav button states.
 * @param {string}      tab  'encrypt' | 'decrypt' | 'verify' | 'about'
 * @param {HTMLElement} btn  The clicked nav button
 */
function switchTab(tab, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`panel-${tab}`).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── RESULT DISPLAY ─────────────────────────────────────────────────────

/**
 * Builds a meta-item HTML fragment for the result grid.
 * @param {string} key  Label
 * @param {string} val  Value
 * @returns {string}
 */
function metaItem(key, val) {
  return `
    <div class="meta-item">
      <div class="meta-key">${key}</div>
      <div class="meta-val">${val}</div>
    </div>`;
}

// ── CLIPBOARD ──────────────────────────────────────────────────────────

/**
 * Copies the text content of an element to the clipboard.
 * @param {string} elId
 */
async function copyHash(elId) {
  const text = document.getElementById(elId).textContent.trim();
  await navigator.clipboard.writeText(text);
  toast('Hash copied to clipboard!', 'success');
}

// ── DOWNLOAD HELPER ────────────────────────────────────────────────────

/**
 * Triggers a file download from a Blob.
 * @param {Blob}   blob
 * @param {string} filename
 */
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 600);
}

// ── MISC ───────────────────────────────────────────────────────────────

/** Simple promise-based sleep. */
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── THEME TOGGLE (Feature 25: dark / light / system) ──────────────────────
// Cycles dark -> light -> system -> dark. Persisted; theme-init.js applies
// the saved choice on the next page load before anything paints.
function currentThemeLabel() {
  var saved = localStorage.getItem('vsTheme');
  if (saved === 'dark') return '🌙 Dark';
  if (saved === 'light') return '☀️ Light';
  return '🖥️ System';
}
function cycleTheme() {
  var saved = localStorage.getItem('vsTheme');
  var next = saved === 'dark' ? 'light' : saved === 'light' ? null : 'dark';
  if (next) { localStorage.setItem('vsTheme', next); document.documentElement.setAttribute('data-theme', next); }
  else { localStorage.removeItem('vsTheme'); document.documentElement.removeAttribute('data-theme'); }
  var btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = currentThemeLabel();
}
document.addEventListener('DOMContentLoaded', function () {
  var btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = currentThemeLabel();
});

// ── COMMAND PALETTE (Feature 26: Ctrl+K / Cmd+K) ───────────────────────────
// Built entirely in JS so every page gets it just by including ui.js —
// no per-page markup to keep in sync. Pure client-side navigation; it
// calls no API and has no access implications beyond what the link itself
// already enforces server-side.
(function () {
  var COMMANDS = [
    { label: 'Dashboard', icon: '🏠', href: 'dashboard.html' },
    { label: 'My Vault — upload & manage files', icon: '🗄️', href: 'index.html' },
    { label: 'Recycle Bin', icon: '🗑️', href: 'recycle-bin.html' },
    { label: 'Shared With Me', icon: '📥', href: 'shared-with-me.html' },
    { label: 'My Shares', icon: '📤', href: 'my-shares.html' },
    { label: 'Scan QR code', icon: '🔳', href: 'scan.html' },
    { label: 'Activity log', icon: '📜', href: 'activity.html' },
    { label: 'Security Center', icon: '🛡️', href: 'security.html' },
    { label: 'Active sessions', icon: '💻', href: 'sessions.html' },
    { label: 'Analytics', icon: '📊', href: 'analytics.html' },
    { label: 'Settings', icon: '⚙️', href: 'settings.html' },
    { label: 'Profile', icon: '👤', href: 'profile.html' },
    { label: 'Admin dashboard', icon: '👑', href: 'admin.html' },
    { label: 'Toggle dark / light theme', icon: '🌓', action: 'theme' },
    { label: 'Log out', icon: '🚪', action: 'logout' },
  ];

  var overlay, input, list, built = false;

  function build() {
    if (built) return;
    built = true;
    overlay = document.createElement('div');
    overlay.id = 'cmdk-overlay';
    overlay.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9999;align-items:flex-start;justify-content:center;padding-top:12vh;';
    overlay.innerHTML =
      '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;width:92%;max-width:480px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.4);">' +
        '<input id="cmdk-input" placeholder="Type a command or page… (Esc to close)" style="width:100%;padding:14px 16px;border:0;border-bottom:1px solid var(--border);background:var(--surface);color:var(--text);font-family:var(--font-mono);font-size:.9rem;outline:none;"/>' +
        '<div id="cmdk-list" style="max-height:50vh;overflow:auto;"></div>' +
      '</div>';
    document.body.appendChild(overlay);
    input = document.getElementById('cmdk-input');
    list = document.getElementById('cmdk-list');
    input.addEventListener('input', render);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
  }

  function escCmdk(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  function render() {
    var q = input.value.trim().toLowerCase();
    var matches = COMMANDS.filter(function (c) { return !q || c.label.toLowerCase().indexOf(q) !== -1; });
    list.innerHTML = matches.map(function (c, i) {
      return '<div class="cmdk-row" data-idx="' + i + '" style="padding:10px 16px;cursor:pointer;display:flex;gap:10px;align-items:center;font-size:.84rem;' + (i === 0 ? 'background:var(--surface2);' : '') + '">' +
        '<span>' + c.icon + '</span><span>' + escCmdk(c.label) + '</span></div>';
    }).join('') || '<div style="padding:16px;color:var(--muted);font-size:.8rem;">No matching command.</div>';
    list.querySelectorAll('.cmdk-row').forEach(function (row) {
      row.addEventListener('click', function () { run(matches[parseInt(row.dataset.idx, 10)]); });
    });
  }

  function run(cmd) {
    if (!cmd) return;
    if (cmd.action === 'theme') { cycleTheme(); close(); return; }
    if (cmd.action === 'logout') { close(); fetch('/api/logout', { method: 'POST' }).then(function () { window.location.href = '/login.html'; }); return; }
    window.location.href = cmd.href;
  }

  function open_() {
    build();
    overlay.style.display = 'flex';
    input.value = '';
    render();
    setTimeout(function () { input.focus(); }, 0);
  }
  function close() { if (overlay) overlay.style.display = 'none'; }

  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open_(); }
    else if (e.key === 'Escape' && overlay && overlay.style.display !== 'none') { close(); }
    else if (overlay && overlay.style.display !== 'none') {
      var rows = list ? list.querySelectorAll('.cmdk-row') : [];
      if (!rows.length) return;
      var current = list.querySelector('.cmdk-row[style*="surface2"]');
      var idx = current ? parseInt(current.dataset.idx, 10) : 0;
      if (e.key === 'ArrowDown') { e.preventDefault(); highlight(Math.min(rows.length - 1, idx + 1)); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); highlight(Math.max(0, idx - 1)); }
      else if (e.key === 'Enter') { e.preventDefault(); rows[idx] && rows[idx].click(); }
    }
  });
  function highlight(idx) {
    list.querySelectorAll('.cmdk-row').forEach(function (r, i) { r.style.background = i === idx ? 'var(--surface2)' : ''; });
  }
})();

// ── ACCESSIBILITY (Feature 24): Escape closes any open modal ──────────────
// Works for every .modal-overlay across the app (share/version/preview
// modals etc.) without each page needing its own handler, since they all
// share the same "add/remove .show" convention.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  document.querySelectorAll('.modal-overlay.show').forEach((el) => el.classList.remove('show'));
});
