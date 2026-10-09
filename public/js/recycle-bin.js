/**
 * VaultShare 2.0 — public/js/recycle-bin.js
 * Loaded on recycle-bin.html only. Depends on ui.js (toast, fmtSize).
 */

'use strict';

function escapeHtmlRB(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateRB(isoString) {
  const d = new Date(isoString.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

async function loadRecycleBin() {
  const list = document.getElementById('bin-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const res = await fetch('/api/recycle-bin');
    const data = await res.json();

    if (!res.ok || !data.ok) {
      list.innerHTML = '<div class="empty-state">Could not load Recycle Bin.</div>';
      return;
    }

    document.getElementById('retention-note').textContent =
      `Deleted files are automatically permanently deleted after ${data.retentionDays} days.`;

    if (data.files.length === 0) {
      list.innerHTML = '<div class="empty-state">Recycle Bin is empty.</div>';
      return;
    }

    list.innerHTML = data.files.map((f) => `
      <div class="vault-row" data-file-id="${f.id}">
        <div class="vault-file-icon">🗑️</div>
        <div class="vault-meta">
          <div class="vault-name">${escapeHtmlRB(f.original_filename)}</div>
          <div class="vault-sub">
            <span>${fmtSize(f.file_size)}</span>
            <span>Deleted ${fmtDateRB(f.deleted_at)}</span>
          </div>
        </div>
        <div class="vault-actions">
          <button onclick="restoreFile(${f.id})">↩ Restore</button>
          <button class="danger" onclick="permanentlyDelete(${f.id})">🗑 Delete Forever</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    list.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

async function restoreFile(fileId) {
  try {
    const res = await fetch(`/api/recycle-bin/${fileId}/restore`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not restore file.', 'error');
      return;
    }
    toast('File restored.', 'success');
    loadRecycleBin();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

async function permanentlyDelete(fileId) {
  if (!confirm('Permanently delete this file? This cannot be undone.')) return;
  try {
    const res = await fetch(`/api/recycle-bin/${fileId}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not delete file.', 'error');
      return;
    }
    toast('File permanently deleted.', 'success');
    loadRecycleBin();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

async function emptyBin() {
  if (!confirm('Permanently delete EVERYTHING in the Recycle Bin? This cannot be undone.')) return;
  try {
    const res = await fetch('/api/recycle-bin', { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not empty Recycle Bin.', 'error');
      return;
    }
    toast(`Permanently deleted ${data.count} file(s).`, 'success');
    loadRecycleBin();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

loadRecycleBin();
