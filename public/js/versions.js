/**
 * VaultShare 2.0 — public/js/versions.js
 * =====================================================================
 * Frontend for Feature: File Version History. Loaded on index.html.
 * Depends on: crypto.js (encryptFileData), ui.js (toast, fmtSize).
 * =====================================================================
 */

'use strict';

let _versionContext = null; // { fileId, filename }

function escVer(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtDateVer(isoString) {
  const d = new Date(isoString.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

function openVersionModal(fileId, filename) {
  _versionContext = { fileId, filename };
  document.getElementById('version-modal-filename').textContent = filename;
  document.getElementById('version-file-input').value = '';
  document.getElementById('version-password').value = '';
  document.getElementById('version-modal-overlay').classList.add('show');
  loadVersionHistory();
}

function closeVersionModal() {
  document.getElementById('version-modal-overlay').classList.remove('show');
  _versionContext = null;
}

async function loadVersionHistory() {
  const list = document.getElementById('version-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  if (!_versionContext) return;

  try {
    const res = await fetch(`/api/vault/files/${_versionContext.fileId}/versions`);
    const data = await res.json();
    if (!res.ok || !data.ok) {
      list.innerHTML = '<div class="empty-state">Could not load version history.</div>';
      return;
    }

    const rows = [];
    rows.push(`
      <div class="vault-row">
        <div class="vault-file-icon">🔒</div>
        <div class="vault-meta">
          <div class="vault-name">Version ${data.current.version} (current)</div>
          <div class="vault-sub">
            <span class="vault-algo-badge">${escVer(data.current.algorithm)}</span>
            <span>${fmtSize(data.current.file_size)}</span>
            <span>${fmtDateVer(data.current.created_at)}</span>
          </div>
        </div>
      </div>
    `);

    data.olderVersions.forEach((v) => {
      rows.push(`
        <div class="vault-row">
          <div class="vault-file-icon">🕓</div>
          <div class="vault-meta">
            <div class="vault-name">Version ${v.version_number}</div>
            <div class="vault-sub">
              <span class="vault-algo-badge">${escVer(v.algorithm)}</span>
              <span>${fmtSize(v.file_size)}</span>
              <span>${fmtDateVer(v.created_at)}</span>
            </div>
          </div>
          <div class="vault-actions">
            <button onclick="downloadVersion(${v.id})">⬇</button>
            <button onclick="restoreVersion(${v.id})">↩ Restore</button>
            <button class="danger" onclick="deleteVersion(${v.id})">🗑</button>
          </div>
        </div>
      `);
    });

    list.innerHTML = rows.join('');
  } catch (err) {
    list.innerHTML = '<div class="empty-state">Could not reach the server.</div>';
  }
}

function downloadVersion(versionId) {
  if (!_versionContext) return;
  window.location.href = `/api/vault/files/${_versionContext.fileId}/versions/${versionId}/download`;
}

async function restoreVersion(versionId) {
  if (!_versionContext) return;
  if (!confirm('Restore this version? It will become the new current version (nothing is deleted).')) return;

  try {
    const res = await fetch(`/api/vault/files/${_versionContext.fileId}/versions/${versionId}/restore`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not restore version.', 'error');
      return;
    }
    toast('Version restored.', 'success');
    loadVersionHistory();
    loadVaultFiles();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

async function deleteVersion(versionId) {
  if (!_versionContext) return;
  if (!confirm('Permanently delete this old version?')) return;

  try {
    const res = await fetch(`/api/vault/files/${_versionContext.fileId}/versions/${versionId}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not delete version.', 'error');
      return;
    }
    toast('Old version deleted.', 'success');
    loadVersionHistory();
  } catch (err) {
    toast('Could not reach the server.', 'error');
  }
}

/**
 * Uploads a new version of the current file. Runs the SAME client-side
 * AES-256-GCM + PBKDF2 flow as the main Encrypt tab (via crypto.js) —
 * the server never sees plaintext or the password here either.
 */
async function uploadNewVersion() {
  if (!_versionContext) return;

  const fileInput = document.getElementById('version-file-input');
  const password = document.getElementById('version-password').value;
  const btn = document.getElementById('version-upload-btn');

  if (!fileInput.files[0]) { toast('Choose a file first.', 'error'); return; }
  if (!password || password.length < 6) { toast('Password must be at least 6 characters.', 'error'); return; }

  btn.disabled = true;
  btn.textContent = 'Encrypting…';

  try {
    const file = fileInput.files[0];
    const plainBuffer = await file.arrayBuffer();

    const { packageBuffer, hashHex } = await encryptFileData({
      plainBuffer,
      password,
      algoKey: 'gcm',
      iterations: 310000,
      saltLen: 32,
      originalName: file.name,
      includeHash: true,
      onProgress: () => {},
    });

    btn.textContent = 'Uploading…';

    const form = new FormData();
    const blob = new Blob([packageBuffer], { type: 'application/octet-stream' });
    form.append('file', blob, `${file.name}.vaultenc`);
    form.append('algorithm', 'AES-256-GCM');
    form.append('fileHash', hashHex);

    const res = await fetch(`/api/vault/files/${_versionContext.fileId}/versions`, { method: 'POST', body: form });
    const data = await res.json();

    if (!res.ok || !data.ok) {
      toast((data.errors && data.errors[0]) || 'Could not upload new version.', 'error');
      return;
    }

    toast(`Uploaded as version ${data.file.version}.`, 'success');
    fileInput.value = '';
    document.getElementById('version-password').value = '';
    loadVersionHistory();
    loadVaultFiles();
  } catch (err) {
    toast(`Could not upload new version: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '⬆ Upload as New Version';
  }
}
