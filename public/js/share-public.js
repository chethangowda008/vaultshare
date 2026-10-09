/**
 * VaultShare — public/js/share-public.js
 * Loaded on share.html only. No login required — this page is what a
 * QR code or a copy-pasted link opens for a recipient.
 */

'use strict';

function escSP(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function fmtSizeSP(bytes) {
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(2)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function fmtDateSP(isoLike) {
  if (!isoLike) return 'Never';
  const d = new Date(isoLike.replace(' ', 'T') + 'Z');
  return d.toLocaleString();
}

function getToken() {
  // URL is /share/<token>
  const parts = window.location.pathname.split('/').filter(Boolean);
  return parts[parts.length - 1];
}

async function loadShare() {
  const token = getToken();
  const content = document.getElementById('share-content');

  try {
    const res = await fetch(`/api/public/shares/${encodeURIComponent(token)}`);
    const data = await res.json();

    if (!res.ok || !data.ok) {
      content.innerHTML = `<div class="result-header error">✕ ${escSP((data.errors && data.errors[0]) || 'Link not found.')}</div>`;
      return;
    }

    const s = data.share;

    if (s.status !== 'active') {
      const messages = {
        expired:   '✕ This share link has expired.',
        revoked:   '✕ This share link has been revoked.',
        completed: '✕ Download limit reached for this share link.',
      };
      content.innerHTML = `
        <div class="result-header error">${messages[s.status] || '✕ This link is no longer active.'}</div>
        <div style="color:var(--muted);font-size:.8rem;margin-top:8px;">${escSP(s.filename)}</div>
      `;
      return;
    }

    content.innerHTML = `
      <div class="result-header success">✓ Share Active</div>
      <div style="font-family:var(--font-display);font-weight:700;margin:10px 0 4px;word-break:break-all;">${escSP(s.filename)}</div>
      <div style="color:var(--muted);font-size:.78rem;margin-bottom:18px;">
        ${escSP(s.algorithm)} · ${fmtSizeSP(s.fileSize)} · Expires: ${fmtDateSP(s.expiresAt)}
      </div>
      ${s.passwordProtected ? `
        <div class="field" style="margin-bottom:10px;">
          <label>This share is password-protected</label>
          <input type="password" id="share-access-password" placeholder="Enter the share password"/>
        </div>
      ` : ''}
      <div id="share-access-error" style="color:#e55;font-size:.76rem;margin-bottom:8px;display:none;"></div>
      ${s.files ? `
        <div style="text-align:left;margin-bottom:10px;font-size:.8rem;">
          <div style="color:var(--muted);margin-bottom:6px;">This share contains ${s.files.length} files:</div>
          ${s.files.map((f) => `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <span style="flex:1;word-break:break-all;">${escSP(f.filename)} <span style="color:var(--muted);">(${fmtSizeSP(f.fileSize)})</span></span>
            <button class="copy-btn" onclick="accessFile(this.dataset.name, ${f.itemId})" data-name="${escSP(f.filename)}">⬇ Download</button></div>`).join('')}
        </div>` : `<button class="btn btn-primary" id="access-file-btn" onclick="accessFile('${escSP(s.filename).replace(/'/g, "\\'")}')">⬇ Access File</button>`}
      <div style="color:var(--muted);font-size:.7rem;margin-top:14px;">
        This is an encrypted VaultShare package (.vaultenc). You'll need the password from whoever
        sent you this link to open it in the Decrypt tab.
      </div>
    `;
  } catch (err) {
    content.innerHTML = '<div class="result-header error">✕ Could not reach the server.</div>';
  }
}

async function accessFile(filename, itemId) {
  const token = getToken();
  const btn = document.getElementById('access-file-btn') || { disabled: false, textContent: '' };
  const errBox = document.getElementById('share-access-error');
  const passInput = document.getElementById('share-access-password');
  errBox.style.display = 'none';

  btn.disabled = true;
  btn.textContent = 'Downloading…';

  try {
    const res = await fetch(`/api/public/shares/${encodeURIComponent(token)}/download`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: passInput ? passInput.value : undefined, itemId }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      errBox.textContent = (data.errors && data.errors[0]) || 'Could not download this file.';
      errBox.style.display = 'block';
      return;
    }

    const blob = await res.blob();
    const downloadName = (filename || 'file').replace(/\.[^/.]+$/, '') + '.vaultenc';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    errBox.textContent = 'Could not reach the server.';
    errBox.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = '⬇ Access File';
  }
}

loadShare();
