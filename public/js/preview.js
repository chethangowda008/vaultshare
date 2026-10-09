/**
 * VaultShare 2.0 — public/js/preview.js
 * Secure client-side file preview. The encrypted file is fetched through the
 * normal authenticated download route, decrypted IN THE BROWSER with
 * crypto.js, and shown from a temporary blob: URL that is revoked on close.
 * No public URL is ever created and the server never sees the plaintext.
 */
'use strict';

let _previewCtx = null;   // { fileId, filename }
let _previewUrl = null;
const PREVIEW_MAX_BYTES = 25 * 1024 * 1024;
const IMG_TYPES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', svg: 'image/svg+xml' };

function previewExt(name) { const m = /\.([a-z0-9]+)$/i.exec(name || ''); return m ? m[1].toLowerCase() : ''; }

function openPreviewModal(fileId, filename) {
  _previewCtx = { fileId, filename };
  document.getElementById('preview-filename').textContent = filename;
  document.getElementById('preview-password').value = '';
  document.getElementById('preview-body').innerHTML = '';
  document.getElementById('preview-error').style.display = 'none';
  document.getElementById('preview-pass-row').style.display = 'block';
  document.getElementById('preview-modal-overlay').classList.add('show');
}

function closePreviewModal() {
  if (_previewUrl) { URL.revokeObjectURL(_previewUrl); _previewUrl = null; }
  document.getElementById('preview-body').innerHTML = '';
  document.getElementById('preview-modal-overlay').classList.remove('show');
  _previewCtx = null;
}

function previewError(msg) {
  const el = document.getElementById('preview-error');
  el.textContent = msg; el.style.display = 'block';
}

async function runPreview() {
  if (!_previewCtx) return;
  const password = document.getElementById('preview-password').value;
  const btn = document.getElementById('preview-btn');
  const body = document.getElementById('preview-body');
  document.getElementById('preview-error').style.display = 'none';
  if (!password) { previewError('Enter the file password.'); return; }

  btn.disabled = true; btn.textContent = 'Decrypting…';
  try {
    const res = await fetch(`/api/vault/download/${_previewCtx.fileId}`);
    if (!res.ok) throw new Error('Could not download the encrypted file.');
    const packageBuffer = await res.arrayBuffer();
    const { plainBuffer, meta } = await decryptFileData({ packageBuffer, password, verifyHash: true, onProgress: () => {} });
    const name = meta.originalName || _previewCtx.filename;
    const ext = previewExt(name);
    if (plainBuffer.byteLength > PREVIEW_MAX_BYTES) throw new Error('File is too large to preview (25 MB max). Download it instead.');

    body.innerHTML = '';
    if (_previewUrl) { URL.revokeObjectURL(_previewUrl); _previewUrl = null; }

    if (IMG_TYPES[ext]) {
      _previewUrl = URL.createObjectURL(new Blob([plainBuffer], { type: IMG_TYPES[ext] }));
      const img = document.createElement('img');
      img.src = _previewUrl; img.alt = name; img.style.maxWidth = '100%';
      body.appendChild(img);
    } else if (ext === 'pdf') {
      _previewUrl = URL.createObjectURL(new Blob([plainBuffer], { type: 'application/pdf' }));
      const frame = document.createElement('iframe');
      frame.src = _previewUrl; frame.title = name; frame.style.cssText = 'width:100%;height:60vh;border:0;background:#fff;';
      body.appendChild(frame);
    } else if (ext === 'csv') {
      renderCsv(new TextDecoder().decode(plainBuffer), body);
    } else if (['txt', 'md', 'log', 'json', 'xml', 'js', 'py', 'java', 'c', 'cpp', 'html', 'css', 'sql', 'yml', 'yaml', 'ini'].includes(ext)) {
      const pre = document.createElement('pre');
      pre.style.cssText = 'white-space:pre-wrap;word-break:break-word;font-size:.78rem;';
      pre.textContent = new TextDecoder().decode(plainBuffer);   // textContent => no HTML injection
      body.appendChild(pre);
    } else {
      throw new Error(`Preview isn't available for .${ext || 'this'} files. Use Download instead.`);
    }
    document.getElementById('preview-pass-row').style.display = 'none';
  } catch (err) {
    previewError(err.message || 'Preview failed.');
  } finally {
    btn.disabled = false; btn.textContent = '🔓 Decrypt & Preview';
  }
}

/** Small safe CSV parser -> HTML table built with textContent (max 200 rows). */
function renderCsv(text, container) {
  const rows = []; let row = [], cell = '', q = false;
  for (let i = 0; i < text.length && rows.length < 200; i++) {
    const c = text[i];
    if (q) { if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n') { row.push(cell.replace(/\r$/, '')); rows.push(row); row = []; cell = ''; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const table = document.createElement('table');
  table.style.cssText = 'border-collapse:collapse;font-size:.74rem;';
  rows.forEach((r, ri) => {
    const tr = document.createElement('tr');
    r.forEach((v) => {
      const td = document.createElement(ri === 0 ? 'th' : 'td');
      td.textContent = v; td.style.cssText = 'border:1px solid var(--border);padding:4px 8px;text-align:left;';
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  container.appendChild(table);
}
