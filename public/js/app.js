/**
 * VaultShare — app.js
 * =====================================================================
 * Top-level application controller. Wires UI events to crypto engine.
 * Depends on: crypto.js, ui.js
 * =====================================================================
 */

'use strict';

// ── STATE ──────────────────────────────────────────────────────────────
let _encBlob = null;  // Last encrypted output blob
let _decBlob = null;  // Last decrypted output blob
let _encMeta = null;  // { originalName, algoName, hashHex } for the last encryption — used by saveToVault()

// ── ENCRYPT ────────────────────────────────────────────────────────────

/**
 * Reads form values, validates them, calls encryptFileData(),
 * and populates the result section.
 */
async function encryptFile() {
  const fileInput  = document.getElementById('enc-file-input');
  const pass       = document.getElementById('enc-pass').value;
  const pass2      = document.getElementById('enc-pass2').value;
  const iterations = parseInt(document.getElementById('kdf-iter').value, 10);
  const saltLen    = parseInt(document.getElementById('salt-len').value, 10);
  const outName    = document.getElementById('out-name').value.trim();
  const includeHash = document.getElementById('include-hash').checked;
  const algoKey    = getSelectedAlgo();

  // ── Validation ──
  if (!fileInput.files[0]) { toast('Please select a file to encrypt.', 'error'); return; }
  if (!pass)               { toast('Please enter a password.', 'error'); return; }
  if (pass !== pass2)      { toast('Passwords do not match.', 'error'); return; }
  if (pass.length < 6)     { toast('Password must be at least 6 characters.', 'error'); return; }

  const file = fileInput.files[0];

  // ── Reset UI ──
  document.getElementById('enc-result').classList.remove('show');
  document.getElementById('enc-error').classList.remove('show');
  const btn = document.getElementById('enc-btn');
  btn.disabled = true;

  try {
    const plainBuffer = await file.arrayBuffer();

    const { packageBuffer, hashHex } = await encryptFileData({
      plainBuffer,
      password:     pass,
      algoKey,
      iterations,
      saltLen,
      originalName: file.name,
      includeHash,
      onProgress:   (pct, label) => setProgress('enc', pct, label),
    });

    await sleep(300);
    hideProgress('enc');

    // Determine output filename
    const baseName = (outName || file.name).replace(/\.[^/.]+$/, '');
    const dlName   = `${baseName}.vaultenc`;

    // Wire download button
    _encBlob = new Blob([packageBuffer], { type: 'application/octet-stream' });
    document.getElementById('enc-dl-btn').onclick = () => triggerDownload(_encBlob, dlName);

    // Build result metadata grid
    const algoName = { gcm: 'AES-256-GCM', cbc: 'AES-256-CBC', ctr: 'AES-256-CTR' }[algoKey];
    _encMeta = { originalName: file.name, algoName, hashHex };
    document.getElementById('enc-meta').innerHTML =
      metaItem('Original File',   file.name)                    +
      metaItem('Algorithm',       algoName)                     +
      metaItem('Key Size',        '256-bit')                    +
      metaItem('KDF',             `PBKDF2 · ${iterations.toLocaleString()} iters`) +
      metaItem('Salt',            `${saltLen * 8}-bit random`)  +
      metaItem('IV',              `${saltLen === 16 ? 128 : 96}-bit random`) +
      metaItem('Original Size',   fmtSize(plainBuffer.byteLength)) +
      metaItem('Encrypted Size',  fmtSize(packageBuffer.byteLength));

    document.getElementById('enc-hash').textContent = hashHex;
    document.getElementById('enc-result').classList.add('show');
    toast('File encrypted successfully!', 'success');

  } catch (err) {
    hideProgress('enc');
    document.getElementById('enc-error-msg').textContent = err.message;
    document.getElementById('enc-error').classList.add('show');
    toast(`Encryption failed: ${err.message}`, 'error');
    console.error('[VaultShare] Encrypt error:', err);
  }

  btn.disabled = false;
}

// ── SAVE TO VAULT (Feature 4) ─────────────────────────────────────────
// Uploads the .vaultenc package produced above to the server. The
// encryption password is never sent — only the already-encrypted
// bytes, the original filename, the algorithm label, and the SHA-256
// hash (which is also embedded inside the package itself, so it can
// always be independently re-checked on decrypt).
async function saveToVault() {
  if (!_encBlob || !_encMeta) {
    toast('Encrypt a file first.', 'error');
    return;
  }

  const btn = document.getElementById('enc-vault-btn');
  const originalText = btn.textContent;
  btn.disabled = true;

  try {
    await uploadInChunks(_encBlob, _encMeta, (pct, label) => { btn.textContent = `${label} ${pct}%`; }, false);
    toast('Saved to your Vault!', 'success');
  } catch (err) {
    if (err.duplicate) {
      // Feature 7: duplicate file detection — let the user choose rather than silently blocking.
      if (confirm('An identical file already exists in your vault. Upload anyway?')) {
        try {
          await uploadInChunks(_encBlob, _encMeta, (pct, label) => { btn.textContent = `${label} ${pct}%`; }, true);
          toast('Saved to your Vault!', 'success');
        } catch (err2) {
          toast(err2.message || 'Could not save to vault.', 'error');
        }
      }
    } else {
      toast(err.message || 'Could not save to vault.', 'error');
    }
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

/**
 * Resumable upload of the ALREADY-ENCRYPTED package in 4 MB chunks.
 * If a chunk fails (network drop / server error) it retries a few times,
 * asking the server how many bytes it already has and continuing from
 * there — the upload never restarts from zero. Sensitive data is not
 * involved: only ciphertext is sent, same as before.
 */
async function uploadInChunks(blob, meta, onProgress, confirmDuplicate) {
  const jsonHeaders = { 'Content-Type': 'application/json' };
  const initRes = await fetch('/api/uploads/init', {
    method: 'POST', headers: jsonHeaders,
    body: JSON.stringify({ originalFilename: meta.originalName, totalSize: blob.size, algorithm: meta.algoName, fileHash: meta.hashHex, confirmDuplicate }),
  });
  const init = await initRes.json();
  if (initRes.status === 409 && init.duplicate) {
    throw Object.assign(new Error('Duplicate file.'), { duplicate: true });
  }
  if (!initRes.ok || !init.ok) throw new Error((init.errors && init.errors[0]) || 'Could not start upload.');

  const { uploadId, chunkSize } = init;
  let offset = 0, failures = 0;

  while (offset < blob.size) {
    const end = Math.min(offset + chunkSize, blob.size);
    try {
      const res = await fetch(`/api/uploads/${uploadId}?offset=${offset}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: blob.slice(offset, end),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) { offset = data.received; failures = 0; }
      else if (res.status === 409 && typeof data.received === 'number') { offset = data.received; }   // resync
      else if (res.status >= 400 && res.status < 500 && res.status !== 408) throw Object.assign(new Error((data.errors && data.errors[0]) || 'Upload rejected.'), { fatal: true });
      else throw new Error('Server error');
    } catch (err) {
      if (err.fatal) throw err;
      failures += 1;
      if (failures > 5) throw new Error('Upload interrupted. Check your connection and try again.');
      onProgress(Math.floor((offset / blob.size) * 100), `Retrying (${failures}/5)…`);
      await new Promise((r) => setTimeout(r, 1000 * failures));
      // Resume: ask the server how much it really has.
      try {
        const st = await (await fetch(`/api/uploads/${uploadId}`)).json();
        if (st.ok) offset = st.received;
      } catch { /* still offline: loop will retry */ }
      continue;
    }
    onProgress(Math.floor((offset / blob.size) * 100), `Uploading ${fmtSize(offset)} / ${fmtSize(blob.size)}`);
  }

  const done = await fetch(`/api/uploads/${uploadId}/complete`, { method: 'POST' });
  const doneData = await done.json();
  if (!done.ok || !doneData.ok) throw new Error((doneData.errors && doneData.errors[0]) || 'Could not finish upload.');
  return doneData.file;
}

// ── DECRYPT ────────────────────────────────────────────────────────────

/**
 * Reads form values, validates them, calls decryptFileData(),
 * and populates the result section.
 */
async function decryptFile() {
  const fileInput  = document.getElementById('dec-file-input');
  const pass       = document.getElementById('dec-pass').value;
  const verifyHash = document.getElementById('verify-hash').checked;

  if (!fileInput.files[0]) { toast('Please select a .vaultenc file.', 'error'); return; }
  if (!pass)               { toast('Please enter the decryption password.', 'error'); return; }

  // ── Reset UI ──
  document.getElementById('dec-result').classList.remove('show');
  document.getElementById('dec-error').classList.remove('show');
  const btn = document.getElementById('dec-btn');
  btn.disabled = true;

  try {
    const packageBuffer = await fileInput.files[0].arrayBuffer();

    const { plainBuffer, computedHash, meta } = await decryptFileData({
      packageBuffer,
      password:    pass,
      verifyHash,
      onProgress:  (pct, label) => setProgress('dec', pct, label),
    });

    await sleep(300);
    hideProgress('dec');

    // Wire download button
    _decBlob = new Blob([plainBuffer], { type: 'application/octet-stream' });
    document.getElementById('dec-dl-btn').onclick =
      () => triggerDownload(_decBlob, meta.originalName);

    // Build result metadata
    const hashStatus = meta.hashVerified
      ? '✅ Verified'
      : (meta.embeddedHash ? '⚠ Skipped' : 'No hash embedded');

    document.getElementById('dec-meta').innerHTML =
      metaItem('Original Filename', meta.originalName)         +
      metaItem('Algorithm',         meta.algorithm)            +
      metaItem('KDF Iterations',    meta.iterations.toLocaleString()) +
      metaItem('Decrypted Size',    fmtSize(plainBuffer.byteLength)) +
      metaItem('Integrity',         hashStatus);

    document.getElementById('dec-hash').textContent = computedHash;
    document.getElementById('dec-result').classList.add('show');
    toast('Decrypted & integrity verified!', 'success');

  } catch (err) {
    hideProgress('dec');
    document.getElementById('dec-error-msg').textContent = err.message;
    document.getElementById('dec-error').classList.add('show');
    toast(err.message, 'error');
    console.error('[VaultShare] Decrypt error:', err);
  }

  btn.disabled = false;
}

// ── VERIFY / HASH ──────────────────────────────────────────────────────

/**
 * Computes and displays the SHA-256 hash of the selected file.
 */
async function computeHash() {
  const input = document.getElementById('ver-file-input');
  if (!input.files[0]) return;

  document.getElementById('ver-result').classList.remove('show');

  try {
    const buffer = await input.files[0].arrayBuffer();
    const hash   = await hashFile(buffer);

    document.getElementById('ver-hash').textContent = hash;
    document.getElementById('ver-result').classList.add('show');
    document.getElementById('ver-status-label').textContent  = '🔍 Hash Computed';
    document.getElementById('ver-status-label').className    = 'result-header success';

    compareHashes();
    toast('SHA-256 hash computed.', 'info');
  } catch (err) {
    toast(`Failed to compute hash: ${err.message}`, 'error');
  }
}

/**
 * Compares the computed hash against the user-supplied expected hash
 * and updates the comparison result display.
 */
function compareHashes() {
  const computed  = document.getElementById('ver-hash').textContent.trim().toLowerCase();
  const expected  = document.getElementById('expected-hash').value.trim().toLowerCase();
  const resultEl  = document.getElementById('ver-compare-result');
  const statusEl  = document.getElementById('ver-status-label');

  if (!expected || computed === '—') {
    resultEl.textContent = '';
    return;
  }

  if (computed === expected) {
    resultEl.innerHTML  = '<span style="color:var(--accent3)">✅ Hashes MATCH — file is byte-for-byte identical</span>';
    statusEl.textContent = '✅ Integrity Verified';
    statusEl.className   = 'result-header success';
  } else {
    resultEl.innerHTML  = '<span style="color:var(--danger)">❌ Hashes DO NOT MATCH — file may be modified or corrupted</span>';
    statusEl.textContent = '❌ Integrity Failed';
    statusEl.className   = 'result-header error';
  }
}

/** Resets the verify panel result state. */
function clearVerify() {
  document.getElementById('ver-result').classList.remove('show');
  document.getElementById('ver-hash').textContent = '—';
  document.getElementById('ver-compare-result').textContent = '';
}
