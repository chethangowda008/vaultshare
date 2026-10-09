/**
 * VaultShare 2.0 — public/js/scan.js
 * QR scanner: camera (getUserMedia) or uploaded image -> jsQR decode ->
 * validate the link (same origin, /share/<token> only) -> ask the server
 * whether the share is usable -> open the secure share page.
 * Decoding happens entirely in the browser.
 */
'use strict';

let _stream = null, _raf = null, _busy = false;
const video = document.getElementById('scan-video');
const canvas = document.getElementById('scan-canvas');
const ctx = canvas.getContext('2d', { willReadFrequently: true });

function msg(text, kind) {
  const el = document.getElementById('scan-msg');
  el.textContent = text; el.className = 'scan-msg' + (kind ? ' ' + kind : '');
}

/** Returns the share token if `text` is a VaultShare link on THIS server, else null. */
function extractToken(text) {
  let url;
  try { url = new URL(text.trim()); } catch { return null; }
  if (url.origin !== window.location.origin) return null;
  const m = /^\/share\/([A-Za-z0-9_-]{16,64})\/?$/.exec(url.pathname);
  return m ? m[1] : null;
}

async function handleDecoded(text) {
  if (_busy) return;
  _busy = true;
  const token = extractToken(text);
  if (!token) {
    msg('This QR code is not a VaultShare link for this server.', 'error');
    _busy = false; return;
  }
  stopScan();
  msg('VaultShare link found — checking it…');
  try {
    const res = await fetch(`/api/public/shares/${encodeURIComponent(token)}`);
    const data = await res.json().catch(() => ({}));
    if (res.status === 404) { msg('This share does not exist (invalid or unknown token).', 'error'); _busy = false; return; }
    if (!res.ok || !data.ok) { msg((data.errors && data.errors[0]) || 'Could not check this share.', 'error'); _busy = false; return; }
    const s = data.share;
    const expired = s.status === 'expired' || (s.expiresAt && new Date(s.expiresAt.replace(' ', 'T') + 'Z') < new Date());
    if (s.status === 'revoked') { msg('This share was revoked by its owner.', 'error'); _busy = false; return; }
    if (expired) { msg('This share has expired.', 'error'); _busy = false; return; }
    if (s.status === 'completed' || (s.downloadLimit !== null && s.downloadCount >= s.downloadLimit)) { msg('This share has reached its download limit.', 'error'); _busy = false; return; }
    msg('Valid share — opening…', 'ok');
    window.location.href = `/share/${encodeURIComponent(token)}`;
  } catch {
    msg('Could not reach the server. Check your connection and try again.', 'error');
    _busy = false;
  }
}

function decodeFrame(w, h) {
  canvas.width = w; canvas.height = h;
  ctx.drawImage(video, 0, 0, w, h);
  const img = ctx.getImageData(0, 0, w, h);
  const code = window.jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
  if (code && code.data) handleDecoded(code.data);
}

function tick() {
  if (!_stream) return;
  if (video.readyState === video.HAVE_ENOUGH_DATA && !_busy) decodeFrame(video.videoWidth, video.videoHeight);
  _raf = requestAnimationFrame(tick);
}

async function startScan() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    msg('Camera is not available in this browser. Use "Upload QR image" instead.', 'error'); return;
  }
  try {
    _stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    video.srcObject = _stream; await video.play();
    document.getElementById('video-wrap').style.display = 'block';
    msg('Scanning… hold the QR code inside the frame.');
    _busy = false; tick();
  } catch (err) {
    const denied = err && (err.name === 'NotAllowedError' || err.name === 'SecurityError');
    msg(denied ? 'Camera permission was denied. Allow camera access in your browser, or upload a QR image instead.'
               : 'Could not start the camera. Try uploading a QR image instead.', 'error');
  }
}

function stopScan() {
  if (_raf) cancelAnimationFrame(_raf);
  if (_stream) _stream.getTracks().forEach((t) => t.stop());
  _stream = null; _raf = null;
  document.getElementById('video-wrap').style.display = 'none';
}

document.getElementById('qr-file').addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const img = new Image();
  img.onload = () => {
    canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
    ctx.drawImage(img, 0, 0);
    const d = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(d.data, canvas.width, canvas.height);
    URL.revokeObjectURL(img.src);
    if (code && code.data) handleDecoded(code.data); else msg('No QR code found in that image.', 'error');
  };
  img.onerror = () => msg('That file could not be read as an image.', 'error');
  img.src = URL.createObjectURL(file);
});
