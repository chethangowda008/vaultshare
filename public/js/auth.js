if (localStorage.getItem('vsReduceMotion') === '1') document.documentElement.classList.add('reduce-motion');
/**
 * VaultShare — public/js/auth.js
 * =====================================================================
 * Frontend logic for Feature 1: User Registration & Login.
 * Loaded on login.html, register.html, AND index.html.
 * =====================================================================
 */

'use strict';

let _authToastTimer = null;

/** Same toast pattern used in ui.js, kept local so this file works
 *  standalone on login.html / register.html (which don't load ui.js). */
function authToast(message, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(_authToastTimer);
  _authToastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

function showAuthError(messages) {
  const box = document.getElementById('auth-error');
  if (!box) return;
  box.innerHTML = Array.isArray(messages)
    ? messages.map((m) => `<div>${escapeHtml(m)}</div>`).join('')
    : escapeHtml(messages);
  box.style.display = 'block';
}

function hideAuthError() {
  const box = document.getElementById('auth-error');
  if (box) box.style.display = 'none';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function setButtonLoading(btn, loading, loadingText, normalText) {
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? loadingText : normalText;
}

// ── SHOW / HIDE PASSWORD TOGGLES ─────────────────────────────────────────
document.querySelectorAll('.eye-btn[data-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.toggle);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? '👁' : '🙈';
  });
});

// ── PASSWORD STRENGTH METER (register page only) ────────────────────────
const strengthInput = document.getElementById('password');
const strengthFill  = document.getElementById('strength-fill');
const strengthLabel = document.getElementById('strength-label');

if (strengthInput && strengthFill && document.getElementById('registerForm')) {
  strengthInput.addEventListener('input', () => {
    const val = strengthInput.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (val.length >= 12) score++;
    if (/[a-z]/.test(val) && /[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    const levels = [
      { pct: 0,   color: 'var(--border)', label: 'At least 8 characters, with a letter and a number' },
      { pct: 25,  color: 'var(--danger)', label: 'Weak' },
      { pct: 50,  color: 'var(--warn)',   label: 'Fair' },
      { pct: 75,  color: 'var(--accent)', label: 'Good' },
      { pct: 100, color: 'var(--accent3)', label: 'Strong' },
    ];
    const lvl = levels[Math.min(score, 4)];
    strengthFill.style.width = lvl.pct + '%';
    strengthFill.style.background = lvl.color;
    if (strengthLabel) strengthLabel.textContent = val ? lvl.label : levels[0].label;
  });
}

// ── LOGIN FORM ────────────────────────────────────────────────────────────
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAuthError();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');

    setButtonLoading(btn, true, 'Logging in…', 'Login');
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (!res.ok || !data.ok) {
        showAuthError(data.errors || ['Login failed.']);
        setButtonLoading(btn, false, 'Logging in…', 'Login');
        return;
      }

      authToast('Welcome back!', 'success');
      window.location.href = '/';
    } catch (err) {
      showAuthError(['Could not reach the server. Please try again.']);
      setButtonLoading(btn, false, 'Logging in…', 'Login');
    }
  });
}

// ── REGISTER FORM ─────────────────────────────────────────────────────────
const registerForm = document.getElementById('registerForm');
if (registerForm) {
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAuthError();

    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const btn = document.getElementById('registerBtn');

    if (password !== confirmPassword) {
      showAuthError(['Passwords do not match.']);
      return;
    }

    setButtonLoading(btn, true, 'Creating account…', 'Create Account');
    try {
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });
      const data = await res.json();

      if (!res.ok || !data.ok) {
        showAuthError(data.errors || ['Registration failed.']);
        setButtonLoading(btn, false, 'Creating account…', 'Create Account');
        return;
      }

      authToast('Account created!', 'success');
      window.location.href = '/';
    } catch (err) {
      showAuthError(['Could not reach the server. Please try again.']);
      setButtonLoading(btn, false, 'Creating account…', 'Create Account');
    }
  });
}

// ── LOGGED-IN USER BAR (index.html only) ──────────────────────────────────
const userBarSlot = document.getElementById('user-bar-slot');
if (userBarSlot) {
  fetch('/api/me')
    .then((res) => res.json())
    .then((data) => {
      if (!data.ok || !data.user) return; // shouldn't happen — page is protected server-side

      // Feature 18 — single shared check, used by every page's sidebar:
      // only reveal the "Admin" link when the server says this user is
      // an admin. The client never decides this on its own.
      const adminNavLink = document.getElementById('admin-nav-link');
      if (adminNavLink) {
        adminNavLink.style.display = data.user.is_admin ? '' : 'none';
      }
      // VaultShare 3.0: same pattern for the new admin-only pages.
      ['admin-users-nav-link', 'admin-audit-nav-link'].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.style.display = data.user.is_admin ? '' : 'none';
      });

      const bar = document.createElement('div');
      bar.className = 'user-bar';
      bar.innerHTML = `
        <span class="user-name">👤 ${escapeHtml(data.user.name)}</span>
        <button class="logout-link" id="logoutBtn">Logout</button>
      `;
      userBarSlot.appendChild(bar);

      document.getElementById('logoutBtn').addEventListener('click', async () => {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
      });
    })
    .catch(() => {});
}
