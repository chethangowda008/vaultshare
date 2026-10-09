/**
 * VaultShare — tests/crypto.test.js
 * =====================================================================
 * Unit tests for the cryptographic core.
 * Run with Node.js (>= 19 for built-in Web Crypto) or Jest + jsdom.
 *
 * Usage:
 *   node --experimental-vm-modules tests/crypto.test.js
 *   or
 *   npx jest tests/crypto.test.js
 * =====================================================================
 */

// Polyfill crypto for Node < 19
import { webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}

import { strict as assert } from 'assert';

// ── Inline minimal crypto functions for testing ──────────────────────

const MAGIC      = new Uint8Array([0x56, 0x4C, 0x54, 0x45]);
const ALGO_MAP   = { gcm: 'AES-GCM', cbc: 'AES-CBC', ctr: 'AES-CTR' };
const ALGO_IDS   = { gcm: 0, cbc: 1, ctr: 2 };
const ID_TO_ALGO = ['AES-GCM', 'AES-CBC', 'AES-CTR'];
const IV_LEN     = { 'AES-GCM': 12, 'AES-CBC': 16, 'AES-CTR': 16 };

async function deriveKey(password, salt, iterations, algoName) {
  const enc = new TextEncoder();
  const km  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    km, { name: algoName, length: 256 }, false, ['encrypt', 'decrypt']
  );
}

function buildAlgoParams(algoName, iv) {
  if (algoName === 'AES-GCM') return { name: 'AES-GCM', iv };
  if (algoName === 'AES-CBC') return { name: 'AES-CBC', iv };
  if (algoName === 'AES-CTR') return { name: 'AES-CTR', counter: iv, length: 128 };
}

function uint8ArrayToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  return arr;
}

async function sha256Hex(buffer) {
  const h = await crypto.subtle.digest('SHA-256', buffer);
  return uint8ArrayToHex(new Uint8Array(h));
}

function buildPackage({ algoId, salt, iv, originalName, hashHex, includeHash, ciphertext, iterations }) {
  const nameBytes = new TextEncoder().encode(originalName);
  const hashBytes = includeHash ? hexToUint8Array(hashHex) : new Uint8Array(0);
  const cipherArr = new Uint8Array(ciphertext);
  const header    = new Uint8Array(15);
  const hView     = new DataView(header.buffer);
  header.set(MAGIC, 0);
  header[4] = 0x01; header[5] = algoId;
  header[6] = salt.byteLength; header[7] = iv.byteLength;
  hView.setUint32(8, iterations, false);
  hView.setUint16(12, nameBytes.byteLength, false);
  header[14] = includeHash ? 0x01 : 0x00;
  const total = header.byteLength + salt.byteLength + iv.byteLength +
                nameBytes.byteLength + hashBytes.byteLength + cipherArr.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  const write = a => { out.set(a, off); off += a.byteLength; };
  write(header); write(salt); write(iv); write(nameBytes); write(hashBytes); write(cipherArr);
  return out.buffer;
}

function parsePackage(buffer) {
  const bytes = new Uint8Array(buffer);
  const view  = new DataView(buffer);
  if (bytes[0]!==0x56||bytes[1]!==0x4C||bytes[2]!==0x54||bytes[3]!==0x45)
    throw new Error('Invalid magic');
  if (bytes[4] !== 0x01) throw new Error('Unsupported version');
  const algoId     = bytes[5];
  const saltLen    = bytes[6];
  const ivLen      = bytes[7];
  const iterations = view.getUint32(8, false);
  const nameLen    = view.getUint16(12, false);
  const hasHash    = bytes[14] === 0x01;
  let off = 15;
  const salt      = bytes.slice(off, off + saltLen); off += saltLen;
  const iv        = bytes.slice(off, off + ivLen);   off += ivLen;
  const nameBytes = bytes.slice(off, off + nameLen); off += nameLen;
  const originalName = new TextDecoder().decode(nameBytes);
  let embeddedHash = null;
  if (hasHash) { embeddedHash = uint8ArrayToHex(bytes.slice(off, off + 32)); off += 32; }
  return { algoId, saltLen, ivLen, iterations, originalName, embeddedHash, ciphertext: buffer.slice(off), salt, iv };
}

// ── TEST HELPERS ──────────────────────────────────────────────────────

let passed = 0, failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌  ${name}`);
    console.error(`       ${err.message}`);
    failed++;
  }
}

// ── TEST SUITES ───────────────────────────────────────────────────────

async function runTests() {
  console.log('\n══════════════════════════════════════');
  console.log('  VaultShare Cryptographic Test Suite');
  console.log('══════════════════════════════════════\n');

  // ── SHA-256 ──
  console.log('SHA-256 Hash');
  await test('empty buffer produces known hash', async () => {
    const hash = await sha256Hex(new ArrayBuffer(0));
    assert.equal(hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  await test('same input always gives same hash', async () => {
    const buf = new TextEncoder().encode('VaultShare test').buffer;
    assert.equal(await sha256Hex(buf), await sha256Hex(buf));
  });

  await test('different inputs give different hashes', async () => {
    const a = await sha256Hex(new TextEncoder().encode('hello').buffer);
    const b = await sha256Hex(new TextEncoder().encode('world').buffer);
    assert.notEqual(a, b);
  });

  // ── KEY DERIVATION ──
  console.log('\nKey Derivation (PBKDF2)');
  await test('derives a key without throwing', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key  = await deriveKey('password123', salt, 10000, 'AES-GCM');
    assert.ok(key);
  });

  await test('same password + salt = same key (deterministic)', async () => {
    const salt = new Uint8Array(32).fill(0xab);
    const k1   = await deriveKey('samepass', salt, 10000, 'AES-GCM');
    const k2   = await deriveKey('samepass', salt, 10000, 'AES-GCM');
    // Keys are non-extractable; we verify by encrypting with k1 and decrypting with k2
    const iv   = new Uint8Array(12);
    const plain = new TextEncoder().encode('deterministic');
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k1, plain);
    const dt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct);
    assert.equal(new TextDecoder().decode(dt), 'deterministic');
  });

  await test('different passwords produce different keys', async () => {
    const salt  = new Uint8Array(32).fill(0x01);
    const iv    = new Uint8Array(12);
    const plain = new TextEncoder().encode('test data');
    const k1    = await deriveKey('password1', salt, 10000, 'AES-GCM');
    const k2    = await deriveKey('password2', salt, 10000, 'AES-GCM');
    const ct    = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k1, plain);
    await assert.rejects(
      () => crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k2, ct),
      'Different password must fail to decrypt'
    );
  });

  // ── AES-GCM ROUND-TRIP ──
  console.log('\nAES-256-GCM Round-Trip');

  async function roundTripGCM(plainText, password, iterations = 10000) {
    const plain = new TextEncoder().encode(plainText).buffer;
    const salt  = crypto.getRandomValues(new Uint8Array(32));
    const iv    = crypto.getRandomValues(new Uint8Array(12));
    const key   = await deriveKey(password, salt, iterations, 'AES-GCM');
    const ct    = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
    const key2  = await deriveKey(password, salt, iterations, 'AES-GCM');
    const dt    = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct);
    return new TextDecoder().decode(dt);
  }

  await test('short text encrypts and decrypts correctly', async () => {
    assert.equal(await roundTripGCM('Hello, World!', 'pass'), 'Hello, World!');
  });

  await test('unicode text round-trips correctly', async () => {
    const txt = '日本語テスト 🔐 αβγδ';
    assert.equal(await roundTripGCM(txt, 'unicodepass'), txt);
  });

  await test('1 KB of random data round-trips', async () => {
    const bytes  = crypto.getRandomValues(new Uint8Array(1024));
    const plain  = bytes.buffer;
    const salt   = crypto.getRandomValues(new Uint8Array(32));
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const key    = await deriveKey('testpass', salt, 10000, 'AES-GCM');
    const ct     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
    const key2   = await deriveKey('testpass', salt, 10000, 'AES-GCM');
    const decBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct);
    assert.deepEqual(new Uint8Array(decBuf), bytes);
  });

  await test('GCM detects tampering (authentication tag)', async () => {
    const plain = new TextEncoder().encode('authenticated').buffer;
    const salt  = crypto.getRandomValues(new Uint8Array(32));
    const iv    = crypto.getRandomValues(new Uint8Array(12));
    const key   = await deriveKey('pass', salt, 10000, 'AES-GCM');
    const ct    = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
    ct[0] ^= 0xFF; // Corrupt one byte
    const key2 = await deriveKey('pass', salt, 10000, 'AES-GCM');
    await assert.rejects(
      () => crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct.buffer),
      'GCM must reject tampered ciphertext'
    );
  });

  // ── AES-CBC ROUND-TRIP ──
  console.log('\nAES-256-CBC Round-Trip');
  await test('CBC encrypts and decrypts correctly', async () => {
    const plain = new TextEncoder().encode('CBC test data').buffer;
    const salt  = crypto.getRandomValues(new Uint8Array(32));
    const iv    = crypto.getRandomValues(new Uint8Array(16));
    const key   = await deriveKey('pass', salt, 10000, 'AES-CBC');
    const ct    = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, plain);
    const key2  = await deriveKey('pass', salt, 10000, 'AES-CBC');
    const dt    = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key2, ct);
    assert.equal(new TextDecoder().decode(dt), 'CBC test data');
  });

  // ── AES-CTR ROUND-TRIP ──
  console.log('\nAES-256-CTR Round-Trip');
  await test('CTR encrypts and decrypts correctly', async () => {
    const plain = new TextEncoder().encode('CTR test data').buffer;
    const salt  = crypto.getRandomValues(new Uint8Array(32));
    const iv    = crypto.getRandomValues(new Uint8Array(16));
    const key   = await deriveKey('pass', salt, 10000, 'AES-CTR');
    const ct    = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key, plain);
    const key2  = await deriveKey('pass', salt, 10000, 'AES-CTR');
    const dt    = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key2, ct);
    assert.equal(new TextDecoder().decode(dt), 'CTR test data');
  });

  // ── PACKAGE FORMAT ──
  console.log('\nBinary Package Format');
  await test('magic bytes are correct', () => {
    assert.deepEqual(Array.from(MAGIC), [0x56, 0x4C, 0x54, 0x45]);
  });

  await test('package builds and parses round-trip', async () => {
    const salt   = crypto.getRandomValues(new Uint8Array(32));
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const plain  = new TextEncoder().encode('package test').buffer;
    const key    = await deriveKey('pass', salt, 10000, 'AES-GCM');
    const ct     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
    const hashHex = await sha256Hex(plain);

    const pkg = buildPackage({
      algoId: 0, salt, iv,
      originalName: 'test-file.txt',
      hashHex, includeHash: true,
      ciphertext: ct, iterations: 10000,
    });

    const parsed = parsePackage(pkg);
    assert.equal(parsed.originalName, 'test-file.txt');
    assert.equal(parsed.algoId, 0);
    assert.equal(parsed.iterations, 10000);
    assert.equal(parsed.embeddedHash, hashHex);
    assert.equal(parsed.saltLen, 32);
    assert.equal(parsed.ivLen, 12);
  });

  await test('package without hash parses correctly', async () => {
    const salt = new Uint8Array(16);
    const iv   = new Uint8Array(12);
    const ct   = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]).buffer;

    const pkg = buildPackage({
      algoId: 0, salt, iv,
      originalName: 'no-hash.bin',
      hashHex: '', includeHash: false,
      ciphertext: ct, iterations: 100000,
    });

    const parsed = parsePackage(pkg);
    assert.equal(parsed.embeddedHash, null);
    assert.equal(parsed.originalName, 'no-hash.bin');
  });

  await test('invalid magic bytes throw an error', () => {
    const bad = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x01]).buffer;
    assert.throws(() => parsePackage(bad), /Invalid magic/);
  });

  await test('filename with unicode survives round-trip', async () => {
    const salt = new Uint8Array(32);
    const iv   = new Uint8Array(12);
    const ct   = new Uint8Array([1,2,3]).buffer;
    const name = '日本語ファイル 🔐.pdf';

    const pkg    = buildPackage({ algoId: 0, salt, iv, originalName: name, hashHex: '', includeHash: false, ciphertext: ct, iterations: 10000 });
    const parsed = parsePackage(pkg);
    assert.equal(parsed.originalName, name);
  });

  // ── IV UNIQUENESS ──
  console.log('\nIV Uniqueness');
  await test('two encryptions of the same file produce different ciphertexts', async () => {
    const plain = new TextEncoder().encode('same data').buffer;
    const salt  = new Uint8Array(32).fill(0x42);
    const key   = await deriveKey('pass', salt, 10000, 'AES-GCM');

    const iv1 = crypto.getRandomValues(new Uint8Array(12));
    const iv2 = crypto.getRandomValues(new Uint8Array(12));
    const ct1 = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv1 }, key, plain));
    const ct2 = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv2 }, key, plain));

    // IVs should be different (with overwhelming probability)
    assert.notDeepEqual(ct1, ct2);
  });

  // ── SUMMARY ──
  console.log('\n══════════════════════════════════════');
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log('══════════════════════════════════════\n');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
