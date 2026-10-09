/**
 * VaultShare — crypto.js
 * =====================================================================
 * All cryptographic operations using the browser's native Web Crypto API.
 * No external dependencies. No server communication.
 *
 * Supported algorithms: AES-256-GCM, AES-256-CBC, AES-256-CTR
 * Key derivation: PBKDF2-SHA256
 * Integrity: SHA-256
 * Package format: Custom binary (.vaultenc)
 * =====================================================================
 */

'use strict';

// ── CONSTANTS ──────────────────────────────────────────────────────────
const MAGIC       = new Uint8Array([0x56, 0x4C, 0x54, 0x45]); // "VLTE"
const FORMAT_VER  = 0x01;

/** Maps short key → WebCrypto algorithm name */
const ALGO_MAP = {
  gcm: 'AES-GCM',
  cbc: 'AES-CBC',
  ctr: 'AES-CTR',
};

/** Maps short key → header byte ID */
const ALGO_IDS = { gcm: 0, cbc: 1, ctr: 2 };

/** Maps header byte → WebCrypto algorithm name */
const ID_TO_ALGO = ['AES-GCM', 'AES-CBC', 'AES-CTR'];

/** IV length per algorithm */
const IV_LEN = {
  'AES-GCM': 12,
  'AES-CBC': 16,
  'AES-CTR': 16,
};

// ── KEY DERIVATION ─────────────────────────────────────────────────────

/**
 * Derives a 256-bit AES key from a password using PBKDF2-SHA256.
 *
 * @param {string}     password   - User-supplied passphrase
 * @param {Uint8Array} salt       - Random salt (128 or 256 bit)
 * @param {number}     iterations - PBKDF2 iteration count
 * @param {string}     algoName   - e.g. 'AES-GCM'
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt, iterations, algoName) {
  const enc = new TextEncoder();

  // Import raw password bytes as PBKDF2 key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive a non-extractable AES key
  return crypto.subtle.deriveKey(
    {
      name:       'PBKDF2',
      salt:       salt,
      iterations: iterations,
      hash:       'SHA-256',
    },
    keyMaterial,
    { name: algoName, length: 256 },
    false,                            // not extractable
    ['encrypt', 'decrypt']
  );
}

// ── ALGORITHM PARAMS ───────────────────────────────────────────────────

/**
 * Builds the algorithm parameter object for SubtleCrypto encrypt/decrypt.
 *
 * @param {string}     algoName
 * @param {Uint8Array} iv
 * @returns {object}
 */
function buildAlgoParams(algoName, iv) {
  switch (algoName) {
    case 'AES-GCM': return { name: 'AES-GCM', iv };
    case 'AES-CBC': return { name: 'AES-CBC', iv };
    case 'AES-CTR': return { name: 'AES-CTR', counter: iv, length: 128 };
    default:        throw new Error(`Unknown algorithm: ${algoName}`);
  }
}

// ── SHA-256 ────────────────────────────────────────────────────────────

/**
 * Computes a hex-encoded SHA-256 hash of an ArrayBuffer.
 *
 * @param {ArrayBuffer} buffer
 * @returns {Promise<string>} 64-character hex string
 */
async function sha256Hex(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return uint8ArrayToHex(new Uint8Array(hashBuffer));
}

// ── BINARY HELPERS ─────────────────────────────────────────────────────

/** @param {Uint8Array} bytes @returns {string} */
function uint8ArrayToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** @param {string} hex @returns {Uint8Array} */
function hexToUint8Array(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

// ── PACKAGE FORMAT ─────────────────────────────────────────────────────

/**
 * Binary .vaultenc package layout (all multi-byte fields: big-endian):
 *
 * HEADER (15 bytes):
 *   [0-3]  magic      = 0x56 0x4C 0x54 0x45  ("VLTE")
 *   [4]    version    = 0x01
 *   [5]    algoId     = 0=GCM 1=CBC 2=CTR
 *   [6]    saltLen    = 16 or 32
 *   [7]    ivLen      = 12 or 16
 *   [8-11] iterations = uint32 big-endian
 *   [12-13] nameLen   = uint16 big-endian
 *   [14]   hasHash    = 0x00 or 0x01
 *
 * BODY:
 *   salt       = saltLen bytes
 *   iv         = ivLen bytes
 *   name       = nameLen bytes (UTF-8)
 *   sha256     = 32 bytes  (only if hasHash === 0x01)
 *   ciphertext = variable
 */

/**
 * Serialises all components into a .vaultenc binary ArrayBuffer.
 */
function buildPackage({
  algoId, salt, iv, originalName,
  hashHex, includeHash, ciphertext, iterations,
}) {
  const nameBytes  = new TextEncoder().encode(originalName);
  const hashBytes  = includeHash ? hexToUint8Array(hashHex) : new Uint8Array(0);
  const cipherArr  = new Uint8Array(ciphertext);

  // Build 15-byte header
  const header = new Uint8Array(15);
  const hView  = new DataView(header.buffer);
  header.set(MAGIC, 0);
  header[4]  = FORMAT_VER;
  header[5]  = algoId;
  header[6]  = salt.byteLength;
  header[7]  = iv.byteLength;
  hView.setUint32(8, iterations, false);   // big-endian
  hView.setUint16(12, nameBytes.byteLength, false);
  header[14] = includeHash ? 0x01 : 0x00;

  // Concatenate all sections
  const totalLen = (
    header.byteLength +
    salt.byteLength +
    iv.byteLength +
    nameBytes.byteLength +
    hashBytes.byteLength +
    cipherArr.byteLength
  );

  const out = new Uint8Array(totalLen);
  let offset = 0;
  const write = arr => { out.set(arr, offset); offset += arr.byteLength; };

  write(header);
  write(salt);
  write(iv);
  write(nameBytes);
  write(hashBytes);
  write(cipherArr);

  return out.buffer;
}

/**
 * Parses a .vaultenc binary ArrayBuffer.
 *
 * @param   {ArrayBuffer} buffer
 * @returns {object} Parsed package fields
 * @throws  {Error}   On malformed magic, unsupported version, etc.
 */
function parsePackage(buffer) {
  const bytes = new Uint8Array(buffer);
  const view  = new DataView(buffer);

  // Validate magic
  if (bytes[0] !== 0x56 || bytes[1] !== 0x4C ||
      bytes[2] !== 0x54 || bytes[3] !== 0x45) {
    throw new Error('Invalid file: not a VaultShare package (.vaultenc)');
  }

  const version = bytes[4];
  if (version !== 0x01) {
    throw new Error(`Unsupported package version: 0x${version.toString(16)}`);
  }

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
  if (hasHash) {
    embeddedHash = uint8ArrayToHex(bytes.slice(off, off + 32));
    off += 32;
  }

  const ciphertext = buffer.slice(off);

  return {
    algoId, saltLen, ivLen, iterations,
    originalName, embeddedHash,
    ciphertext, salt, iv,
  };
}

// ── PUBLIC API ─────────────────────────────────────────────────────────

/**
 * Encrypts a file and returns a .vaultenc package buffer.
 *
 * @param {object} opts
 * @param {ArrayBuffer} opts.plainBuffer     - File bytes to encrypt
 * @param {string}      opts.password        - Encryption password
 * @param {string}      opts.algoKey         - 'gcm' | 'cbc' | 'ctr'
 * @param {number}      opts.iterations      - PBKDF2 iterations
 * @param {number}      opts.saltLen         - 16 or 32 bytes
 * @param {string}      opts.originalName    - Original filename
 * @param {boolean}     opts.includeHash     - Embed SHA-256?
 * @param {Function}    opts.onProgress      - (pct, label) => void
 * @returns {Promise<{ packageBuffer: ArrayBuffer, hashHex: string }>}
 */
async function encryptFileData(opts) {
  const {
    plainBuffer, password, algoKey,
    iterations, saltLen, originalName,
    includeHash, onProgress = () => {},
  } = opts;

  const algoName = ALGO_MAP[algoKey];
  if (!algoName) throw new Error(`Unknown algorithm key: ${algoKey}`);

  onProgress(10, 'Computing SHA-256 hash…');
  const hashHex = await sha256Hex(plainBuffer);

  onProgress(30, 'Generating cryptographic salt & IV…');
  const salt  = crypto.getRandomValues(new Uint8Array(saltLen));
  const iv    = crypto.getRandomValues(new Uint8Array(IV_LEN[algoName]));

  onProgress(50, `Deriving 256-bit key via PBKDF2 (${iterations.toLocaleString()} iterations)…`);
  const key = await deriveKey(password, salt, iterations, algoName);

  onProgress(75, `Encrypting with ${algoName}…`);
  const params     = buildAlgoParams(algoName, iv);
  const ciphertext = await crypto.subtle.encrypt(params, key, plainBuffer);

  onProgress(92, 'Building .vaultenc package…');
  const packageBuffer = buildPackage({
    algoId: ALGO_IDS[algoKey],
    salt, iv, originalName, hashHex,
    includeHash, ciphertext, iterations,
  });

  onProgress(100, 'Done!');
  return { packageBuffer, hashHex };
}

/**
 * Decrypts a .vaultenc package and returns the plaintext buffer.
 *
 * @param {object} opts
 * @param {ArrayBuffer} opts.packageBuffer   - Encrypted .vaultenc bytes
 * @param {string}      opts.password        - Decryption password
 * @param {boolean}     opts.verifyHash      - Verify embedded SHA-256?
 * @param {Function}    opts.onProgress      - (pct, label) => void
 * @returns {Promise<{ plainBuffer: ArrayBuffer, meta: object, computedHash: string }>}
 */
async function decryptFileData(opts) {
  const {
    packageBuffer, password,
    verifyHash = true,
    onProgress = () => {},
  } = opts;

  onProgress(10, 'Parsing package header…');
  const pkg = parsePackage(packageBuffer);

  const algoName = ID_TO_ALGO[pkg.algoId];
  if (!algoName) throw new Error(`Unknown algorithm ID in package: ${pkg.algoId}`);

  onProgress(30, `Deriving key via PBKDF2 (${pkg.iterations.toLocaleString()} iterations)…`);
  const key = await deriveKey(password, pkg.salt, pkg.iterations, algoName);

  onProgress(60, `Decrypting with ${algoName}…`);
  let plainBuffer;
  try {
    const params = buildAlgoParams(algoName, pkg.iv);
    plainBuffer  = await crypto.subtle.decrypt(params, key, pkg.ciphertext);
  } catch {
    throw new Error('Decryption failed — wrong password or corrupted file.');
  }

  onProgress(85, 'Verifying file integrity…');
  const computedHash = await sha256Hex(plainBuffer);

  if (verifyHash && pkg.embeddedHash) {
    if (computedHash !== pkg.embeddedHash) {
      throw new Error(
        'Integrity check FAILED — SHA-256 hash mismatch. ' +
        'The file may be corrupted or tampered with.'
      );
    }
  }

  onProgress(100, 'Done!');

  return {
    plainBuffer,
    computedHash,
    meta: {
      originalName:  pkg.originalName,
      algorithm:     algoName,
      iterations:    pkg.iterations,
      saltBits:      pkg.saltLen * 8,
      embeddedHash:  pkg.embeddedHash,
      hashVerified:  verifyHash && !!pkg.embeddedHash,
    },
  };
}

/**
 * Computes the SHA-256 hash of a file's ArrayBuffer.
 *
 * @param {ArrayBuffer} buffer
 * @returns {Promise<string>} hex string
 */
async function hashFile(buffer) {
  return sha256Hex(buffer);
}
