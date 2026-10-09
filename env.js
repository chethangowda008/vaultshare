/**
 * Loads variables from a local .env file (if present) BEFORE any other module
 * reads process.env. Imported first in server.js. Real environment variables
 * always win over the file. Uses Node's built-in loader (Node 20.12+/22).
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const envPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '.env');
if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
  try { process.loadEnvFile(envPath); } catch (e) { console.error('[env] Could not read .env:', e.message); }
}
