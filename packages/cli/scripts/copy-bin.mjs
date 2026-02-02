import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO_ROOT = path.resolve(__dirname, '../../..');
const SRC_BINARY = path.join(REPO_ROOT, 'packages/parser-rust/target/release/logtower-parser');
const DEST_DIR = path.join(__dirname, '../bin');
const DEST_BINARY = path.join(DEST_DIR, 'logtower-parser');

console.log(`[Bundle] Looking for Rust binary at: ${SRC_BINARY}`);

if (fs.existsSync(SRC_BINARY)) {
    if (!fs.existsSync(DEST_DIR)) {
        fs.mkdirSync(DEST_DIR, { recursive: true });
    }
    fs.copyFileSync(SRC_BINARY, DEST_BINARY);
    // Ensure executable permissions
    fs.chmodSync(DEST_BINARY, '755');
    console.log(`[Bundle] Copied binary to: ${DEST_BINARY}`);
} else {
    console.warn(`[Bundle] Rust binary not found at ${SRC_BINARY}.`);
    console.warn(`[Bundle] Skipping copy. Ensure you run 'npm run build:rust' before packaging.`);
}
