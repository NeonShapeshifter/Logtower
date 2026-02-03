import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function resolveParserBinary(): string {
    // 1. Production: Bundled binary in ../bin/ (relative to dist/utils.js)
    // dist/utils.js -> ../bin -> bin/
    const prodBinDir = path.resolve(__dirname, '../bin');
    const prodBin = path.join(prodBinDir, process.platform === 'win32' ? 'logtower-parser.exe' : 'logtower-parser');

    if (fs.existsSync(prodBin)) {
        return prodBin;
    }

    // 2. Development: Monorepo structure
    // packages/cli/dist/utils.js -> ../../../ -> monorepo root
    const repoRoot = path.resolve(__dirname, '../../..');
    const devBin = path.join(repoRoot, 'packages/parser-rust/target/release/logtower-parser');
    const devBinWin = path.join(repoRoot, 'packages/parser-rust/target/release/logtower-parser.exe');

    if (process.platform === 'win32' && fs.existsSync(devBinWin)) return devBinWin;
    if (fs.existsSync(devBin)) return devBin;

    // 3. Debug fallback
    const debugBin = path.join(repoRoot, 'packages/parser-rust/target/debug/logtower-parser');
    const debugBinWin = path.join(repoRoot, 'packages/parser-rust/target/debug/logtower-parser.exe');

    if (process.platform === 'win32' && fs.existsSync(debugBinWin)) return debugBinWin;
    if (fs.existsSync(debugBin)) return debugBin;

    throw new Error(
        `Logtower Parser Binary not found.\nExpected at: ${prodBin}\nOr dev path: ${devBin}`
    );
}
