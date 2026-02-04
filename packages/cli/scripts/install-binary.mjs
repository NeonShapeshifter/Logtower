import fs from 'fs';
import path from 'path';
import https from 'https';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CONFIGURATION
// TODO: Replace with your actual GitHub User/Repo
const REPO = "NeonShapeshifter/Logtower";
const BIN_NAME = "logtower-parser";
const DEST_DIR = path.join(__dirname, '../bin');

// Detect Platform
const PLATFORM = process.platform;
const ARCH = process.arch;

// Set destination path with correct extension for Windows
const DEST_PATH = path.join(DEST_DIR, PLATFORM === 'win32' ? `${BIN_NAME}.exe` : BIN_NAME);

const SUPPORTED_PLATFORMS = {
    'win32': 'win-x64.exe',
    'linux': 'linux-x64',
    'darwin': 'macos-x64'
};

function getDownloadUrl(version) {
    const suffix = SUPPORTED_PLATFORMS[PLATFORM];
    if (!suffix) {
        throw new Error(`Unsupported platform: ${PLATFORM}`);
    }
    // Remove 'v' prefix if present for clean URL construction if needed, 
    // but GitHub releases usually use the tag name directly (e.g. v0.0.1)
    return `https://github.com/${REPO}/releases/download/${version}/logtower-parser-${suffix}`;
}

async function downloadBinary(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        https.get(url, (response) => {
            if (response.statusCode === 302 || response.statusCode === 301) {
                downloadBinary(response.headers.location, dest).then(resolve).catch(reject);
                return;
            }
            if (response.statusCode !== 200) {
                reject(new Error(`Failed to download: ${response.statusCode}`));
                return;
            }
            response.pipe(file);
            file.on('finish', () => {
                file.close(() => resolve());
            });
        }).on('error', (err) => {
            fs.unlink(dest, () => {});
            reject(err);
        });
    });
}

async function main() {
    // Ensure bin dir exists
    if (!fs.existsSync(DEST_DIR)) {
        fs.mkdirSync(DEST_DIR, { recursive: true });
    }

    // Check if we are in a dev environment (monorepo)
    // In dev, we prefer building from source or using the local target
    const rustTargetDir = path.resolve(__dirname, '../../../parser-rust/target/release');
    const localBin = path.join(rustTargetDir, PLATFORM === 'win32' ? 'logtower-parser.exe' : 'logtower-parser');

    if (fs.existsSync(localBin)) {
        console.log('[Install] Found local development binary. Copying...');
        fs.copyFileSync(localBin, DEST_PATH);
        fs.chmodSync(DEST_PATH, 0o755);
        return;
    }

    // If not in dev or local binary missing, try to download
    try {
        // Read version from package.json
        const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8'));
        const version = `v${packageJson.version}`; // Assumption: Release tag matches "v" + package version

        console.log(`[Install] Downloading binary for ${PLATFORM} (${version})...`);
        const url = getDownloadUrl(version);
        
        await downloadBinary(url, DEST_PATH);
        fs.chmodSync(DEST_PATH, 0o755);
        console.log('[Install] Binary downloaded successfully.');
    } catch (error) {
        console.warn(`[Install] Download failed: ${error.message}`);
        
        // Check if Rust source exists before trying to build
        const rustSourceDir = path.resolve(__dirname, '../../../parser-rust');
        const cargoToml = path.join(rustSourceDir, 'Cargo.toml');

        if (!fs.existsSync(cargoToml)) {
             console.error('[Install] CRITICAL: Pre-built binary not found and Rust source code is missing.');
             console.error('          This npm package does not include the Rust source code required to build from scratch.');
             console.error('          Please install from a cloned git repository or wait for a binary release.');
             process.exit(1);
        }

        console.warn('[Install] Falling back to cargo build...');
        
        try {
            // Attempt to build from source if cargo is available
            execSync('cargo build --release', { 
                cwd: rustSourceDir,
                stdio: 'inherit' 
            });
            // Try copy again
            if (fs.existsSync(localBin)) {
                fs.copyFileSync(localBin, DEST_PATH);
                fs.chmodSync(DEST_PATH, 0o755);
                console.log('[Install] Built from source successfully.');
            } else {
                 throw new Error("Build finished but binary not found.");
            }
        } catch (buildError) {
             console.error('[Install] CRITICAL: Could not download binary AND could not build from source.');
             console.error('Please ensure you have Rust installed or check your internet connection.');
             process.exit(1);
        }
    }
}

main();
