
import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CLI_PATH = path.resolve(__dirname, '../packages/cli/dist/index.js');

const args = process.argv.slice(2).join(' ');
try {
  // We call the CLI directly. We must ensure it is built.
  const output = execSync(`node ${CLI_PATH} hunt ${args}`, { encoding: 'utf-8', stdio: ['inherit', 'pipe', 'pipe'] });
  console.log(output);
} catch (e) {
  // Silent fail or log error
  if (e.stdout) console.log(e.stdout);
  if (e.stderr) console.error(e.stderr);
  process.exit(1);
}
