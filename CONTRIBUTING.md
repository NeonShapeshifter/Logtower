# Contributing to Logtower

We welcome contributions! Logtower is a monorepo managed with npm workspaces.

## Prerequisites

*   **Node.js**: v18.0.0 or higher.
*   **Rust**: Latest stable toolchain (install via [rustup.rs](https://rustup.rs)).

## Project Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-org/logtower.git
    cd logtower
    ```

2.  **Install Node dependencies:**
    ```bash
    npm install
    ```

3.  **Build the project (Rust + TypeScript):**
    This command compiles the Rust parser and builds all TypeScript packages.
    ```bash
    npm run build:all
    ```
    *Note: The first build might take a minute to compile Rust dependencies.*

## Development Workflow

### Structure
*   `packages/parser-rust`: The Rust source code.
*   `packages/rules`: Where detection rules live.
*   `packages/engine`: The detection logic core.
*   **`packages/cli`**: The entry point and UI.

### Adding a New Rule
Rules are written in TypeScript in `packages/rules/src`.

1.  Create a file (e.g., `packages/rules/src/my_new_rule.ts`).
2.  Define the rule using the `Rule` interface:
    ```typescript
    import { Rule } from '@neonshapeshifter/logtower-engine';

    export const MY_RULE: Rule = {
        id: 'CUSTOM_001',
        title: 'Suspicious Cmd Usage',
        severity: 'HIGH',
        module: 'custom',
        description: 'Detects cmd.exe being used in a weird way.',
        detection: {
            selection: {
                'process.image': '*\\cmd.exe',
                'process.command_line': ['* /c powershell *', '* /k *']
            }
        }
    };
    ```
3.  Export it in `packages/rules/src/index.ts`.
4.  Rebuild: `npm run build` (or just `npm run build --workspace=@neonshapeshifter/logtower-rules`).

### Testing
*   **Unit Tests:** `npm run test`
*   **Smoke Tests:** `npm run test:smoke` (Runs the full pipeline against sample data).

## Building for Release
To create a portable build (including the binary):
```bash
npm run build:all
```
This ensures the Rust binary is copied to `packages/cli/bin/`, making the CLI package self-contained.

