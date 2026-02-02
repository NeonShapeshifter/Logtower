# Logtower

**Portable Threat Hunting & Forensic Triage Suite.**

Logtower is a high-performance tool designed for rapid forensic triage and threat hunting on Windows Event Logs (EVTX). It combines a fast Rust-based parsing engine with a flexible TypeScript detection logic and an interactive Terminal User Interface (TUI).

## Key Features

*   **🚀 High Performance**: Rust-based EVTX parser (`parser-rust`) processes gigabytes of logs in seconds.
*   **🖥️ Interactive TUI**: Navigate findings, rules, and graphs directly in your terminal.
*   **🤖 Headless Mode**: Scriptable CLI for automated triage, CI/CD pipelines, or reporting.
*   **🛡️ Detection Rules**: Built-in SIGMA-inspired rulesets (LOLBAS, Lateral Movement, Persistence, Credential Access).
*   **🧠 Threat Intel**: Automatic enrichment using local feeds (IPs, Tor Exits, Hashes).
*   **📦 Portable**: Self-contained build; no external runtime dependencies once compiled.

## Installation

### 🚀 Quick Install (The Fancy Way)
Install Logtower globally via NPM to start hunting immediately:

```bash
npm install -g @neonshapeshifter/logtower
```

Once installed, you can run it from anywhere:
```bash
logtower
```

---

### 🛠️ Developer Setup (Build from Source)
If you want to contribute or modify the code:

1.  **Prerequisites**:
    *   Node.js (v18+)
    *   Rust (Cargo) - *Required for high-performance parsing*

2.  **Clone & Build**:
    ```bash
    git clone https://github.com/neonshapeshifter/logtower.git
    cd logtower
    npm install
    npm run build:all
    ```

3.  **Link Locally**:
    ```bash
    cd packages/cli
    npm link
    ```

## Usage

### Interactive Mode (TUI)
Simply run the command without arguments to launch the dashboard:

```bash
logtower
```

### Headless Mode (CLI)
Run automated hunts against specific files:

```bash
# Basic scan (Default: LOLBAS rules, Important findings)
logtower hunt ./evidence/Security.evtx

# Generate a report file
logtower hunt ./evidence/Security.evtx --report

# Output machine-readable JSON (for piping to jq or other tools)
logtower hunt ./evidence/Security.evtx --json

# Use a specific ruleset (options: lolbas, lateral, cred, persistence, all)
logtower hunt ./evidence/Security.evtx --ruleset lateral
```

## Project Structure

This is a **monorepo** managing the following packages:

*   **`packages/parser-rust`**: The core EVTX parsing engine (Rust).
*   **`packages/engine`**: The detection logic, matcher, and state tracking (TypeScript).
*   **`packages/rules`**: Library of detection rules.
*   **`packages/core`**: Shared schemas and types.
*   **`packages/cli`**: The product interface (TUI + CLI wrapper).

## Development

*   **`npm run test`**: Run unit tests.
*   **`npm run test:smoke`**: Run integration smoke tests against samples.