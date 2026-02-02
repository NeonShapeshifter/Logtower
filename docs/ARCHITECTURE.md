# Logtower Architecture

Logtower uses a **Hybrid Architecture** combining Rust for high-performance I/O and parsing, and Node.js/TypeScript for flexible detection logic and UI.

```mermaid
graph TD
    User[User / CI] -->|Runs Command| CLI[Logtower CLI (Node.js)]
    CLI -->|Spawns Subprocess| Rust[Parser Binary (Rust)]
    
    subgraph "High Performance Zone"
    Rust -->|Reads| EVTX[EVTX File]
    Rust -->|Streams JSONL| Stdout[Standard Output]
    end
    
    subgraph "Detection Engine (Node.js)"
    Stdout -->|Pipe| Stream[Input Stream]
    Stream -->|Normalize| Norm[Event Normalizer]
    Norm -->|Event Object| Matcher[Rule Matcher]
    Rules[Rule Library] -->|Load| Matcher
    Intel[Intel Feeds] -->|Enrich| Matcher
    Matcher -->|Match Found| State[State Tracker]
    State -->|Confirmed| Findings[Findings Store]
    end
    
    Findings -->|Render| TUI[Interactive TUI (Ink)]
    Findings -->|Export| JSON[JSON Report]
```

## Core Components

### 1. The Parser (`packages/parser-rust`)
*   **Role:** Raw data ingestion.
*   **Tech:** Rust + `evtx` crate.
*   **Behavior:** Reads binary EVTX files, converts records to flat JSON objects, and prints them to `stdout` line-by-line. This avoids loading the entire file into memory, allowing processing of multi-gigabyte files with constant memory usage.

### 2. The CLI Wrapper (`packages/cli`)
*   **Role:** Orchestration and UI.
*   **Tech:** Node.js, Commander, Ink (React for Terminal).
*   **Behavior:**
    *   Locates the Rust binary (either bundled in `bin/` or in the dev build path).
    *   Spawns the parser as a child process.
    *   Reads `stdout` line-by-line.
    *   Handles user interaction via TUI.

### 3. The Engine (`packages/engine`)
*   **Role:** Detection Logic.
*   **Tech:** TypeScript.
*   **Components:**
    *   **Matcher:** Stateless rule evaluation (Regex/String matching).
    *   **Tracker:** Stateful logic (e.g., counting logons within a time window for "Brute Force" detection).
    *   **Intel:** Checks IPs/Hashes against loaded feeds.

### 4. Rules (`packages/rules`)
*   **Role:** Detection Content.
*   **Format:** TypeScript objects (inspired by Sigma).
*   **Structure:** Rules are compiled into the binary, ensuring zero-latency loading.

## Data Flow

1.  **Ingest:** `logtower-parser` reads EVTX chunks.
2.  **Stream:** JSON strings are sent to Node.js.
3.  **Normalize:** Raw fields (e.g., `Image`, `CommandLine`) are mapped to a standard schema (`process.image`, `process.command_line`).
4.  **Enrich:** Intel module checks if IPs/Domains are known bad.
5.  **Match:** The event is checked against active rulesets (e.g., `lolbas`).
6.  **Alert:** If a match occurs, a `Finding` object is created and stored/displayed.
