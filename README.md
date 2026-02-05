# Logtower

> **Portable threat hunting platform with 1,033+ detection rules.**
> Detect Mimikatz, LOLBAS abuse, and lateral movement in EVTX logs in seconds.

**Quick start:** `npm install -g @neonshapeshifter/logtower`

---

## 🎯 Quick Demo

**Detecting real malware in action:**
```bash
# Detect Mimikatz credential dumping
logtower hunt mimikatz.evtx --summary
```

**Output:**
```
=== Execution Summary ===
Processed Events: 22
Total Findings: 15

[Severity Breakdown]
  CRITICAL: 5
  HIGH: 4
  MEDIUM: 4
  LOW: 2

[Top Detections]
  [CRITICAL] LSASS Memory Dumping (Mimikatz/ProcDump) (2)
  [CRITICAL] PowerShell Accessing LSASS (2)
  [CRITICAL] Mimikatz Specific Access Mask (2)
```

![Logtower TUI](https://github.com/user-attachments/assets/e26090e2-3812-4f02-baff-65e9efaad3d0)
*5-panel interactive interface: Event Stream (left),Log detail, Critical Findings, Detection Report and Deep Inspector (right)*

## ✅ Validated Against Real Threats

Logtower has been tested against public APT samples and exploitation frameworks:

- ✅ **EVTX-ATTACK-SAMPLES** (Mimikatz, Babyshark APT, DeepBlueMagic)
- ✅ **WinPwnage** exploitation framework
- ✅ **Real-world** lateral movement techniques (PsExec, WMI, DCOM)

## Key Features

### 🔍 1,033+ Detection Rules
Massive library curated from SIGMA, Elastic, and community research:
*   **LOLBAS Abuse**: `certutil`, `rundll32`, `mshta`, `powershell` abuse.
*   **Lateral Movement**: PSExec pipes, WMI consumers, RDP tunneling.
*   **Credential Access**: LSASS dumping, DCSync, Kerberoasting (RC4/AS-REP).
*   **Persistence**: Registry run keys, Scheduled Tasks, WMI Subscriptions.
*   **Defense Evasion**: Timestomping, Process Hollowing, Masquerading.

### 🛡️ Embedded IR Playbooks
Don't just detect—respond. Every finding includes a tactical playbook:
*   **Context**: What is happening? (e.g., "Golden Ticket Usage").
*   **Response**: Step-by-step containment (Isolate, Reset KRBTGT, etc.).
*   **MITRE**: Tactic and Technique mapping.

### 🧠 Threat Intelligence
Automated IOC enrichment using local and online feeds:
*   **URLhaus**: Malicious URL detection.
*   **Tor Project**: Exit node identification.
*   **AbuseIPDB**: IP reputation checks.

### ⚡ Dual-Mode Architecture

| **Interactive TUI** | **Headless CLI** |
| :--- | :--- |
| For **human analysts**. | For **robots & CI/CD**. |
| Real-time 4-panel dashboard. | JSON output for SOAR. |
| Keyboard navigation (`↑`, `↓`, `Tab`). | Scriptable pipelines. |
| Deep inspection of raw events. | Batch processing. |

## Installation

### Quick Install (Recommended)
```bash
npm install -g @neonshapeshifter/logtower
```

Verify installation:
```bash
logtower --version
# Output: 1.0.0
```

### From Source (Development)
See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions (Rust + Node.js).

## Usage

### Interactive Mode
Launch the TUI on a file:
```bash
logtower hunt evidence.evtx
```

**Controls:**
*   `↑ / ↓`: Navigate findings list.
*   `Enter`: View details.
*   `Tab`: Toggle between panels.
*   `f`: Cycle severity filters (ALL -> CRIT -> HIGH).
*   `s`: Show summary stats.
*   `q` / `ESC`: Back / Exit.

### Headless Mode
Scan a folder and output JSON for your SIEM:
```bash
logtower hunt ./logs/ --json > alerts.json
```

Use a specific ruleset (e.g., only lateral movement):
```bash
logtower hunt ./logs/ --ruleset lateral
```

### Rule Catalog
Explore the database of 1,033+ attacks:
```bash
logtower info              # List all rules
logtower info golden       # Search for "golden ticket"
logtower info CRED_001     # View specific playbook
```

## Project Structure

*   **`packages/parser-rust`**: High-performance EVTX parser.
*   **`packages/engine`**: Detection logic & state tracking.
*   **`packages/rules`**: The 1,033+ detection rules.
*   **`packages/cli`**: The TUI and CLI wrapper.

---
*Built for hunters, by hunters.*
