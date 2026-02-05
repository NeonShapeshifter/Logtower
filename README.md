# Logtower

**Portable threat hunting & forensic triage platform for Windows event logs.**

Logtower combines a high-performance Rust parser with 1,033+ detection rules and automated threat intelligence to provide SOC analysts with fast, offline incident response capabilities. Validated against real APT samples (Mimikatz, Babyshark) and exploitation frameworks (WinPwnage).

## 🎯 Quick Demo

**Detecting real malware in action:**
```bash
# Install
npm install -g @neonshapeshifter/logtower

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

**Validated against:**
- ✅ EVTX-ATTACK-SAMPLES (Mimikatz, Babyshark APT)
- ✅ WinPwnage exploitation framework
- ✅ Real-world lateral movement techniques

![Logtower TUI - Mimikatz Detection](docs/screenshots/tui-mimikatz.png)
*Interactive 4-panel TUI showing credential dumping detection*

## Key Features

### 🔍 1,033+ Detection Rules
Curated from SIGMA, Elastic, and community sources:
- **LOLBAS Abuse**: 30+ rules (PowerShell, certutil, rundll32, mshta)
- **Lateral Movement**: Detection of PSExec, WMI, RDP abuse
- **Credential Access**: LSASS dumping, Mimikatz, DCSync
- **Persistence**: Registry keys, scheduled tasks, WMI events
- **Defense Evasion**: Timestomping, process hollowing, masquerading

### 🛡️ Embedded IR Playbooks
Every critical detection includes step-by-step response guidance:
- Containment procedures
- Evidence collection steps
- MITRE ATT&CK mappings
- Remediation guidance

**Example:** Golden Ticket Detection
```
[CRITICAL] Golden Ticket Usage (T1558.001)

RESPONSE PROTOCOL:
1. ISOLATE: Disconnect all Domain Controllers
2. RESET: Change KRBTGT password (twice)
3. WAIT: Force replication across DCs
4. VERIFY: Check for additional persistence
```

### 🧠 Threat Intelligence Integration
Automated IOC validation:
- **URLhaus**: Malicious URL detection
- **Tor Project**: Exit node identification
- **AbuseIPDB**: IP reputation checks
- **Local Feeds**: Custom IOC lists

Smart escalation: Unknown IOCs maintain baseline severity, confirmed threats escalate to CRITICAL with context.

### 🖥️ Dual-Mode Architecture

**Interactive TUI (Analyst Workflow):**
- 4-panel layout: Event Stream, Findings, Inspector, Report
- Real-time severity counters
- Forensic context (process chains, access masks, timelines)
- Keyboard navigation

**Headless CLI (Automation/CI-CD):**
- JSON output for SOAR integration
- Scriptable workflows
- Batch processing
- Pipeline-ready

### ⚡ High Performance
- **Rust Parser**: 1GB EVTX in ~18 seconds
- **Rule Engine**: 1,033 rules evaluated in <50ms per event
- **Streaming Architecture**: Low memory footprint on large datasets
- **Production Tested**: Validated against APT samples

## ✅ Real-World Validation

Logtower has been tested against public APT samples and exploitation frameworks:

### Detected Attacks

| Sample | Techniques Detected | Findings |
|--------|-------------------|----------|
| **Babyshark APT + Mimikatz** | LSASS dumping (T1003.001), Process injection (T1055) | 15 findings (5 CRITICAL) |
| **WinPwnage Framework** | UAC bypass (T1548.002), Rundll32 abuse | 11 findings (4 CRITICAL) |
| **Lateral Movement Samples** | PSExec, WMI, Pass-the-Hash | Multiple detections |

### Example: Credential Dumping Detection

**Input:** `babyshark_mimikatz_powershell.evtx` (22 events)

**Detections:**
- LSASS Memory Dumping (Mimikatz signature)
- PowerShell accessing LSASS (access mask 0x1010)
- Unknown process touching LSASS
- Suspicious parent-child relationships

**Inspector Output:**
```
[PROCESS INJECTION / ACCESS]
Source: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Target: C:\Windows\system32\lsass.exe
Access: 0x1010 (PROCESS_VM_READ)

[EVIDENCE TIMELINE]
- [16:58:14] Event ID 10 - Process Access
- [17:01:35] Event ID 10 - Process Access

Use 'info CRED_006_LSASS_DUMP' for response protocol.
```

## Installation

### Quick Install (Recommended)
```bash
npm install -g @neonshapeshifter/logtower
```

Verify installation:
```bash
logtower --version
```

### From Source (Development)

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Usage

### Interactive TUI Mode

Launch the visual interface for real-time hunting:
```bash
logtower
# or specify file
logtower hunt malicious.evtx
```

**Controls:**
- `↑/↓`: Navigate findings
- `Enter`: View details
- `Tab`: Switch panels
- `f`: Filter by severity
- `s`: Summary view
- `q/ESC`: Exit/Back

### Headless CLI Mode (Production)

**Quick scan:**
```bash
logtower hunt logs/ --summary
```

**JSON output for automation:**
```bash
logtower hunt logs/ --json > findings.json
```

**Specific ruleset:**
```bash
logtower hunt logs/ --ruleset lolbas
# Options: lolbas, lateral, cred, persistence, all
```

**With threat intelligence:**
```bash
logtower hunt logs/ --intel --json
```

### Rule Catalog

Browse all 1,033 detection rules:
```bash
logtower info              # List all rules
logtower info golden       # Search for specific rules
logtower info CRED_001     # View detailed playbook
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
