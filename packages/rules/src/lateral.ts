import { Rule } from '@neonshapeshifter/logtower-engine';

export const LATERAL_RULES: Rule[] = [
  {
    id: 'LATERAL_002_RDP_REMOTE',
    title: 'Remote RDP Logon (External)',
    severity: 'MEDIUM',
    module: 'LATERAL',
    mitre: ['T1021.001'],
    detection: {
      selection: {
        'event_id': '4624',
        'user.logon_type': '10',
        'network.src_ip': ['*', '!127.0.0.1', '!::1', '!-'],
        'user.name': ['!*$*', '!ANONYMOUS LOGON']
      }
    },
    description: "Detects incoming Remote Desktop (RDP) connections from external IPs (non-localhost). RDP is the #1 method for manual lateral movement.",
    response_steps: [
      "1. VERIFY: Confirm if the 'source' user was authorized to connect to this 'dest'.",
      "2. CHECK IP: Geolocate the source IP. Is it internal or external/public?",
      "3. PROCESS: Check processes spawned by svchost.exe -> rdpclip.exe on the destination.",
      "4. ISOLATE: If not a legitimate admin, isolate the destination host."
    ]
  },
  {
    id: 'LATERAL_003_RDP_TUNNEL',
    title: 'Local RDP Logon (Tunneling/Ssh)',
    severity: 'LOW',
    module: 'LATERAL',
    mitre: ['T1021.001'],
    detection: {
      selection: {
        'event_id': '4624',
        'user.logon_type': '10',
        'network.src_ip': ['127.0.0.1', '::1'],
        'user.name': ['!*$*', '!ANONYMOUS LOGON']
      }
    },
    description: "Detects RDP Logons originating from '127.0.0.1'. This indicates RDP traffic is being tunneled (e.g., via SSH Port Forwarding or Ngrok).",
    response_steps: [
      "1. INSPECT: Look for processes listening on port 3389 or high ports (netstat).",
      "2. HUNT: Search for 'plink.exe', 'ssh.exe', or C2 agents (chisel, ngrok).",
      "3. TERMINATE: Kill the session and the tunnel process."
    ]
  },
  {
    id: 'LATERAL_004_WINRM_CONFIG_MEDIUM',
    title: 'WinRM Configuration Modification',
    severity: 'MEDIUM',
    module: 'LATERAL',
    mitre: ['T1021.006'],
    detection: {
      selection: {
        'process.image': '*winrm.exe',
        'process.command_line': ['*quickconfig*', '*set*winrm/config/service*']
      }
    },
    description: "Attacker is enabling or modifying WinRM (Windows Remote Management) to allow remote PowerShell execution (PSRemoting).",
    response_steps: [
      "1. CHECK AUTH: Who executed this? Is it an admin configuring a new server?",
      "2. SCOPE: Check if 'AllowUnencrypted' or 'BasicAuth' (Weak configs) were enabled.",
      "3. REVERT: If malicious, disable WinRM service and check firewall rules."
    ]
  },
  {
    id: 'LATERAL_005_RPCPING_CONNECTIVITY_LOW',
    title: 'RpcPing Connectivity Check',
    severity: 'LOW',
    module: 'LATERAL',
    mitre: ['T1021.003'],
    detection: {
      selection: {
        'process.image': '*rpcping.exe',
        'process.command_line': ['*-s*']
      }
    },
    description: "RpcPing.exe used to test RPC connectivity to other hosts. Often used by attackers to map targets vulnerable to DCOM/WMI.",
    response_steps: [
      "1. CONTEXT: Review previous commands. Was it an isolated ping or part of a scan?",
      "2. MONITOR: Watch for subsequent WMI (wmic.exe) or DCOM lateral movement attempts."
    ]
  },
  {
    id: 'LATERAL_006_WINRS_REMOTE_SHELL_HIGH',
    title: 'WinRS Remote Shell Execution',
    severity: 'HIGH',
    module: 'LATERAL',
    mitre: ['T1021.006'],
    detection: {
      selection: {
        'process.image': '*winrs.exe',
        'process.command_line': ['*-r:*']
      }
    },
    description: "Execution of WinRS (Windows Remote Shell). Allows obtaining an interactive CMD shell on a remote host via WinRM.",
    response_steps: [
      "1. CRITICAL: WinRS is rarely used by modern legitimate admins (who prefer Enter-PSSession).",
      "2. ISOLATE: Isolate both hosts (source and destination).",
      "3. LOGS: Review WinRM Logs on the destination (Microsoft-Windows-WinRM/Operational)."
    ]
  },
  {
    id: 'LATERAL_007_SMB_EXEC_PSEXEC',
    title: 'SMB Lateral Movement (PsExec Style)',
    severity: 'HIGH',
    module: 'LATERAL',
    mitre: ['T1570'],
    detection: {
      selection: {
        'event_id': '5140', // Share access (or 5145)
        'share_name': ['*ADMIN$*', '*C$*'],
        'relative_target_name': ['*.exe', '*.bat', '*.ps1'] // Writing executable to admin share
      }
    },
    description: "Detects file writes to administrative shares (ADMIN$, C$) followed by service creation or execution. This is the signature behavior of PsExec, Cobalt Strike SMB Beacon, and Impacket.",
    response_steps: [
      "1. SOURCE: Identify the machine connecting to the share.",
      "2. FILE: What was written? (e.g., PSEXESVC.exe).",
      "3. SERVICE: Check for a new service created immediately after the file write.",
      "4. BLOCK: Block SMB (445) from workstations."
    ]
  },
  {
    id: 'LATERAL_008_WMI_EXEC',
    title: 'WMI Lateral Movement',
    severity: 'HIGH',
    module: 'LATERAL',
    mitre: ['T1047'],
    detection: {
      selection: {
        'process.image': '*wmic.exe',
        'process.command_line': ['*/node:*', '*process call create*']
      }
    },
    description: "Using WMI to spawn a process on a remote machine. This is 'agentless' lateral movement as it only requires WMI ports (135 + high ports).",
    response_steps: [
      "1. TARGET: Which machine was targeted (/node:TARGET)?",
      "2. COMMAND: What command was executed?",
      "3. ACCOUNT: Which user credentials were used? (Check 4624 type 3 on target)."
    ]
  },
  {
    id: 'LATERAL_009_DCOM_MMC',
    title: 'DCOM Lateral Movement (MMC20.Application)',
    severity: 'CRITICAL',
    module: 'LATERAL',
    mitre: ['T1021.003'],
    detection: {
      selection: {
        'process.parent_image': '*mmc.exe', // When DCOM spawns it, parent is often weird or svchost
        'process.command_line': ['*MMC20.Application*', '*ExecuteShellCommand*']
        // Note: Real detection often requires EDR/Sysmon ImageLoad of dcomlaunch or network traffic on 135
      }
    },
    description: "Abusing the MMC20.Application DCOM object to execute commands on a remote machine. A stealthy alternative to PsExec/WMI.",
    response_steps: [
      "1. ISOLATE: DCOM attacks are hard to detect and imply the attacker has Admin creds.",
      "2. NETWORK: Look for RPC traffic (TCP 135) between workstations.",
      "3. REMEDIATE: Disable DCOM if not needed (Hardening)."
    ]
  },
  {
    id: 'LATERAL_010_SSH_TUNNEL',
    title: 'SSH Lateral Movement / Tunneling',
    severity: 'MEDIUM',
    module: 'LATERAL',
    mitre: ['T1572'],
    detection: {
      selection: {
        'process.image': ['*ssh.exe', '*plink.exe'],
        'process.command_line': ['* -R *', '* -L *', '* -D *', '*root@*']
      }
    },
    description: "Using SSH (native or Putty/Plink) to move laterally or create tunnels (Port Forwarding) to bypass firewalls.",
    response_steps: [
      "1. MAPPING: Map the tunnel. Local port -> Remote Target.",
      "2. KEYS: Did they leave SSH keys on disk?",
      "3. KILL: Terminate the session."
    ]
  },
  {
    id: 'LATERAL_011_NAMED_PIPE_IMPERSONATION',
    title: 'Named Pipe Impersonation',
    severity: 'HIGH',
    module: 'LATERAL',
    mitre: ['T1134'],
    detection: {
      selection: {
        'event_id': '17', // Sysmon Pipe Created (or 18 Pipe Connected)
        'pipe_name': ['*msagent*', '*postex_ssh*', '*status_*'] // Cobalt Strike default pipe patterns
      }
    },
    description: "Connecting to a Named Pipe to move laterally (SMB) or impersonate a client. Tools like Cobalt Strike use specific pipe names for SMB Beacons.",
    response_steps: [
      "1. PATTERN: Identify the pipe name pattern (CS often uses predictable ones).",
      "2. PROCESS: Identify the process hosting the pipe.",
      "3. SCAN: Scan the network for other hosts with the same pipe pattern."
    ]
  },
  {
    id: 'LATERAL_012_PASS_THE_TICKET',
    title: 'Pass-the-Ticket (Kerberos)',
    severity: 'CRITICAL',
    module: 'LATERAL',
    mitre: ['T1550.003'],
    detection: {
      selection: {
        'event_id': '4624',
        'logon_type': '3',
        'logon_guid': '{00000000-0000-0000-0000-000000000000}' // Sometimes indicates PTT/Forged ticket
        // Or finding klist purge followed by immediate service access
      }
    },
    description: "Injecting a stolen Kerberos Ticket (TGT or TGS) into the current session to access remote resources without knowing the password.",
    response_steps: [
      "1. PURGE: 'klist purge' removes current tickets (but attacker can re-inject).",
      "2. REBOOT: The only sure way to clear malicious tickets from LSA memory.",
      "3. RESET: Reset the account password associated with the ticket (if known)."
    ]
  }
];
