import { Rule } from '@neonshapeshifter/logtower-engine';

export const DEFENSE_RULES: Rule[] = [
  {
    id: 'DEFENSE_001_PROCESS_HOLLOWING',
    title: 'Process Hollowing Detected',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1055.012'],
    detection: {
      selection: {
        'event_id': '25', // Sysmon: Process Tampering (or 10 with specific flags)
        'process.image': ['*svchost.exe', '*explorer.exe', '*notepad.exe', '*calc.exe'], // Common targets
        'type': 'Image is replaced' // Conceptual mapping
      }
    },
    description: "Malware unmapped the code section of a legitimate process (like svchost.exe) and replaced it with its own malicious code. The process looks legitimate in Task Manager but runs malware.",
    response_steps: [
      "1. MEMORY DUMP: Use a forensic tool (Volatility/Rekall) to analyze the process memory.",
      "2. COMPARE: Compare the in-memory code with the on-disk binary. Differences confirm hollowing.",
      "3. KILL: Terminate the hollowed process.",
      "4. HUNT: Identify the parent process (loader) that performed the injection."
    ]
  },
  {
    id: 'DEFENSE_002_PROCESS_INJECTION',
    title: 'Remote Process Injection (CreateRemoteThread)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1055.002'],
    detection: {
      selection: {
        'event_id': '8', // Sysmon: CreateRemoteThread
        'start_address': ['!*kernel32*', '!*ntdll*'], // Starts in non-standard module usually
        'source_image': ['!*system32*', '!*program files*'] // Injected from weird location
      }
    },
    description: "A process injected code into another running process using CreateRemoteThread. This is the most common technique to migrate from a dropper to a stable process (like explorer.exe).",
    response_steps: [
      "1. IDENTIFY: Source Image (Injector) vs Target Image (Victim).",
      "2. ISOLATE: The 'Source' is the malware loader. The 'Target' is compromised.",
      "3. RESTART: Restart the victim process if critical (or reboot host)."
    ]
  },
  {
    id: 'DEFENSE_003_AMSI_BYPASS',
    title: 'AMSI Bypass / Patching',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1562.001'],
    detection: {
      selection: {
        'event_id': '10', // Sysmon ProcessAccess or specific EDR alerts
        'process.target_image': '*amsi.dll',
        'process.call_trace': '*AmsiScanBuffer*' // Crude approx, usually requires EDR
      }
    },
    description: "The attacker patched 'amsi.dll' in memory to disable the Antimalware Scan Interface. This allows them to run malicious PowerShell scripts without AV detection.",
    response_steps: [
      "1. ASSUME BREACH: If AMSI is disabled, they are running obfuscated scripts.",
      "2. LOGS: Check PowerShell Script Block logs (Event 4104) immediately.",
      "3. TERMINATE: Kill the PowerShell/CScript process."
    ]
  },
  {
    id: 'DEFENSE_004_ETW_DISABLE',
    title: 'ETW Logging Disabled (Blinding)',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1562.002'],
    detection: {
      selection: {
        'process.image': '*logman.exe',
        'process.command_line': ['*stop*', '*update*', '*trace*', '*session*']
      }
    },
    description: "Attacker is using 'logman' or patching ntdll functions (EtwEventWrite) to stop Event Tracing for Windows (ETW). This blinds EDRs and log collectors.",
    response_steps: [
      "1. RE-ENABLE: 'logman start <SessionName>' (if via logman).",
      "2. INVESTIGATE: Why did they blind the sensor? Imminent major action (Ransomware/Exfil).",
      "3. ISOLATE: Immediate isolation required."
    ]
  },
  {
    id: 'DEFENSE_005_TIMESTOMPING',
    title: 'File Timestomping Detected',
    severity: 'MEDIUM',
    module: 'DEFENSE',
    mitre: ['T1070.006'],
    detection: {
      selection: {
        'event_id': '2', // Sysmon: File creation time changed
        'previous_creation_time': '*' // Any change is suspicious if not installer
      }
    },
    description: "The creation timestamp of a file was modified to match an older date (often matching kernel32.dll). Used to hide malware from forensic analysts looking for 'recent' files.",
    response_steps: [
      "1. IGNORE TIME: Do not trust the 'Date Modified/Created' columns in Explorer.",
      "2. MFT: Analyze the Master File Table ($MFT) to retrieve the REAL creation time ($StdInfo vs $FileName attributes).",
      "3. SAMPLE: The file is likely malware. Collect it."
    ]
  },
  {
    id: 'DEFENSE_006_MASQUERADING',
    title: 'Process Masquerading (Fake System Binaries)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1036.005'],
    detection: {
      selection: {
        'process.image': ['*svchost.exe', '*csrss.exe', '*wininit.exe', '*lsass.exe'],
        'process.executable_path': ['!C:WindowsSystem32*', '!C:WindowsSysWOW64*']
      }
    },
    description: "A system binary (svchost.exe, lsass.exe) is running from a non-standard path (e.g., C:Tempsvchost.exe). This is malware trying to blend in.",
    response_steps: [
      "1. PATH CHECK: System binaries MUST reside in System32 or SysWOW64.",
      "2. HASH: It's 100% malicious. Get the hash.",
      "3. KILL: Terminate and delete."
    ]
  },
  {
    id: 'DEFENSE_007_PARENT_PID_SPOOFING',
    title: 'Parent PID Spoofing',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1134.004'],
    detection: {
      selection: {
        // Hard to detect with simple sigma, usually requires mismatched parent create times
        'event_id': '1',
        'process.parent_image': '*explorer.exe', // Spoofed to look like user launched it
        'process.command_line': '*powershell*'
      }
    },
    description: "The attacker launched a process but manually set its 'Parent Process ID' to a legitimate process (like explorer.exe or spoolsv.exe) to break the process tree analysis.",
    response_steps: [
      "1. ETW: Check 'Microsoft-Windows-Kernel-Process' for the REAL creator.",
      "2. ANOMALY: Look for impossible hierarchies (e.g., Word spawning a child that claims explorer.exe is its parent).",
      "3. ISOLATE: Standard malware evasion tactic."
    ]
  },
  {
    id: 'DEFENSE_008_AUDITPOL_DISABLE',
    title: 'Audit Policy Disabled',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1562.002'],
    detection: {
      selection: {
        'process.image': '*auditpol.exe',
        'process.command_line': ['*/set*', '*success:disable*', '*failure:disable*']
      }
    },
    description: "Attacker used auditpol.exe to disable Windows Event Logging for specific categories (e.g., disabling Logon/Logoff auditing).",
    response_steps: [
      "1. RESTORE: Re-apply the Group Policy Object (GPO) for auditing.",
      "2. SCOPE: What category was disabled? That tells you their next move (e.g., Object Access -> Accessing files).",
      "3. INVESTIGATE: This is preparation for a noisy action."
    ]
  },
  {
    id: 'DEFENSE_009_REFLECTIVE_DLL_INJECTION',
    title: 'Reflective DLL Injection',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1055.001'],
    detection: {
      selection: {
        'event_id': '10', // Sysmon Process Access
        'process.source_image': '*powershell.exe',
        'process.target_image': '*rundll32.exe' // Common pattern
      }
    },
    description: "Loading a DLL directly from memory into a process, without the DLL ever touching the disk (No LoadLibrary call). Used by Cobalt Strike and Metasploit.",
    response_steps: [
      "1. MEMORY SCAN: Run a memory scanner (Pe-sieve, Moneta) to find unbacked executable memory regions.",
      "2. CAPTURE: Dump the memory region to extract the payload.",
      "3. KILL: The process is compromised."
    ]
  },
  {
    id: 'DEFENSE_010_POWER_CL_TAMPER',
    title: 'PowerShell Constrained Language Tamper',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1562'],
    detection: {
      selection: {
        'process.command_line': ['*__PSLockdownPolicy*', '*Set-ItemProperty*', '*Env:*']
      }
    },
    description: "Attempting to downgrade PowerShell from 'Constrained Language Mode' (CLM) to 'Full Language Mode' by tampering with environment variables (__PSLockdownPolicy).",
    response_steps: [
      "1. CHECK: Verify current mode ($ExecutionContext.SessionState.LanguageMode).",
      "2. BLOCK: Ensure AppLocker/WDAC policies are enforcing CLM robustly.",
      "3. ALERT: They want to run complex C# or reflection code."
    ]
  },
  {
    id: 'DEFENSE_011_ATOM_BOMBING',
    title: 'Atom Bombing Injection',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1055'],
    detection: {
      selection: {
        'event_id': '8', // CreateRemoteThread or APC injection often used in variants
        // Specific API calls: GlobalAddAtom, NtQueueApcThread
        // Hard to detect via logs without EDR telemetry on API calls.
        // Using a proxy indicator:
        'process.target_image': '*explorer.exe',
        'process.start_address': '0x00000000' // Often anomalous start address
      }
    },
    description: "Injecting code into the Global Atom Table and forcing a legitimate process to retrieve and execute it via APC calls. Bypasses many memory scanners.",
    response_steps: [
      "1. ISOLATE: High sophistication attack.",
      "2. MEMORY: Volatility 'apc_scan' or similar plugins.",
      "3. REBOOT: Clears the Global Atom Table."
    ]
  },
  {
    id: 'DEFENSE_012_EARLY_BIRD',
    title: 'Early Bird Injection (APC Queue)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1055.004'],
    detection: {
      selection: {
        'event_id': '1', // Process Create
        // Early bird creates a process in SUSPENDED state, injects, then resumes.
        // Sysmon Event 1 followed immediately by Event 8 or similar in same millisecond.
        // Proxy:
        'process.command_line': ['* -suspended*', '* /suspended*'] // Rare but some tools use flags
      }
    },
    description: "Creating a suspended process, queuing a malicious APC (Asynchronous Procedure Call) to its main thread, and then resuming it. The malware runs before the AV initialization hook.",
    response_steps: [
      "1. PARENT: The parent process is the loader.",
      "2. CHILD: The child process contains the payload.",
      "3. TERMINATE: Kill the entire process tree."
    ]
  },
  {
    id: 'DEFENSE_013_UNLINKING_PEB',
    title: 'Unlinking from PEB (Module Hiding)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1055'],
    detection: {
      // Very hard via logs. Requires memory introspection.
      // We flag on tools that perform this action.
      selection: {
        'process.command_line': ['*unlink*', '*hide_module*', '*ReflectiveLoader*']
      }
    },
    description: "Malware removes its own entry from the Process Environment Block (PEB) loaded modules list. Tools listing loaded DLLs (like Task Manager) won't see it.",
    response_steps: [
      "1. SCAN: Use 'hollows_hunter' or 'pe-sieve' to find unlinked modules.",
      "2. VAD: Analyze the Virtual Address Descriptor (VAD) tree, which tracks memory allocation regardless of PEB.",
      "3. ALERT: Advanced rootkit behavior."
    ]
  },
  {
    id: 'DEFENSE_014_BINARY_PADDING',
    title: 'Binary Padding (Hash Evasion)',
    severity: 'LOW', // Common annoyance
    module: 'DEFENSE',
    mitre: ['T1027.001'],
    detection: {
      selection: {
        'event_id': '11', // File Create
        'file_size': '>100000000' // Files > 100MB created in Temp/Downloads
        // Attackers puff up files to bypass AV scan limits (often 100MB+).
      }
    },
    description: "Appending null bytes or junk data to a malware binary to make it huge (e.g., >100MB). Many AV engines skip scanning large files for performance.",
    response_steps: [
      "1. CHECK: Why is a 500MB executable running from Temp?",
      "2. SAMPLE: Upload to VirusTotal (might fail due to size) or strip padding first.",
      "3. BLOCK: Block execution of unapproved large binaries."
    ]
  },
  {
    id: 'DEFENSE_015_FILELESS_POWERSHELL',
    title: 'Fileless PowerShell (Reflective)',
    severity: 'CRITICAL',
    module: 'DEFENSE',
    mitre: ['T1059.001'],
    detection: {
      selection: {
        'process.image': '*powershell.exe',
        'process.command_line': ['*ReflectivePicker*', '*Invoke-ReflectivePEInjection*', '*VoidFunc*']
      }
    },
    description: "Executing a binary directly from memory using PowerShell without ever dropping an .exe to disk. 'Fileless' malware.",
    response_steps: [
      "1. LOGS: Check PowerShell ScriptBlock logs (4104).",
      "2. KILL: Powershell.exe is the host.",
      "3. PERSISTENCE: Check WMI or Registry, as fileless malware needs a script-based auto-start."
    ]
  },
  {
    id: 'DEFENSE_016_CALC_SPAWN',
    title: 'Suspicious Calculator/Notepad Spawn',
    severity: 'MEDIUM',
    module: 'DEFENSE',
    mitre: ['T1055'],
    detection: {
      selection: {
        'process.parent_image': ['*powershell.exe', '*cmd.exe', '*mshta.exe'],
        'process.image': ['*calc.exe', '*notepad.exe']
      }
    },
    description: "A shell spawning calc.exe or notepad.exe is the classic 'Proof of Concept' or beacon placeholder for process injection/migration.",
    response_steps: [
      "1. CHECK: Did a user do this? (Unlikely via powershell).",
      "2. MEMORY: Inspect the calc/notepad process memory.",
      "3. ALERT: Likely a C2 Beacon (Cobalt Strike default spawn to notepad)."
    ]
  },
  {
    id: 'DEFENSE_017_UAC_FODHELPER',
    title: 'UAC Bypass - Fodhelper',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1548.002'],
    detection: {
      selection: {
        'process.image': '*fodhelper.exe',
        'process.parent_image': ['*cmd.exe', '*powershell.exe', '*pwsh.exe']
        // Fodhelper should be spawned by Explorer, not a shell
      }
    },
    description: "Fodhelper.exe is an auto-elevating binary. Attackers hijack its registry key (ms-settings) to execute commands with High Integrity (Admin) without a UAC prompt.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\Command.",
      "2. PAYLOAD: The command in that key was executed as Admin.",
      "3. REMEDIATE: Delete the registry key."
    ]
  },
  {
    id: 'DEFENSE_018_UAC_SLUI',
    title: 'UAC Bypass - Slui (File Handler)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1548.002'],
    detection: {
      selection: {
        'process.image': '*slui.exe',
        'process.command_line': ['*-r*'] // Specific flag used in some bypasses
      }
    },
    description: "Slui.exe (Windows Activation) can be abused to bypass UAC via registry hijacking of the file association.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Software\\Classes\\exefile\\shell\\open\\command (or similar classes).",
      "2. CLEAN: Remove the hijacked association."
    ]
  },
  {
    id: 'DEFENSE_019_UAC_SDCLT',
    title: 'UAC Bypass - Sdclt (Backup)',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1548.002'],
    detection: {
      selection: {
        'process.image': '*sdclt.exe',
        'process.parent_image': ['*cmd.exe', '*powershell.exe']
      }
    },
    description: "Sdclt.exe (Backup and Restore) is an auto-elevating binary. Hijacking its associated registry keys allows silent elevation.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe.",
      "2. KILL: Terminate the elevated process."
    ]
  },
  {
    id: 'DEFENSE_020_UAC_COMPUTERDEFAULTS',
    title: 'UAC Bypass - ComputerDefaults',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1548.002'],
    detection: {
      selection: {
        'process.image': '*computerdefaults.exe',
        'process.parent_image': ['*cmd.exe', '*powershell.exe']
      }
    },
    description: "ComputerDefaults.exe helps set default programs. It auto-elevates and reads commands from the Registry, allowing UAC bypass.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command.",
      "2. ALERT: Common in malware automated privilege escalation routines."
    ]
  },
  {
    id: 'DEFENSE_021_UAC_EVENTVWR',
    title: 'UAC Bypass - Event Viewer',
    severity: 'HIGH',
    module: 'DEFENSE',
    mitre: ['T1548.002'],
    detection: {
      selection: {
        'process.image': '*eventvwr.exe',
        'process.parent_image': ['*cmd.exe', '*powershell.exe']
      }
    },
    description: "Eventvwr.exe attempts to load mmc.exe from HKCU registry before System32. Attackers hijack this look-up to run code as High Integrity.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Software\\Classes\\mscfile\\shell\\open\\command.",
      "2. FIX: Remove the key. Event Viewer should use the system association."
    ]
  }
];