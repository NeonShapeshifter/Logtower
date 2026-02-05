import { Rule } from '@neonshapeshifter/logtower-engine';

export const POWERSHELL_RULES: Rule[] = [
  {
    id: "PS_101_DOWNLOADSTRING",
    title: "PowerShell DownloadString",
    severity: "HIGH",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Net.WebClient*", "*DownloadString*"]
      }
    },
    description: "Detects the use of Net.WebClient.DownloadString in PowerShell. This is the most common method to fetch and execute remote code (fileless malware) directly into memory.",
    response_steps: [
      "1. URL: Extract the URL being accessed.",
      "2. CONTENT: Download the script manually (in a sandbox) to analyze.",
      "3. PARENT: What spawned this? Often an Office macro or malicious LNK file."
    ]
  },
  {
    id: "PS_102_DOWNLOADFILE",
    title: "PowerShell DownloadFile",
    severity: "HIGH",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Net.WebClient*", "*DownloadFile*"]
      }
    },
    description: "Detects the use of Net.WebClient.DownloadFile. Unlike DownloadString (memory), this saves the payload to disk, often to Temp or Public folders.",
    response_steps: [
      "1. FILE: Identify where the file was saved.",
      "2. HASH: Get the SHA256 of the dropped file.",
      "3. DELETE: Remove the file and scan the machine."
    ]
  },
  {
    id: "PS_103_INVOKE_EXPRESSION",
    title: "PowerShell IEX Execution",
    severity: "CRITICAL",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Expression*", "*IEX *"]
      }
    },
    description: "Detects 'Invoke-Expression' (IEX). This cmdlet executes a string as code. Attackers use it to run downloaded scripts or de-obfuscated payloads immediately.",
    response_steps: [
      "1. PAYLOAD: What string was passed to IEX?",
      "2. SOURCE: Did it come from a variable (obfuscation) or a download?",
      "3. ISOLATE: High probability of malware execution."
    ]
  },
  {
    id: "PS_104_ENCODED_COMMAND",
    title: "PowerShell Encoded Command",
    severity: "HIGH",
    module: "EXECUTION",
    mitre: ["T1027"],
    detection: {
      selection: {
        "process.command_line": ["*-EncodedCommand*", "*-enc *"]
      }
    },
    description: "Detects the use of Base64 encoded commands (-EncodedCommand). Attackers use this to hide the actual script logic from command line logging and simple signature scans.",
    response_steps: [
      "1. DECODE: Use a Base64 decoder to reveal the command.",
      "2. ANALYZE: Review the decoded script.",
      "3. ALERT: Legitimate use is rare outside of specific admin tools (e.g., SCCM)."
    ]
  },
  {
    id: "PS_105_HIDDEN_WINDOW",
    title: "PowerShell Hidden Window",
    severity: "HIGH",
    module: "DEFENSE",
    mitre: ["T1564.003"],
    detection: {
      selection: {
        "process.command_line": ["*-WindowStyle Hidden*", "*-w hidden*"]
      }
    },
    description: "Detects PowerShell running with a hidden window. This is standard tradecraft for malware to avoid alerting the user.",
    response_steps: [
      "1. USER: Is a user logged in? If so, they didn't see anything.",
      "2. PROCESS: Check the process tree. What launched it?",
      "3. TERMINATE: Kill the process immediately."
    ]
  },
  {
    id: "PS_106_EXEC_BYPASS",
    title: "PowerShell ExecutionPolicy Bypass",
    severity: "HIGH",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*-ExecutionPolicy Bypass*", "*-ep bypass*"]
      }
    },
    description: "Detects attempts to bypass the local PowerShell script execution policy. While easy to bypass, explicit use often indicates a script trying to run on a restricted system.",
    response_steps: [
      "1. SCRIPT: What script file or command followed the bypass flag?",
      "2. INTENT: Is this a developer script or something unknown?"
    ]
  },
  {
    id: "PS_107_NOPROFILE",
    title: "PowerShell NoProfile",
    severity: "INFO",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*-NoProfile*", "*-nop *"]
      }
    },
    description: "Detects usage of -NoProfile. This prevents loading user profile scripts ($profile). Attackers use it to speed up execution and avoid interference/logging from profile settings.",
    response_steps: [
      "1. CONTEXT: Common in automation, but also in 90% of malware payloads.",
      "2. COMBINATION: Is it combined with -Hidden and -Encoded? If so, CRITICAL."
    ]
  },
  {
    id: "PS_108_NONINTERACTIVE",
    title: "PowerShell NonInteractive",
    severity: "INFO",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*-NonInteractive*"]
      }
    },
    description: "Detects usage of -NonInteractive. Prevents an interactive prompt from appearing. Used by scripts that run in the background.",
    response_steps: [
      "1. PARENT: If run by a user interactively, this is suspicious.",
      "2. PURPOSE: Check arguments to see what task is being automated."
    ]
  },
  {
    id: "PS_109_BASE64_CONVERT",
    title: "PowerShell FromBase64String",
    severity: "HIGH",
    module: "DEFENSE",
    mitre: ["T1027", "T1140"],
    detection: {
      selection: {
        "process.command_line": ["*[System.Convert]::FromBase64String*"]
      }
    },
    description: "Detects manual Base64 decoding within a script. Often used to decode a payload (PE file or Shellcode) hidden inside the script text.",
    response_steps: [
      "1. DECODE: Find the Base64 string in the logs/script.",
      "2. IDENTIFY: What is the decoded output? (Header MZ = Executable)."
    ]
  },
  {
    id: "PS_110_STREAMREADER",
    title: "PowerShell StreamReader Usage",
    severity: "LOW",
    module: "COLLECTION",
    mitre: ["T1005"],
    detection: {
      selection: {
        "process.command_line": ["*New-Object*IO.StreamReader*"]
      }
    },
    description: "Detects usage of StreamReader. Can be used to read local files for exfiltration or analysis.",
    response_steps: [
      "1. FILE: What file is being read?",
      "2. EXFIL: Is the content being sent to a network socket?"
    ]
  },
  {
    id: "PS_111_STOP_COMPUTER",
    title: "PowerShell Stop-Computer",
    severity: "MEDIUM",
    module: "IMPACT",
    mitre: ["T1529"],
    detection: {
      selection: {
        "process.command_line": ["*Stop-Computer*"]
      }
    },
    description: "Detects execution of Stop-Computer. Attackers may shut down a host to disrupt operations or hide tracks (wipe memory).",
    response_steps: [
      "1. AUTH: Who ran this?",
      "2. CONTEXT: Was it scheduled maintenance or unexpected?"
    ]
  },
  {
    id: "PS_112_MINIDUMP",
    title: "PowerShell MiniDump Write",
    severity: "CRITICAL",
    module: "CRED",
    mitre: ["T1003.001"],
    detection: {
      selection: {
        "process.command_line": ["*MiniDumpWriteDump*"]
      }
    },
    description: "Detects usage of MiniDumpWriteDump via PowerShell (P/Invoke). This is the core API used to dump LSASS memory and steal credentials.",
    response_steps: [
      "1. TARGET: Check if the target PID matches LSASS.exe.",
      "2. ISOLATE: Immediate isolation required.",
      "3. RESET: Password reset for all active users."
    ]
  },
  {
    id: "PS_113_AMSI_BYPASS",
    title: "PowerShell AMSI Bypass Attempt",
    severity: "CRITICAL",
    module: "DEFENSE",
    mitre: ["T1562.001"],
    detection: {
      selection: {
        "process.command_line": ["*AmsiScanBuffer*"]
      }
    },
    description: "Detects attempts to patch 'AmsiScanBuffer' in memory. This disables the Antimalware Scan Interface (AMSI), allowing malicious scripts to run undetected by AV.",
    response_steps: [
      "1. BLOCK: This is a confirmed attack attempt.",
      "2. PAYLOAD: What script ran *after* the bypass?",
      "3. INVESTIGATE: Assume AV was blind for the duration of this session."
    ]
  },
  {
    id: "PS_114_ETW_KILL",
    title: "PowerShell ETW Tampering",
    severity: "CRITICAL",
    module: "DEFENSE",
    mitre: ["T1562.002"],
    detection: {
      selection: {
        "process.command_line": ["*EtwEventWrite*"]
      }
    },
    description: "Detects attempts to patch 'EtwEventWrite' to disable Event Tracing for Windows (ETW). This blinds EDRs and log collectors.",
    response_steps: [
      "1. ALERT: High sophistication indicator.",
      "2. STATUS: Check if logging stopped coming from this host."
    ]
  },
  {
    id: "PS_115_REFLECTION",
    title: "PowerShell Reflection Assembly Load",
    severity: "HIGH",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*System.Reflection.Assembly*"]
      }
    },
    description: "Detects loading of .NET assemblies via Reflection (Load, LoadFile). Used to load DLLs/EXEs from memory or non-standard locations without touching disk.",
    response_steps: [
      "1. ASSEMBLY: What binary was loaded?",
      "2. SOURCE: Was it a byte array (fileless) or a file path?"
    ]
  },
  {
    id: "PS_116_INVOKE_ITEM",
    title: "PowerShell Invoke-Item Execution",
    severity: "INFO",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Item*", "*ii *"]
      }
    },
    description: "Detects usage of Invoke-Item (ii). Executes the default action for a file (e.g., opens a .txt, runs an .exe).",
    response_steps: [
      "1. FILE: What file was invoked?",
      "2. BEHAVIOR: Similar to double-clicking a file."
    ]
  },
  {
    id: "PS_117_START_PROCESS",
    title: "PowerShell Start-Process Spawning",
    severity: "INFO",
    module: "EXECUTION",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Start-Process*", "*spps *"]
      }
    },
    description: "Detects Start-Process usage. Used to launch executables, often with specific arguments or verb (RunAs for admin).",
    response_steps: [
      "1. CHILD: What process was started?",
      "2. ARGS: Check for suspicious arguments passed to the child."
    ]
  },
  {
    id: "PS_118_INVOKE_WEBREQUEST",
    title: "PowerShell Web Request",
    severity: "MEDIUM",
    module: "COMMAND_AND_CONTROL",
    mitre: ["T1105"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-WebRequest*", "*iwr *"]
      }
    },
    description: "Detects Invoke-WebRequest (iwr). The modern version of WebClient. Used to scrape web pages or download files.",
    response_steps: [
      "1. URL: Check the destination URL.",
      "2. OUTPUT: Was the content saved to disk (-OutFile) or memory?"
    ]
  },
  {
    id: "PS_119_INVOKE_RESTMETHOD",
    title: "PowerShell Rest Method",
    severity: "MEDIUM",
    module: "COMMAND_AND_CONTROL",
    mitre: ["T1105"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-RestMethod*", "*irm *"]
      }
    },
    description: "Detects Invoke-RestMethod (irm). Used to interact with REST APIs. Malware uses it to communicate with C2 servers (receiving JSON commands).",
    response_steps: [
      "1. API: Identify the API endpoint.",
      "2. DATA: What data was sent/received?"
    ]
  },
  {
    id: "PS_120_BITS_TRANSFER",
    title: "PowerShell BitsTransfer",
    severity: "HIGH",
    module: "COMMAND_AND_CONTROL",
    mitre: ["T1197"],
    detection: {
      selection: {
        "process.command_line": ["*Start-BitsTransfer*"]
      }
    },
    description: "Detects usage of the BITS module in PowerShell. A stealthier way to download files using background bandwidth.",
    response_steps: [
      "1. SOURCE: URL of the file.",
      "2. DEST: Local path."
    ]
  },
  {
    id: "PS_121_INVOKE_MIMIKATZ",
    title: "Invoke-Mimikatz Detected",
    severity: "CRITICAL",
    module: "CRED",
    mitre: ["T1003"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Mimikatz*"]
      }
    },
    description: "Detects the legendary Invoke-Mimikatz script (PowerSploit). Used to dump credentials from memory in plain text.",
    response_steps: [
      "1. ISOLATE: The attacker has admin access and is stealing credentials.",
      "2. RESET: Reset KRBTGT and all admin passwords.",
      "3. REBUILD: Consider the host compromised at the root level."
    ]
  },
  {
    id: "PS_122_NINJACOPY",
    title: "Invoke-NinjaCopy Detected",
    severity: "CRITICAL",
    module: "DEFENSE",
    mitre: ["T1003.003"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-NinjaCopy*"]
      }
    },
    description: "Detects Invoke-NinjaCopy. Uses raw volume access to copy locked system files (like NTDS.dit or SAM) while the OS is running.",
    response_steps: [
      "1. TARGET: Check which file was copied. If NTDS.dit, the entire domain is compromised.",
      "2. DESTINATION: Where was the copy sent?"
    ]
  },
  {
    id: "PS_123_GPPPASSWORD",
    title: "Get-GPPPassword Detected",
    severity: "CRITICAL",
    module: "CRED",
    mitre: ["T1552.006"],
    detection: {
      selection: {
        "process.command_line": ["*Get-GPPPassword*"]
      }
    },
    description: "Detects Get-GPPPassword. Scans the domain's SYSVOL for Group Preference Policy XML files containing decrypted passwords (legacy vulnerability).",
    response_steps: [
      "1. PATCH: Install KB2962486 (prevents saving passwords in GPO).",
      "2. CLEANUP: Delete old XML files from SYSVOL manually."
    ]
  },
  {
    id: "PS_124_TOKEN_MANIPULATION",
    title: "Invoke-TokenManipulation Detected",
    severity: "HIGH",
    module: "PRIVILEGE_ESCALATION",
    mitre: ["T1134"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-TokenManipulation*"]
      }
    },
    description: "Detects Invoke-TokenManipulation. Used to steal tokens from other processes to impersonate users (e.g., becoming SYSTEM or Domain Admin).",
    response_steps: [
      "1. TARGET: Whose token was stolen?",
      "2. ACTION: Did they spawn a new process with that token?"
    ]
  },
  {
    id: "PS_125_SHELLCODE",
    title: "Invoke-Shellcode Detected",
    severity: "CRITICAL",
    module: "EXECUTION",
    mitre: ["T1055"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Shellcode*"]
      }
    },
    description: "Detects Invoke-Shellcode. Injects shellcode into the current or remote process. Often used to launch Meterpreter or Cobalt Strike beacons.",
    response_steps: [
      "1. INJECTION: Check target Process ID.",
      "2. MEMORY: The payload is running in memory of a legitimate process."
    ]
  },
  {
    id: "PS_126_REFLECTIVE_PE",
    title: "Invoke-ReflectivePEInjection Detected",
    severity: "CRITICAL",
    module: "EXECUTION",
    mitre: ["T1055"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-ReflectivePEInjection*"]
      }
    },
    description: "Detects Invoke-ReflectivePEInjection. Loads a DLL/EXE from memory directly into the process space, bypassing Windows Loader (and disk detection).",
    response_steps: [
      "1. ISOLATE: Advanced technique usage.",
      "2. DUMP: Full memory dump required for analysis."
    ]
  },
  {
    id: "PS_127_PASSHASHES",
    title: "Get-PassHashes Detected",
    severity: "CRITICAL",
    module: "CRED",
    mitre: ["T1003"],
    detection: {
      selection: {
        "process.command_line": ["*Get-PassHashes*"]
      }
    },
    description: "Detects Get-PassHashes. Dumps password hashes from the SAM database or LSASS.",
    response_steps: [
      "1. CREDENTIALS: All local account passwords should be considered compromised.",
      "2. RESET: Reset local admin passwords."
    ]
  },
  {
    id: "PS_128_OBFUSCATION",
    title: "Invoke-Obfuscation Detected",
    severity: "HIGH",
    module: "DEFENSE",
    mitre: ["T1027"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Obfuscation*"]
      }
    },
    description: "Detects usage of the Invoke-Obfuscation framework. Used to scramble PowerShell scripts to evade AV signatures.",
    response_steps: [
      "1. DEOBFUSCATE: Extremely difficult manually. Check script block logs (Event 4104) which capture de-obfuscated code at runtime."
    ]
  },
  {
    id: "PS_129_POWERUP",
    title: "PowerUp AllChecks Detected",
    severity: "HIGH",
    module: "PRIVILEGE_ESCALATION",
    mitre: ["T1046"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-AllChecks*"]
      }
    },
    description: "Detects PowerUp 'Invoke-AllChecks'. Automated scanner for local privilege escalation vectors (services, registry, etc.).",
    response_steps: [
      "1. RESULT: If this ran fully, the attacker knows exactly how to get SYSTEM privileges.",
      "2. REMEDIATE: Run the same check yourself and fix the findings."
    ]
  },
  {
    id: "PS_130_POWERVIEW",
    title: "PowerView Recon Detected",
    severity: "HIGH",
    module: "DISCOVERY",
    mitre: ["T1087"],
    detection: {
      selection: {
        "process.command_line": ["*Get-NetDomain*", "*Get-NetUser*"]
      }
    },
    description: "Detects PowerView commands. The standard tool for Active Directory reconnaissance (Users, Groups, Computers, Shares, ACLs).",
    response_steps: [
      "1. SCOPE: What was queried? (User hunting vs Domain mapping).",
      "2. ALERT: Precursor to lateral movement."
    ]
  },
  {
    id: "PS_131_SHERLOCK",
    title: "Sherlock Vuln Scanner Detected",
    severity: "HIGH",
    module: "PRIVILEGE_ESCALATION",
    mitre: ["T1068"],
    detection: {
      selection: {
        "process.command_line": ["*Find-AllVulns*"]
      }
    },
    description: "Detects Sherlock 'Find-AllVulns'. Legacy script used to find missing Windows patches for local privilege escalation exploits.",
    response_steps: [
      "1. PATCH: Ensure the system is up to date.",
      "2. INTENT: Attacker is looking for an exploit path."
    ]
  },
  {
    id: "PS_132_BLOODHOUND",
    title: "BloodHound Ingestor Detected",
    severity: "HIGH",
    module: "DISCOVERY",
    mitre: ["T1087", "T1482"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-BloodHound*"]
      }
    },
    description: "Detects Sharphound/BloodHound ingestor. Maps the entire AD relationship graph to find 'Attack Paths' to Domain Admin.",
    response_steps: [
      "1. IMPACT: The attacker has a complete map of your AD security posture.",
      "2. RESPONSE: Rotate the account used to run this."
    ]
  },
  {
    id: "PS_133_EMPIRE",
    title: "PowerShell Empire Detected",
    severity: "CRITICAL",
    module: "COMMAND_AND_CONTROL",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.command_line": ["*Invoke-Empire*"]
      }
    },
    description: "Detects artifacts related to the Empire C2 framework.",
    response_steps: [
      "1. ISOLATE: Full C2 compromise.",
      "2. INVESTIGATE: Determine the entry point."
    ]
  },
  {
    id: "PS_135_COBALTSTRIKE",
    title: "CobaltStrike Beacon Pattern",
    severity: "HIGH",
    module: "COMMAND_AND_CONTROL",
    mitre: ["T1059.001"],
    detection: {
      selection: {
        "process.image": ["*powershell.exe", "*pwsh.exe"],
        "process.command_line": ["*-nop -w hidden -enc*"]
      }
    },
    description: "Detects the default Cobalt Strike PowerShell beacon launcher pattern (NoProfile + Hidden + Encoded).",
    response_steps: [
      "1. DECODE: Base64 decode the payload to find the C2 IP/Domain.",
      "2. BLOCK: Block the C2 at the firewall.",
      "3. ISOLATE: Host is actively controlled."
    ]
  }
];
