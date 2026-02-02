import { Rule } from '@neonshapeshifter/logtower-engine';

export const TOOL_SIGNATURES_RULES: Rule[] = [
  // --- CREDENTIAL DUMPING ---
  {
    "id": "TOOL_001_MIMIKATZ",
    "title": "Mimikatz Tool Detected",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.image": ["*mimikatz.exe", "*mimi.exe", "*sekurlsa.dll"],
        "process.command_line": ["*sekurlsa::*", "*lsadump::*", "*privilege::debug*"]
      }
    },
    "description": "Mimikatz is a leading post-exploitation tool used to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket or build Golden tickets.",
    "response_steps": [
      "1. ISOLATE: Disconnect the affected machine from the network immediately.",
      "2. RESET: Assume all active credentials (logged-in users) are compromised. Force password resets.",
      "3. INVESTIGATE: Identify how the tool was introduced (dropped file, downloaded via script).",
      "4. REIMAGE: The system integrity is likely compromised beyond repair."
    ]
  },
  {
    "id": "TOOL_002_RUBEUS",
    "title": "Rubeus Kerberos Tool",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1558"],
    "detection": {
      "selection": {
        "process.image": "*Rubeus.exe",
        "process.command_line": ["*kerberoast*", "*asreproast*", "*monitor*", "*triage*"]
      }
    },
    "description": "Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is used for Kerberoasting, AS-REP Roasting, S4U abuse, and ticket extraction/injection.",
    "response_steps": [
      "1. ISOLATE: Immediate host isolation.",
      "2. ANALYZE: Check command line arguments to determine the specific attack (e.g., 'kerberoast' targets service accounts).",
      "3. RESET: Reset passwords for any service accounts or users targeted.",
      "4. HUNT: Look for subsequent ticket usage (Pass-the-Ticket) across the network."
    ]
  },
  {
    "id": "TOOL_003_PROCDUMP_LSASS",
    "title": "Procdump on LSASS",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.image": "*procdump*.exe",
        "process.command_line": "*lsass*"
      }
    },
    "description": "Detects the usage of Sysinternals ProcDump to create a memory dump of the Local Security Authority Subsystem Service (LSASS). Attackers use this valid Microsoft tool to evade AV while dumping credentials.",
    "response_steps": [
      "1. VERIFY: Is this legitimate debugging activity by a sysadmin?",
      "2. HASH: Check the hash of the procdump executable (to ensure it's not a renamed malware).",
      "3. DELETE: Remove the output dump file immediately.",
      "4. RESET: Assume credentials in memory are compromised."
    ]
  },
  {
    "id": "TOOL_004_LAZAGNE",
    "title": "LaZagne Credential Tool",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "process.image": "*lazagne.exe",
        "process.command_line": "*lazagne*"
      }
    },
    "description": "LaZagne is an open-source application used to retrieve lots of passwords stored on a local computer (browsers, mail, wifi, databases, etc.).",
    "response_steps": [
      "1. CONTAIN: Kill the process and isolate the host.",
      "2. RESET: Reset passwords for applications likely targeted (e.g., browser saved passwords, email).",
      "3. INVESTIGATE: Determine entry point."
    ]
  },

  // --- RECONNAISSANCE ---
  {
    "id": "TOOL_005_BLOODHOUND",
    "title": "BloodHound/SharpHound Detected",
    "severity": "HIGH",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "process.image": ["*SharpHound.exe", "*BloodHound.exe"],
        "process.command_line": ["*-CollectionMethod All*", "*Invoke-BloodHound*"]
      }
    },
    "description": "BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers use it to find attack paths to Domain Admin.",
    "response_steps": [
      "1. BLOCK: Kill the collection process (SharpHound).",
      "2. HUNT: Identify the user account performing the collection.",
      "3. REINFORCE: The attacker is mapping the network. Expect lateral movement attempts soon."
    ]
  },
  {
    "id": "TOOL_006_ADFIND",
    "title": "AdFind Discovery Tool",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "process.image": "*AdFind.exe",
        "process.command_line": ["*AdFind*", "*objectcategory=*"]
      }
    },
    "description": "AdFind is a command line Active Directory query tool. While legitimate, it is heavily favored by ransomware groups (like Ryuk/Conti) for reconnaissance.",
    "response_steps": [
      "1. VERIFY: Is this a known admin tool?",
      "2. ANALYZE: Check the queries. Are they dumping all computers or users?",
      "3. CONTAIN: If unauthorized, isolate the machine."
    ]
  },
  {
    "id": "TOOL_007_NMAP",
    "title": "Nmap Network Scanner",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1046"],
    "detection": {
      "selection": {
        "process.image": "*nmap.exe"
      }
    },
    "description": "Nmap is a network scanner used to discover hosts and services. Unauthorized use indicates network mapping/discovery phase.",
    "response_steps": [
      "1. VERIFY: Authorized scan?",
      "2. IDENTIFY: Which subnets are being scanned?",
      "3. BLOCK: Block the source IP at the firewall if external/unauthorized."
    ]
  },

  // --- LATERAL MOVEMENT ---
  {
    "id": "TOOL_008_PSEXEC_TOOL",
    "title": "PsExec Tool Usage",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.image": ["*PsExec.exe", "*PsExec64.exe"],
        "process.command_line": ["*-accepteula*"] // Common flag in scripts
      }
    },
    "description": "PsExec allows executing processes on other systems. It is commonly used for lateral movement. The '-accepteula' flag often indicates automated/scripted usage.",
    "response_steps": [
      "1. VERIFY: Is this an admin deployment?",
      "2. ANALYZE: What command is being executed remotely?",
      "3. ISOLATE: If unknown, cut network access to prevent spread."
    ]
  },
  {
    "id": "TOOL_009_IMPACKET",
    "title": "Impacket Toolset Detected",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1021"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmiexec*", "*smbexec*", "*atexec*", "*psexec.py*"]
      }
    },
    "description": "Impacket is a collection of Python classes for working with network protocols. Tools like wmiexec and smbexec are standard in attacker toolkits for lateral movement without touching disk (or minimal footprint).",
    "response_steps": [
      "1. CRITICAL: High fidelity attack indicator.",
      "2. ISOLATE: Isolate source and target systems.",
      "3. RESET: Reset credentials of the user account used for execution."
    ]
  },

  // --- C2 / AGENTS ---
  {
    "id": "TOOL_010_COBALT_STRIKE_PIPE",
    "title": "Cobalt Strike Default Pipe",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "pipe.name": ["*\\msagent_*", "*\\postex_*", "*\\status_*"]
      }
    },
    "description": "Detects default named pipes used by Cobalt Strike Beacon. Cobalt Strike is a commercial adversary simulation software widely used by threat actors.",
    "response_steps": [
      "1. ISOLATE: Isolate the host immediately. This is an active C2 channel.",
      "2. MEMORY DUMP: Capture RAM for analysis before shutdown if possible.",
      "3. REIMAGE: The host is fully compromised."
    ]
  },
  {
    "id": "TOOL_011_METERPRETER",
    "title": "Meterpreter Artifact",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.command_line": "*meterpreter*"
      }
    },
    "description": "Meterpreter is a Metasploit attack payload that provides an interactive shell. Detection often indicates a successful exploit or payload delivery.",
    "response_steps": [
      "1. ISOLATE: Disconnect immediately.",
      "2. INVESTIGATE: Identify the parent process (exploit vector).",
      "3. REIMAGE: System is compromised."
    ]
  },
  
  // --- DEFENSE EVASION ---
  {
    "id": "TOOL_012_GMER",
    "title": "GMER Kernel Tool (Anti-AV)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.image": "*gmer.exe"
      }
    },
    "description": "GMER is a rootkit detector, but attackers use it to find and kill antivirus/EDR kernel hooks to disable security monitoring.",
    "response_steps": [
      "1. ALERT: Attacker is attempting to blind security controls.",
      "2. ISOLATE: Isolate host.",
      "3. CHECK: Verify status of AV/EDR agents."
    ]
  }
];