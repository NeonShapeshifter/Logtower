import { Rule } from '@neonshapeshifter/logtower-engine';

export const POWERSHELL_DEEP_RULES: Rule[] = [
  {
    "id": "PS_577_AMSI_BUFFER",
    "title": "AMSI ScanBuffer Bypass Attempt",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*AmsiScanBuffer*", "*amsi.dll*", "*AmsiUtils*"]
      }
    },
    "description": "Detects attempts to manipulate AmsiScanBuffer or amsi.dll in memory. This disables AMSI (Antimalware Scan Interface), blinding AV to malicious scripts.",
    "response_steps": [
      "1. ISOLATE: High confidence bypass attempt.",
      "2. LOGS: Check 4104 logs for the payload executed after the bypass."
    ]
  },
  {
    "id": "PS_578_AMSI_INIT_FAIL",
    "title": "AMSI InitFailed Bypass",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": "*amsiInitFailed*"
      }
    },
    "description": "Detects setting the 'amsiInitFailed' flag to true. This tells the AMSI engine that initialization failed, causing it to stop scanning.",
    "response_steps": [
      "1. ISOLATE: Confirmed bypass.",
      "2. PAYLOAD: Identify malicious script."
    ]
  },
  {
    "id": "PS_579_REFLECTION_LOAD",
    "title": "PowerShell Reflection Assembly Load",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*[Reflection.Assembly]::Load*", "*System.Reflection.Assembly*"]
      }
    },
    "description": "Detects loading .NET assemblies from memory via Reflection. Used to execute fileless malware.",
    "response_steps": [
      "1. SOURCE: Where did the bytes come from? (Download/Base64).",
      "2. ISOLATE: Potential in-memory threat."
    ]
  },
  {
    "id": "PS_580_MEMORY_STREAM",
    "title": "PowerShell MemoryStream Usage (Fileless)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*System.IO.MemoryStream*", "*New-Object IO.MemoryStream*"]
      }
    },
    "description": "Usage of MemoryStream objects. often used to handle shellcode or decrypted payloads in memory without touching disk.",
    "response_steps": [
      "1. CONTEXT: Is this a compression/archiving script?",
      "2. CHECK: Often paired with GzipStream."
    ]
  },
  {
    "id": "PS_581_GZIP_DECOMPRESS",
    "title": "PowerShell Gzip Decompression (Unpacking)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1027", "T1140"],
    "detection": {
      "selection": {
        "process.command_line": ["*System.IO.Compression.GzipStream*", "*Decompress*"]
      }
    },
    "description": "Decompressing Gzip streams in memory. Malware payloads are often compressed to evade static signatures.",
    "response_steps": [
      "1. PAYLOAD: What was decompressed?",
      "2. SOURCE: Downloaded blob?"
    ]
  },
  {
    "id": "PS_582_BASE64_DECODE",
    "title": "PowerShell Base64 Decoding",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1027", "T1140"],
    "detection": {
      "selection": {
        "process.command_line": ["*[System.Convert]::FromBase64String*"]
      }
    },
    "description": "Manual Base64 decoding. Often used to unpack stage 2 payloads.",
    "response_steps": [
      "1. DECODE: Retrieve the string and decode it manually."
    ]
  },
  {
    "id": "PS_583_VIRTUALALLOC",
    "title": "PowerShell VirtualAlloc Call (Shellcode)",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.command_line": ["*VirtualAlloc*", "*WriteProcessMemory*"]
      }
    },
    "description": "Calling VirtualAlloc via P/Invoke. This allocates executable memory, a requirement for running shellcode.",
    "response_steps": [
      "1. ISOLATE: Shellcode injection imminent.",
      "2. KILL: Terminate PowerShell."
    ]
  },
  {
    "id": "PS_584_CREATE_THREAD",
    "title": "PowerShell CreateThread Call (Injection)",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.command_line": ["*CreateThread*", "*CreateRemoteThread*"]
      }
    },
    "description": "Calling CreateThread via P/Invoke. Starts execution of the injected shellcode.",
    "response_steps": [
      "1. ISOLATE: Code execution confirmed."
    ]
  },
  {
    "id": "PS_585_QUEUE_USER_APC",
    "title": "PowerShell QueueUserAPC (Early Bird)",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1055.004"],
    "detection": {
      "selection": {
        "process.command_line": "*QueueUserAPC*"
      }
    },
    "description": "Calling QueueUserAPC. Used for 'Early Bird' injection into suspended processes.",
    "response_steps": [
      "1. ISOLATE: Advanced injection technique."
    ]
  },
  {
    "id": "PS_586_MINIDUMP_API",
    "title": "PowerShell MiniDumpWriteDump (Creds)",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.command_line": "*MiniDumpWriteDump*"
      }
    },
    "description": "Calling MiniDumpWriteDump. Used to dump LSASS memory to disk.",
    "response_steps": [
      "1. ISOLATE: Credential theft in progress.",
      "2. RESET: Reset all passwords."
    ]
  },
  {
    "id": "PS_587_MARSHAL_COPY",
    "title": "PowerShell Marshal.Copy (Memory Ops)",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*System.Runtime.InteropServices.Marshal*", "*Marshal::Copy*"]
      }
    },
    "description": "Using Marshal.Copy to move data into unmanaged memory buffers. Precursor to shellcode execution.",
    "response_steps": [
      "1. CHECK: Look for VirtualAlloc calls."
    ]
  },
  {
    "id": "PS_588_DELEGATE_PTR",
    "title": "GetDelegateForFunctionPointer (Shellcode)",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.command_line": "*GetDelegateForFunctionPointer*"
      }
    },
    "description": "Converting a memory pointer to a delegate. This allows PowerShell to execute shellcode residing in memory.",
    "response_steps": [
      "1. ISOLATE: Confirmed shellcode execution."
    ]
  },
  {
    "id": "PS_589_OBF_BACKTICKS",
    "title": "Obfuscation with Backticks",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*`*`*`*", "*i`n`v`o`k`e*"]
      }
    },
    "description": "Heavy use of backticks to break string signatures (e.g. i`n`v`o`k`e).",
    "response_steps": [
      "1. DEOBFUSCATE: Remove backticks to read command."
    ]
  },
  {
    "id": "PS_590_OBF_CONCAT",
    "title": "Obfuscation with Concatenation",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*'+'*'+'*", "*\"+\"*\"+\"*"]
      }
    },
    "description": "String concatenation to hide keywords.",
    "response_steps": [
      "1. CHECK: Read the assembled string."
    ]
  },
  {
    "id": "PS_591_OBF_FORMAT",
    "title": "Obfuscation with Format Operator",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*\"{0}\" -f *", "*\"{1}\" -f *"]
      }
    },
    "description": "Using format operator (-f) to reorder strings.",
    "response_steps": [
      "1. CHECK: Reassemble the string."
    ]
  },
  {
    "id": "PS_592_OBF_ENV_VARS",
    "title": "Obfuscation via Env Variables",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*$env:public*", "*$env:temp*", "*$env:appdata*"]
      }
    },
    "description": "Using environment variables to build paths or commands.",
    "response_steps": [
      "1. CHECK: Often used to find writable paths."
    ]
  },
  {
    "id": "PS_593_WEB_CLIENT",
    "title": "PowerShell Net.WebClient",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.command_line": "*Net.WebClient*"
      }
    },
    "description": "Instantiating Net.WebClient. Used for downloads.",
    "response_steps": [
      "1. URL: Check the URL."
    ]
  },
  {
    "id": "PS_594_BITSTRANSFER_MOD",
    "title": "BitsTransfer Module Import",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.command_line": ["*Import-Module BitsTransfer*", "*Start-BitsTransfer*"]
      }
    },
    "description": "Importing BITS module. Used for stealthy transfer.",
    "response_steps": [
      "1. CHECK: What files are moved?"
    ]
  },
  {
    "id": "PS_595_GET_CLIPBOARD",
    "title": "PowerShell Clipboard Theft",
    "severity": "HIGH",
    "module": "COLLECTION",
    "mitre": ["T1115"],
    "detection": {
      "selection": {
        "process.command_line": ["*Get-Clipboard*", "*Windows.Forms.Clipboard*"]
      }
    },
    "description": "Reading clipboard content via PowerShell. Attackers steal passwords/keys copied by users.",
    "response_steps": [
      "1. CHECK: What did the user last copy?"
    ]
  },
  {
    "id": "PS_596_KEYSTROKE_LOG",
    "title": "PowerShell Keylogging (GetAsyncKeyState)",
    "severity": "CRITICAL",
    "module": "COLLECTION",
    "mitre": ["T1056.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*GetAsyncKeyState*", "*GetKeyboardState*"]
      }
    },
    "description": "Keylogging via PowerShell P/Invoke.",
    "response_steps": [
      "1. ISOLATE: User input compromised."
    ]
  },
  {
    "id": "PS_597_SCREENSHOT",
    "title": "PowerShell Screen Capture",
    "severity": "HIGH",
    "module": "COLLECTION",
    "mitre": ["T1113"],
    "detection": {
      "selection": {
        "process.command_line": ["*CopyFromScreen*", "*Graphics.FromImage*"]
      }
    },
    "description": "Taking screenshots via PowerShell.",
    "response_steps": [
      "1. ISOLATE: Spyware behavior."
    ]
  },
  {
    "id": "PS_598_SAM_DUMP",
    "title": "PowerShell SAM Registry Dump",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*reg save HKLM\\SAM*", "*reg save HKLM\\SYSTEM*"]
      }
    },
    "description": "Dumping SAM/SYSTEM hives to extract hashes.",
    "response_steps": [
      "1. ISOLATE: Credential theft."
    ]
  },
  {
    "id": "PS_599_WIFI_CREDS",
    "title": "PowerShell WiFi Credential Theft",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1552.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*netsh wlan show profile*", "*key=clear*"]
      }
    },
    "description": "Dumping saved WiFi profiles and cleartext keys.",
    "response_steps": [
      "1. ROTATE: Change WiFi PSK."
    ]
  },
  {
    "id": "PS_600_DOMAIN_RECON",
    "title": "PowerShell Forest/Domain Recon",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1482"],
    "detection": {
      "selection": {
        "process.command_line": ["*Get-ADDomain*", "*Get-ADForest*", "*Get-ADTrust*"]
      }
    },
    "description": "Enumerating AD structure (Forests, Domains, Trusts).",
    "response_steps": [
      "1. CONTEXT: Admin or attacker?"
    ]
  },
  {
    "id": "PS_601_USER_SPN",
    "title": "PowerShell SPN Scanning (Kerberoasting)",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1558.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*Get-NetUser*", "*SPN*", "*servicePrincipalName*"]
      }
    },
    "description": "Scanning for users with Service Principal Names (SPN). Precursor to Kerberoasting.",
    "response_steps": [
      "1. MONITOR: Watch for TGS-REQ events (4769)."
    ]
  },
  {
    "id": "PS_602_RECYCLE_BIN",
    "title": "PowerShell RecycleBin Access",
    "severity": "MEDIUM",
    "module": "COLLECTION",
    "mitre": ["T1564"],
    "detection": {
      "selection": {
        "process.command_line": "*RecycleBin*"
      }
    },
    "description": "Accessing the Recycle Bin to find deleted sensitive files.",
    "response_steps": [
      "1. CHECK: Data recovery attempt?"
    ]
  },
  {
    "id": "PS_603_SCHEDULED_TASK",
    "title": "PowerShell Scheduled Task Create",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "process.command_line": ["*New-ScheduledTaskAction*", "*Register-ScheduledTask*"]
      }
    },
    "description": "Creating scheduled tasks via PowerShell cmdlets.",
    "response_steps": [
      "1. CHECK: Task name and action."
    ]
  },
  {
    "id": "PS_604_SERVICE_CREATE",
    "title": "PowerShell Service Creation",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*New-Service*", "*Set-Service*"]
      }
    },
    "description": "Creating or modifying services via PowerShell.",
    "response_steps": [
      "1. CHECK: Service binPath."
    ]
  },
  {
    "id": "PS_605_FIREWALL_MOD",
    "title": "PowerShell Firewall Disable",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.004"],
    "detection": {
      "selection": {
        "process.command_line": ["*Set-NetFirewallProfile*", "*False*", "*Disabled*"]
      }
    },
    "description": "Disabling Windows Firewall profiles.",
    "response_steps": [
      "1. ENABLE: Restore firewall immediately."
    ]
  },
  {
    "id": "PS_606_DEFENDER_EXCLUSION",
    "title": "PowerShell Defender Exclusion",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*Add-MpPreference*", "*ExclusionPath*"]
      }
    },
    "description": "Adding exclusions to Windows Defender.",
    "response_steps": [
      "1. CHECK: What path was excluded?"
    ]
  },
  {
    "id": "PS_607_STARTUP_FOLDER",
    "title": "PowerShell Startup Folder Write",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*Start Menu\\Programs\\Startup*", "*APPDATA*"]
      }
    },
    "description": "Writing files to the Startup folder.",
    "response_steps": [
      "1. FILE: Identify the payload."
    ]
  },
  {
    "id": "PS_608_COM_OBJECT",
    "title": "PowerShell COM Object Creation",
    "severity": "LOW",
    "module": "EXECUTION",
    "mitre": ["T1559.001"],
    "detection": {
      "selection": {
        "process.command_line": "*New-Object -ComObject*"
      }
    },
    "description": "Creating COM objects. Common but used for many attacks (Outlook, Excel, WScript).",
    "response_steps": [
      "1. CHECK: Which COM object?"
    ]
  },
  {
    "id": "PS_609_XML_RPC",
    "title": "PowerShell XML-RPC Usage",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.command_line": "*System.Xml.XmlRpc*"
      }
    },
    "description": "Usage of XML-RPC. Potential C2 channel.",
    "response_steps": [
      "1. CHECK: Destination."
    ]
  },
  {
    "id": "PS_610_RDP_ENABLE",
    "title": "PowerShell Enabling RDP",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*Set-ItemProperty*", "*fDenyTSConnections*", "*0*"]
      }
    },
    "description": "Enabling Remote Desktop via Registry modification.",
    "response_steps": [
      "1. CONTEXT: Did an admin do this?"
    ]
  }
];