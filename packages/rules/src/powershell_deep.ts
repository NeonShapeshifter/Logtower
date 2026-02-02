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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  }
];
