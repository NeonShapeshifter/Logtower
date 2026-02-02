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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  }
];