import { Rule } from '@neonshapeshifter/logtower-engine';

export const BITS_PERSISTENCE_RULES: Rule[] = [
  {
    "id": "BITS_551_PERSISTENCE_NOTIFY",
    "title": "BITS Job Persistence (SetNotifyCmdLine)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1197", "T1547"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*/SetNotifyCmdLine*", "*/SetMinRetryDelay*"]
      }
    }
  },
  {
    "id": "BITS_552_ADS_DOWNLOAD",
    "title": "BITS Download to ADS (Hidden File)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1564.004"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*:*" 
      }
    }
  },
  {
    "id": "BITS_553_CUSTOM_HEADERS",
    "title": "BITS Custom Headers (C2 Evasion)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/SetCustomHeaders*"
      }
    }
  },
  {
    "id": "BITS_554_JOB_ENUMERATION",
    "title": "BITS Job Reconnaissance",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*/list*", "*/allusers*"]
      }
    }
  },
  {
    "id": "BITS_555_QMGR_DLL_LOAD",
    "title": "BITS COM Object Loaded (No Bitsadmin)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "image_load.file_name": ["qmgr.dll", "qmgrprxy.dll"],
        "process.image": ["*powershell.exe", "*pwsh.exe", "*wscript.exe", "*cscript.exe"]
      }
    }
  },
  {
    "id": "BITS_556_UPLOAD_EXFIL",
    "title": "BITS Upload Job (Exfiltration)",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*/upload*", "*/addfilerange*"]
      }
    }
  },
  {
    "id": "BITS_557_IGNORE_CERTS",
    "title": "BITS Ignore SSL Errors (SecurityFlags)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1197", "T1562"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*/SetSecurityFlags*", "*0x000033E0*", "*13280*", "*0x*"] 
      }
    }
  },
  {
    "id": "BITS_558_MIN_RETRY_DELAY",
    "title": "BITS MinRetryDelay Abuse (Rapid Callback)",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/SetMinRetryDelay*"
      }
    }
  },
  {
    "id": "BITS_559_SET_PROXY",
    "title": "BITS Custom Proxy Settings",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/SetProxySettings*"
      }
    }
  },
  {
    "id": "BITS_560_SET_NOTIFY_FLAGS",
    "title": "BITS Suppress Notifications (Stealth)",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/SetNotifyFlags*"
      }
    }
  },
  {
    "id": "BITS_561_POWERSHELL_COM",
    "title": "BITS COM Object via PowerShell",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": ["*powershell.exe", "*pwsh.exe"],
        "process.command_line": ["*New-Object -ComObject*", "*BackgroundCopyManager*"]
      }
    }
  },
  {
    "id": "BITS_562_VBS_COM",
    "title": "BITS COM Object via VBScript",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": ["*wscript.exe", "*cscript.exe"],
        "process.command_line": ["*CreateObject*", "*BackgroundCopyManager*"]
      }
    }
  },
  {
    "id": "BITS_563_REG_PERSISTENCE",
    "title": "BITS Registry Persistence Detected",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Software\\Microsoft\\Windows\\CurrentVersion\\BITS\\Jobs*",
        "registry.details": "*NotifyCmdLine*" 
      }
    }
  },
  {
    "id": "BITS_564_EVENT_JOB_CREATE",
    "title": "BITS Job Created (EventLog)",
    "severity": "LOW",
    "module": "EXECUTION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "channel": "Microsoft-Windows-Bits-Client/Operational",
        "event_id": "3",
        "user.name": ["!SYSTEM", "!LOCAL SERVICE", "!NETWORK SERVICE"]
      }
    }
  },
  {
    "id": "BITS_565_EVENT_SUSP_URL",
    "title": "BITS Job with Suspicious URL (EventLog)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "channel": "Microsoft-Windows-Bits-Client/Operational",
        "event_id": ["59", "60"], 
        "bits.url": ["*.exe", "*.ps1", "*.vbs", "*.dll", "*.scr"]
      }
    }
  },
  {
    "id": "BITS_566_QMGR_ACCESS",
    "title": "Direct Access to BITS Database (QMGR)",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "file.name": ["qmgr.dat", "qmgr0.dat", "qmgr1.dat"],
        "process.image": ["!*svchost.exe"]
      }
    }
  },
  {
    "id": "BITS_567_TRANSFER_PE",
    "title": "BITS Transferring Executable",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*.exe", "*.dll", "*.scr"]
      }
    }
  },
  {
    "id": "BITS_568_TRANSFER_SCRIPT",
    "title": "BITS Transferring Script",
    "severity": "MEDIUM",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*.ps1", "*.vbs", "*.bat", "*.cmd", "*.js"]
      }
    }
  },
  {
    "id": "BITS_569_TRANSFER_ARCHIVE",
    "title": "BITS Transferring Archive (Exfil/Drop)",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*.zip", "*.rar", "*.7z", "*.tar"]
      }
    }
  },
  {
    "id": "BITS_570_REPL_OVERWRITE",
    "title": "BITS Overwriting System File",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*WindowsSystem32*", "*WindowsSysWOW64*"]
      }
    }
  },
  {
    "id": "BITS_571_JOB_OWNER_SYSTEM",
    "title": "BITS Job Created as SYSTEM (PrivEsc)",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "/create",
        "user.name": "SYSTEM"
      }
    }
  },
  {
    "id": "BITS_572_UNKNOWN_CLIENT",
    "title": "Unknown BITS Client (ImageLoad)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "image_load.file_name": "bits.dll",
        "process.image": ["!*svchost.exe", "!*bitsadmin.exe", "!*msiexec.exe", "!*wuauclt.exe"]
      }
    }
  },
  {
    "id": "BITS_573_LOCAL_FILE_COPY",
    "title": "BITS Local File Copy (Lateral Move Prep)",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*\\localhost*", "*\\127.0.0.1*"]
      }
    }
  },
  {
    "id": "BITS_574_COMPLETE_JOB",
    "title": "BITS Complete Job (Execution Trigger)",
    "severity": "LOW",
    "module": "EXECUTION",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/complete*"
      }
    }
  },
  {
    "id": "BITS_575_CANCEL_JOB",
    "title": "BITS Cancel Job (Anti-Forensics)",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1070"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/cancel*"
      }
    }
  },
  {
    "id": "BITS_576_RESET_ALL",
    "title": "BITS Reset (Mass Cleanup)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1070"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": "*/reset*"
      }
    }
  }
];
