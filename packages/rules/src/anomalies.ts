import { Rule } from '@neonshapeshifter/logtower-engine';

export const ANOMALY_RULES: Rule[] = [
  {
    "id": "GEN_301_CALC_SPAWN",
    "title": "Calc.exe Spawning Process",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.parent_image": "*calc.exe",
        "process.image": ["*cmd.exe", "*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Calc.exe spawning a command shell. This is a classic process injection indicator (e.g., Meterpreter migrated into calc.exe).",
    "response_steps": [
      "1. ISOLATE: High confidence compromised process.",
      "2. DUMP: Dump process memory to find the injected payload."
    ]
  },
  {
    "id": "GEN_302_NOTEPAD_SPAWN",
    "title": "Notepad Spawning Shell",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.parent_image": "*notepad.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Notepad.exe spawning a shell. Users don't do this; injected code does.",
    "response_steps": [
      "1. ISOLATE: Confirmed injection.",
      "2. PARENT: Check who launched notepad originally."
    ]
  },
  {
    "id": "GEN_303_MSPAINT_SPAWN",
    "title": "MsPaint Spawning Shell",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.parent_image": "*mspaint.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "MsPaint spawning a shell. Common target for simple process migration.",
    "response_steps": [
      "1. ISOLATE: Confirmed injection."
    ]
  },
  {
    "id": "GEN_304_SVCHOST_SPAWN_CMD",
    "title": "Svchost Spawning CMD",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1059.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*svchost.exe",
        "process.image": "*cmd.exe"
      }
    },
    "description": "Svchost.exe spawning cmd.exe. Services almost never launch interactive shells directly.",
    "response_steps": [
      "1. SERVICE: Identify which service hosts this svchost (tasklist /svc).",
      "2. COMMAND: What did it execute?"
    ]
  },
  {
    "id": "GEN_305_SVCHOST_SPAWN_PS",
    "title": "Svchost Spawning PowerShell",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1059.001"],
    "detection": {
      "selection": {
        "process.parent_image": "*svchost.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Svchost.exe spawning PowerShell. Could be a compromised service or lateral movement (WMI/WinRM) execution.",
    "response_steps": [
      "1. SERVICE: Identify the service.",
      "2. LOGS: Check PowerShell logs."
    ]
  },
  {
    "id": "GEN_306_LSASS_SPAWN",
    "title": "LSASS Spawning Process",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.parent_image": "*lsass.exe",
        "process.image": ["!*WerFault.exe"]
      }
    },
    "description": "LSASS spawning a child process. Extremely rare. Likely credential theft (SSP injection) or persistence mechanism.",
    "response_steps": [
      "1. ISOLATE: Critical system process compromised.",
      "2. CHILD: What is the child process?"
    ]
  },
  {
    "id": "GEN_307_SPOOLSV_SPAWN",
    "title": "Spoolsv Spawning Shell (PrintNightmare)",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "process.parent_image": "*spoolsv.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Print Spooler service spawning a shell. High fidelity indicator of PrintNightmare or similar spooler exploits.",
    "response_steps": [
      "1. ISOLATE: SYSTEM compromise.",
      "2. DISABLE: Stop Spooler service."
    ]
  },
  {
    "id": "GEN_308_DWM_SPAWN",
    "title": "DWM Spawning Shell",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.parent_image": "*dwm.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Desktop Window Manager spawning a shell. Anomaly.",
    "response_steps": [
      "1. CHECK: Process injection."
    ]
  },
  {
    "id": "GEN_309_LOGONUI_SPAWN",
    "title": "LogonUI Spawning Process (Accessibility Abuse)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.008"],
    "detection": {
      "selection": {
        "process.parent_image": "*logonui.exe",
        "process.image": ["*cmd.exe", "*powershell.exe", "*taskmgr.exe"]
      }
    },
    "description": "LogonUI (Login Screen) spawning a process. Indicates Sticky Keys / Accessibility backdoor trigger.",
    "response_steps": [
      "1. CHECK: Did someone press Shift 5 times?",
      "2. ISOLATE: Backdoor confirmed."
    ]
  },
  {
    "id": "GEN_310_EXPLORER_PARENT_ANOMALY",
    "title": "Process Falsely Claiming Explorer Parent",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1134.004"],
    "detection": {
      "selection": {
        "process.parent_image": "*explorer.exe",
        "process.image": "*svchost.exe"
      }
    },
    "description": "Explorer.exe spawning svchost.exe. Svchost should only be spawned by services.exe. Indicates Parent PID Spoofing.",
    "response_steps": [
      "1. CHECK: Verify parent-child relationship via start times.",
      "2. ISOLATE: Evasion technique."
    ]
  },
  {
    "id": "OFF_311_OFFICE_WSCRIPT",
    "title": "Office Spawning WScript",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": ["*wscript.exe", "*cscript.exe"]
      }
    },
    "description": "Office app launching WScript. Macro executing VBS/JS payload.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_312_OFFICE_RUNDLL",
    "title": "Office Spawning Rundll32",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*rundll32.exe"
      }
    },
    "description": "Office app launching Rundll32. Macro loading malicious DLL.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_313_OFFICE_REGSVR",
    "title": "Office Spawning Regsvr32",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*regsvr32.exe"
      }
    },
    "description": "Office app launching Regsvr32. Macro executing SCT/DLL payload.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_314_OFFICE_MSHTA",
    "title": "Office Spawning Mshta",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*mshta.exe"
      }
    },
    "description": "Office app launching Mshta. Macro executing HTA payload.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_315_OFFICE_CERTUTIL",
    "title": "Office Spawning Certutil",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*certutil.exe"
      }
    },
    "description": "Office app launching Certutil. Macro downloading payload.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_316_OFFICE_BITSADMIN",
    "title": "Office Spawning Bitsadmin",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*bitsadmin.exe"
      }
    },
    "description": "Office app launching Bitsadmin. Macro downloading payload.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_317_OFFICE_SCHTASKS",
    "title": "Office Spawning Schtasks",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*schtasks.exe"
      }
    },
    "description": "Office app launching Schtasks. Macro establishing persistence.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_318_OFFICE_REG",
    "title": "Office Spawning Reg",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*reg.exe"
      }
    },
    "description": "Office app launching Reg.exe. Macro modifying registry (persistence/evasion).",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_319_OFFICE_WMIC",
    "title": "Office Spawning WMIC",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": "*wmic.exe"
      }
    },
    "description": "Office app launching WMIC. Macro using WMI for recon/execution.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "OFF_320_OFFICE_UNKNOWN",
    "title": "Office Spawning Unknown EXE from Temp",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.parent_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"],
        "process.image": ["*\\AppData\\Local\\Temp*", "*\\Users\\Public*"]
      }
    },
    "description": "Office app launching binary from Temp. Dropped malware execution.",
    "response_steps": [
      "1. FILE: Identify document.",
      "2. ISOLATE: Active exploitation."
    ]
  },
  {
    "id": "DL_321_CERTUTIL_URLCACHE",
    "title": "Certutil Download",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*certutil.exe",
        "process.command_line": ["*urlcache*", "*-f *"]
      }
    },
    "description": "Certutil download command.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_322_BITSADMIN_TRANSFER",
    "title": "Bitsadmin Transfer",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "process.command_line": ["*/transfer*", "*/addfile*"]
      }
    },
    "description": "Bitsadmin file transfer.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_323_CURL_DOWNLOAD",
    "title": "Curl Download",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*curl.exe",
        "process.command_line": ["*-O *", "*-o *", "*http*"]
      }
    },
    "description": "Curl downloading a file.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_324_FINGER_DOWNLOAD",
    "title": "Finger Download",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*finger.exe",
        "process.command_line": "*@*"
      }
    },
    "description": "Finger.exe file download.",
    "response_steps": [
      "1. CHECK: Rare legacy abuse."
    ]
  },
  {
    "id": "DL_325_MPCMDRUN_DOWNLOAD",
    "title": "MpCmdRun Download (Defender Abuse)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*MpCmdRun.exe",
        "process.command_line": "*DownloadFile*"
      }
    },
    "description": "Windows Defender CLI used to download file.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_326_DESKTOPIMG_DOWNLOAD",
    "title": "DesktopImgDownldr Download",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*desktopimgdownldr.exe",
        "process.command_line": "*lockscreenurl*"
      }
    },
    "description": "DesktopImgDownldr used to download file.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_327_IMEPAD_DOWNLOAD",
    "title": "IMEPAD Download",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*imepad.exe",
        "process.command_line": "*-c*"
      }
    },
    "description": "IMEPAD used for download.",
    "response_steps": [
      "1. CHECK: Rare LOLBin."
    ]
  },
  {
    "id": "DL_328_HH_DOWNLOAD",
    "title": "HH.exe Remote Execution/Download",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1218.001"],
    "detection": {
      "selection": {
        "process.image": "*hh.exe",
        "process.command_line": "*http*"
      }
    },
    "description": "HH.exe opening remote content.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "DL_329_REGSVR_URL",
    "title": "Regsvr32 Remote Script",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1218.010"],
    "detection": {
      "selection": {
        "process.image": "*regsvr32.exe",
        "process.command_line": "*http*"
      }
    },
    "description": "Regsvr32 loading remote script object.",
    "response_steps": [
      "1. URL: C2 domain."
    ]
  },
  {
    "id": "DL_330_MSHTA_URL",
    "title": "Mshta Remote Execution",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1218.005"],
    "detection": {
      "selection": {
        "process.image": "*mshta.exe",
        "process.command_line": "*http*"
      }
    },
    "description": "Mshta executing remote HTA.",
    "response_steps": [
      "1. URL: C2 domain."
    ]
  },
  {
    "id": "LOC_331_PERFLOGS",
    "title": "Execution from PerfLogs",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*\\PerfLogs*"
      }
    },
    "description": "Execution from PerfLogs directory. Common hiding spot.",
    "response_steps": [
      "1. CHECK: Why is a binary here?"
    ]
  },
  {
    "id": "LOC_332_PUBLIC_USER",
    "title": "Execution from Users Public",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*\\Users\\Public*"
      }
    },
    "description": "Execution from Public profile. Globally writable.",
    "response_steps": [
      "1. CHECK: Malware location."
    ]
  },
  {
    "id": "LOC_333_ROOT_C",
    "title": "Execution from C Drive Root",
    "severity": "LOW",
    "module": "ANOMALY",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": ["C:*.exe", "C:*.bat", "C:*.ps1", "!C:\\Windows*", "!C:\\Program Files*", "!C:\\Program Files (x86)*", "!*install*", "!*setup*", "!*update*"]
      }
    },
    "description": "Execution directly from C: root.",
    "response_steps": [
      "1. CHECK: Bad practice or malware?"
    ]
  },
  {
    "id": "LOC_334_INTEL_FOLDER",
    "title": "Execution from Intel Folder",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*\\Intel*"
      }
    },
    "description": "Execution from C:\\Intel. Often writable.",
    "response_steps": [
      "1. CHECK: Malware location."
    ]
  },
  {
    "id": "LOC_335_TEMP_EXEC",
    "title": "Execution from Temp",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp*"]
      }
    },
    "description": "Execution from Temp folder. Standard dropper behavior.",
    "response_steps": [
      "1. SAMPLE: Retrieve binary."
    ]
  },
  {
    "id": "LOC_336_DOWNLOADS_EXEC",
    "title": "Execution from Downloads",
    "severity": "LOW",
    "module": "EXECUTION",
    "mitre": ["T1204.002"],
    "detection": {
      "selection": {
        "process.image": "*\\Downloads*"
      }
    },
    "description": "Execution from Downloads.",
    "response_steps": [
      "1. CHECK: User downloaded content."
    ]
  },
  {
    "id": "LOC_337_RECYCLE_BIN",
    "title": "Execution from Recycle Bin",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1564"],
    "detection": {
      "selection": {
        "process.image": "*$Recycle.Bin*"
      }
    },
    "description": "Execution from Recycle Bin. Confirmed malware.",
    "response_steps": [
      "1. ISOLATE: Malicious."
    ]
  },
  {
    "id": "LOC_338_FONTS_EXEC",
    "title": "Execution from Fonts Folder",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*\\Windows\\Fonts*"
      }
    },
    "description": "Execution from Fonts folder. Unusual.",
    "response_steps": [
      "1. CHECK: Malware location."
    ]
  },
  {
    "id": "LOC_339_MUSIC_PICTURES",
    "title": "Execution from Media Folders",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": ["*\\Music*", "*\\Pictures*", "*\\Videos*"]
      }
    },
    "description": "Execution from Media folders.",
    "response_steps": [
      "1. CHECK: Malware location."
    ]
  },
  {
    "id": "LOC_340_HIDDEN_FOLDER",
    "title": "Execution from Hidden Folder",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1564.001"],
    "detection": {
      "selection": {
        "process.image": "*\\.**"
      }
    },
    "description": "Execution from dot folder (Unix style hidden).",
    "response_steps": [
      "1. CHECK: Malware location."
    ]
  },
  {
    "id": "PROXY_341_CONTROL_CPL",
    "title": "Control.exe executing CPL",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1218.002"],
    "detection": {
      "selection": {
        "process.image": "*control.exe",
        "process.command_line": "*.cpl*"
      }
    },
    "description": "Control panel item execution.",
    "response_steps": [
      "1. FILE: Identify .cpl file."
    ]
  },
  {
    "id": "PROXY_342_PCALUA",
    "title": "Pcalua Proxy Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.image": "*pcalua.exe",
        "process.command_line": "*-a*"
      }
    },
    "description": "Pcalua.exe executing a binary.",
    "response_steps": [
      "1. CHECK: Evasion."
    ]
  },
  {
    "id": "PROXY_343_FORFILES",
    "title": "Forfiles Proxy Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.image": "*forfiles.exe",
        "process.command_line": ["*/c*", "*/m*"]
      }
    },
    "description": "Forfiles spawning command.",
    "response_steps": [
      "1. CHECK: Parent chain break."
    ]
  },
  {
    "id": "PROXY_344_MAVINJECT",
    "title": "Mavinject Code Injection",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "process.image": "*mavinject.exe",
        "process.command_line": "*INJECTRUNNING*"
      }
    },
    "description": "Mavinject injecting DLL.",
    "response_steps": [
      "1. ISOLATE: MS signed injector."
    ]
  },
  {
    "id": "PROXY_345_INFDEFAULT",
    "title": "InfDefaultInstall Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.image": "*InfDefaultInstall.exe"
      }
    },
    "description": "INF execution.",
    "response_steps": [
      "1. CHECK: What INF?"
    ]
  },
  {
    "id": "PROXY_346_RUNONCE_WRAPPER",
    "title": "RunOnce.exe Wrapper Execution",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.image": "*runonce.exe",
        "process.command_line": ["*/r*", "*cmd.exe*", "*powershell.exe*"]
      }
    },
    "description": "Runonce executing shell.",
    "response_steps": [
      "1. CHECK: Persistence trigger."
    ]
  },
  {
    "id": "PROXY_347_WMIC_PROCESS",
    "title": "WMIC Process Call Create",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.image": "*wmic.exe",
        "process.command_line": ["*process*", "*call*", "*create*"]
      }
    },
    "description": "WMIC spawning process.",
    "response_steps": [
      "1. COMMAND: What executed?"
    ]
  },
  {
    "id": "PROXY_348_ADVPACK",
    "title": "Advpack.dll Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.command_line": ["*rundll32*", "*advpack.dll*"]
      }
    },
    "description": "Advpack.dll execution.",
    "response_steps": [
      "1. CHECK: Evasion."
    ]
  },
  {
    "id": "PROXY_349_ZIPFLDR",
    "title": "Zipfldr.dll RouteTheArgs",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.command_line": ["*rundll32*", "*zipfldr.dll*", "*RouteTheCall*"]
      }
    },
    "description": "Zipfldr execution.",
    "response_steps": [
      "1. CHECK: Evasion."
    ]
  },
  {
    "id": "PROXY_350_IEEXEC",
    "title": "IEExec Managed Code Execution",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1127"],
    "detection": {
      "selection": {
        "process.image": "*ieexec.exe",
        "process.command_line": "*http*"
      }
    },
    "description": "IEExec remote execution.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "CONT_501_DOCKER_PRIV",
    "title": "Docker Privileged Container",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1610"],
    "detection": {
      "selection": {
        "process.command_line": ["*docker run*", "*--privileged*"]
      }
    },
    "description": "Starting a privileged Docker container. Breakout risk.",
    "response_steps": [
      "1. VERIFY: Authorized?"
    ]
  },
  {
    "id": "CONT_502_DOCKER_MOUNT_ROOT",
    "title": "Docker Mounting Host Root",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1610"],
    "detection": {
      "selection": {
        "process.command_line": ["*docker run*", "*-v /:*", "*-v /root*"]
      }
    },
    "description": "Mounting host root filesystem into container.",
    "response_steps": [
      "1. ISOLATE: Host compromise risk."
    ]
  },
  {
    "id": "CONT_503_KUBECTL_EXEC",
    "title": "Kubectl Exec (Shell in Container)",
    "severity": "MEDIUM",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1609"],
    "detection": {
      "selection": {
        "process.command_line": ["*kubectl exec*", "*-it*", "*/bin/bash*", "*/bin/sh*"]
      }
    },
    "description": "Interactive shell in Kubernetes pod.",
    "response_steps": [
      "1. CONTEXT: Debugging or attack?"
    ]
  },
  {
    "id": "CONT_504_WSL_HOST_ACCESS",
    "title": "WSL Accessing Host Files",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.command_line": ["*wsl*", "*/mnt/c/*"]
      }
    },
    "description": "WSL accessing Windows filesystem.",
    "response_steps": [
      "1. CHECK: What files?"
    ]
  },
  {
    "id": "CONT_505_DOCKER_SOCK",
    "title": "Docker Socket Exposure",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1610"],
    "detection": {
      "selection": {
        "process.command_line": ["*-v /var/run/docker.sock*"]
      }
    },
    "description": "Mounting docker socket. Grants root equivalent.",
    "response_steps": [
      "1. ISOLATE: Configuration error."
    ]
  },
  {
    "id": "BROW_506_CHROME_DEBUG",
    "title": "Chrome Remote Debugging",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.command_line": ["*chrome.exe*", "*--remote-debugging-port*"]
      }
    },
    "description": "Chrome started with remote debugging. Allows cookie theft.",
    "response_steps": [
      "1. ISOLATE: Cookie theft risk."
    ]
  },
  {
    "id": "BROW_507_EDGE_DEBUG",
    "title": "Edge Remote Debugging",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.command_line": ["*msedge.exe*", "*--remote-debugging-port*"]
      }
    },
    "description": "Edge started with remote debugging.",
    "response_steps": [
      "1. ISOLATE: Cookie theft risk."
    ]
  },
  {
    "id": "BROW_508_MALICIOUS_EXT",
    "title": "Browser Loading Unpacked Extension",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1176"],
    "detection": {
      "selection": {
        "process.command_line": ["*--load-extension*"]
      }
    },
    "description": "Loading unpacked browser extension.",
    "response_steps": [
      "1. CHECK: Extension source."
    ]
  },
  {
    "id": "BROW_509_HEADLESS_MODE",
    "title": "Browser Headless Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.command_line": ["*--headless*"]
      }
    },
    "description": "Browser running in headless mode.",
    "response_steps": [
      "1. CONTEXT: Automation or malware?"
    ]
  },
  {
    "id": "BROW_510_DISABLING_SECURITY",
    "title": "Browser Disabling Web Security",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*--disable-web-security*"]
      }
    },
    "description": "Disabling browser security features (CORS, etc).",
    "response_steps": [
      "1. ISOLATE: Risky configuration."
    ]
  },
  {
    "id": "USB_511_EXEC_REMOVABLE",
    "title": "Execution from Removable Drive",
    "severity": "MEDIUM",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1091"],
    "detection": {
      "selection": {
        "process.image": ["D:\\*", "E:\\*", "F:\\*", "G:\\*"] // Approximate
      }
    },
    "description": "Execution from non-system drive letters (potential USB).",
    "response_steps": [
      "1. CHECK: Removable media."
    ]
  },
  {
    "id": "USB_512_USB_SPREADER",
    "title": "USB Worm Behavior (Copy to Root)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1091"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy*", "*.exe", "*:\\*"]
      }
    },
    "description": "Copying executables to drive root. Worm behavior.",
    "response_steps": [
      "1. ISOLATE: Worm spreading."
    ]
  },
  {
    "id": "USB_513_MOUNTPOINTS2",
    "title": "Registry MountPoints2 Abuse",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "registry.target_object": "*MountPoints2*"
      }
    },
    "description": "Modification of MountPoints2 (AutoRun for USB).",
    "response_steps": [
      "1. CLEAN: Remove key."
    ]
  },
  {
    "id": "USB_514_IMAGELOAD_USB",
    "title": "DLL Loaded from USB",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1091"],
    "detection": {
      "selection": {
        "image_load.file_path": ["D:\\*", "E:\\*"]
      }
    },
    "description": "Loading DLL from removable drive.",
    "response_steps": [
      "1. CHECK: Sideloading?"
    ]
  },
  {
    "id": "USB_515_EXFIL_TO_USB",
    "title": "Potential Exfiltration to USB",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1052"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy*", "*secret*", "*:\\*"]
      }
    },
    "description": "Copying sensitive files to external drive.",
    "response_steps": [
      "1. CHECK: Data loss."
    ]
  },
  {
    "id": "RDP_516_REG_ENABLE",
    "title": "RDP Enabled via Registry",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*fDenyTSConnections*",
        "registry.details": "0"
      }
    },
    "description": "Enabling RDP via Registry.",
    "response_steps": [
      "1. CHECK: Unauthorized remote access."
    ]
  },
  {
    "id": "RDP_517_ALLOW_FIREWALL",
    "title": "RDP Allowed in Firewall",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.004"],
    "detection": {
      "selection": {
        "process.command_line": ["*netsh*", "*firewall*", "*3389*"]
      }
    },
    "description": "Opening RDP port in firewall.",
    "response_steps": [
      "1. CHECK: Unauthorized access."
    ]
  },
  {
    "id": "RDP_518_REVERSE_RDP",
    "title": "Reverse RDP Tunneling (Plink/Ssh)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.command_line": ["*:3389*"]
      }
    },
    "description": "Tunneling RDP port.",
    "response_steps": [
      "1. ISOLATE: Bypass firewall."
    ]
  },
  {
    "id": "RDP_519_SHADOW_SESSION",
    "title": "RDP Shadow Session (Spying)",
    "severity": "HIGH",
    "module": "COLLECTION",
    "mitre": ["T1113"],
    "detection": {
      "selection": {
        "process.command_line": ["*mstsc*", "*/shadow:*"]
      }
    },
    "description": "Shadowing an RDP session to view user activity.",
    "response_steps": [
      "1. ISOLATE: Spying."
    ]
  },
  {
    "id": "RDP_520_STICKY_KEYS_RDP",
    "title": "Sticky Keys Over RDP",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.008"],
    "detection": {
      "selection": {
        "process.image": "sethc.exe"
      }
    },
    "description": "Sticky keys execution (potential backdoor trigger).",
    "response_steps": [
      "1. CHECK: Parent process."
    ]
  },
  {
    "id": "INST_521_MSI_URL",
    "title": "MSI Install from URL",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.command_line": ["*msiexec*", "*http*"]
      }
    },
    "description": "MSIExec installing from URL.",
    "response_steps": [
      "1. URL: Check source."
    ]
  },
  {
    "id": "INST_522_MSI_QUIET_SYSTEM",
    "title": "MSI Quiet Install as System",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.command_line": ["*msiexec*", "*/q*"]
      }
    },
    "description": "Silent MSI installation.",
    "response_steps": [
      "1. CHECK: What was installed?"
    ]
  },
  {
    "id": "INST_523_MSI_TEMP",
    "title": "MSI Executing from Temp",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.command_line": ["*msiexec*", "*Temp*"]
      }
    },
    "description": "MSIExec running file from Temp.",
    "response_steps": [
      "1. FILE: Identify package."
    ]
  },
  {
    "id": "INST_524_RUNONCE_INSTALLER",
    "title": "RunOnceEx Registry Abuse",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*RunOnceEx*"
      }
    },
    "description": "Modification of RunOnceEx.",
    "response_steps": [
      "1. CLEAN: Remove persistence."
    ]
  },
  {
    "id": "INST_525_ALWAYS_INSTALL_ELEVATED",
    "title": "AlwaysInstallElevated Policy",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1548.002"],
    "detection": {
      "selection": {
        "registry.target_object": "*AlwaysInstallElevated*",
        "registry.details": "1"
      }
    },
    "description": "Setting AlwaysInstallElevated. Allows any user to install MSI as SYSTEM.",
    "response_steps": [
      "1. REVERT: Disable policy immediately."
    ]
  },
  {
    "id": "AZ_526_AZ_CLI_LOGIN",
    "title": "Azure CLI Login Attempt",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1078.004"],
    "detection": {
      "selection": {
        "process.image": "*az.cmd",
        "process.command_line": "*login*"
      }
    },
    "description": "Azure CLI login.",
    "response_steps": [
      "1. CONTEXT: Authorized cloud access?"
    ]
  },
  {
    "id": "AZ_527_AZ_VM_RUN_COMMAND",
    "title": "Azure VM Run Command",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.command_line": "*run-command*"
      }
    },
    "description": "Azure Run Command execution.",
    "response_steps": [
      "1. CHECK: Remote execution from cloud console."
    ]
  },
  {
    "id": "AZ_528_WAAGENT_ABUSE",
    "title": "Windows Azure Agent Suspicious Child",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "process.parent_image": "*WaAppAgent.exe"
      }
    },
    "description": "Azure Agent spawning unknown process.",
    "response_steps": [
      "1. CHECK: Extension activity."
    ]
  },
  {
    "id": "AZ_529_METADATA_SERVICE",
    "title": "Azure Metadata Service Access",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1552"],
    "detection": {
      "selection": {
        "process.command_line": "*169.254.169.254*"
      }
    },
    "description": "Accessing cloud metadata service (IMDS). Used to steal tokens.",
    "response_steps": [
      "1. BLOCK: Unnecessary process access."
    ]
  },
  {
    "id": "OFF_530_OUTLOOK_VBA_ENABLE",
    "title": "Outlook VBA Security Disabled",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*Security\\Level*",
        "registry.details": "1"
      }
    },
    "description": "Lowering Outlook macro security settings.",
    "response_steps": [
      "1. REVERT: Enforce high security."
    ]
  },
  {
    "id": "WMI_531_WIN32_PROCESS_CREATE",
    "title": "WMI Win32_Process Create",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.command_line": ["*Win32_Process*", "*Create*"]
      }
    },
    "description": "Creating process via WMI.",
    "response_steps": [
      "1. COMMAND: What process?"
    ]
  },
  {
    "id": "WMI_532_SHADOWCOPY_DEL",
    "title": "WMIC Delete ShadowCopy",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*shadowcopy*", "*delete*"]
      }
    },
    "description": "Deleting shadow copies via WMIC.",
    "response_steps": [
      "1. ISOLATE: Ransomware."
    ]
  },
  {
    "id": "WMI_533_OS_RECON",
    "title": "WMIC OS Reconnaissance",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1082"],
    "detection": {
      "selection": {
        "process.command_line": ["*os get*", "*os list*"]
      }
    },
    "description": "OS enumeration via WMIC.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "WMI_534_USER_RECON",
    "title": "WMIC User Account Recon",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "process.command_line": ["*useraccount list*"]
      }
    },
    "description": "User enumeration via WMIC.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "WMI_535_STARTUP_LIST",
    "title": "WMIC Startup List Recon",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1083"],
    "detection": {
      "selection": {
        "process.command_line": ["*startup list*"]
      }
    },
    "description": "Startup item enumeration via WMIC.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "MISC_536_WERFAULT_SUSP",
    "title": "WerFault Suspicious Parent",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*WerFault.exe",
        "process.parent_image": ["!*svchost.exe", "!*wermgr.exe"]
      }
    },
    "description": "WerFault.exe spawned by unexpected parent. Hollowing indicator.",
    "response_steps": [
      "1. ISOLATE: Hollowing."
    ]
  },
  {
    "id": "MISC_537_CONHOST_CHILD",
    "title": "Conhost.exe Suspicious Parent",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*conhost.exe"
      }
    },
    "description": "Conhost.exe anomaly.",
    "response_steps": [
      "1. CHECK: Process tree."
    ]
  },
  {
    "id": "MISC_538_TASKMGR_PARENT",
    "title": "Taskmgr Spawning Unknown",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.parent_image": "*taskmgr.exe"
      }
    },
    "description": "Task Manager spawning unexpected child.",
    "response_steps": [
      "1. PROCESS: What did it launch?"
    ]
  },
  {
    "id": "MISC_539_DLLHOST_NET",
    "title": "DllHost.exe Network Connection",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*dllhost.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "DllHost making network connections. Could be COM surrogate abuse.",
    "response_steps": [
      "1. CHECK: Destination."
    ]
  },
  {
    "id": "MISC_540_NOTEPAD_NET",
    "title": "Notepad.exe Network Connection",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*notepad.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "Notepad making network connections. Confirmed code injection.",
    "response_steps": [
      "1. ISOLATE: Malware."
    ]
  },
  {
    "id": "SHIM_541_SDBINST",
    "title": "Sdbinst.exe Shim Installation",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.011"],
    "detection": {
      "selection": {
        "process.image": "*sdbinst.exe"
      }
    },
    "description": "Installation of Application Shim.",
    "response_steps": [
      "1. CHECK: What SDB file?"
    ]
  },
  {
    "id": "SHIM_542_CUSTOM_SHIM",
    "title": "Custom Shim Database File",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.011"],
    "detection": {
      "selection": {
        "process.command_line": "*.sdb"
      }
    },
    "description": "Usage of custom .sdb file.",
    "response_steps": [
      "1. ANALYZE: Parse SDB."
    ]
  },
  {
    "id": "DRV_543_DRIVER_SIGN_OFF",
    "title": "Disabling Driver Signature Enforcement",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*nointegritychecks*"]
      }
    },
    "description": "Disabling driver signature checks. Allows loading malicious drivers (rootkits).",
    "response_steps": [
      "1. ISOLATE: Rootkit prep."
    ]
  },
  {
    "id": "EVT_544_EVENT_SERVICE_STOP",
    "title": "Stopping EventLog Service",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*stop*", "*EventLog*"]
      }
    },
    "description": "Stopping Windows Event Log service.",
    "response_steps": [
      "1. ISOLATE: Blinding sensors."
    ]
  },
  {
    "id": "PRT_545_PRINTER_DRIVER_ADD",
    "title": "Suspicious Printer Driver Add",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "process.command_line": ["*Add-PrinterDriver*"]
      }
    },
    "description": "Adding printer driver. Possible PrintNightmare exploitation.",
    "response_steps": [
      "1. CHECK: Driver source."
    ]
  },
  {
    "id": "WMI_546_MOFCOMP",
    "title": "Mofcomp.exe MOF Compilation",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "process.image": "*mofcomp.exe"
      }
    },
    "description": "Compiling MOF file into WMI.",
    "response_steps": [
      "1. CHECK: MOF content."
    ]
  },
  {
    "id": "COM_547_MMC_SPAWN",
    "title": "MMC Spawning Shell",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.parent_image": "*mmc.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "MMC spawning shell. DCOM lateral movement via MMC20.Application.",
    "response_steps": [
      "1. ISOLATE: Lateral movement."
    ]
  },
  {
    "id": "COM_548_SERVICES_SPAWN_CMD",
    "title": "Services.exe Spawning CMD",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*services.exe",
        "process.image": "*cmd.exe"
      }
    },
    "description": "Services.exe spawning cmd.exe. Malicious service execution.",
    "response_steps": [
      "1. ISOLATE: System compromise."
    ]
  },
  {
    "id": "COM_549_WINLOGON_SPAWN",
    "title": "Winlogon Spawning Shell (Non-Userinit)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.004"],
    "detection": {
      "selection": {
        "process.parent_image": "*winlogon.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Winlogon spawning shell. Persistence trigger or credential provider abuse.",
    "response_steps": [
      "1. ISOLATE: Critical persistence."
    ]
  },
  {
    "id": "HUNT_550_ETW_TRACE_STOP",
    "title": "Stopping ETW Trace Session",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*logman*", "*stop*"]
      }
    },
    "description": "Stopping ETW trace session.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
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
    },
    "description": "Setting BITS notify command line. Persistent execution.",
    "response_steps": [
      "1. CLEAN: Clear BITS jobs."
    ]
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
    },
    "description": "BITS downloading to Alternate Data Stream.",
    "response_steps": [
      "1. CHECK: Hiding payload."
    ]
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
    },
    "description": "Setting custom headers on BITS job. Used for C2 comms.",
    "response_steps": [
      "1. CHECK: C2 profile."
    ]
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
    },
    "description": "Listing BITS jobs.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
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
    },
    "description": "Loading BITS DLLs manually. Using BITS API without bitsadmin.",
    "response_steps": [
      "1. CHECK: Stealthy BITS usage."
    ]
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
    },
    "description": "Creating BITS upload job. Data exfiltration.",
    "response_steps": [
      "1. URL: Destination server."
    ]
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
    },
    "description": "Ignoring SSL cert errors in BITS. Used for self-signed C2.",
    "response_steps": [
      "1. CHECK: C2 evasion."
    ]
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
    },
    "description": "Setting short retry delay. Faster C2 polling.",
    "response_steps": [
      "1. CHECK: C2 tuning."
    ]
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
    },
    "description": "Setting custom proxy for BITS.",
    "response_steps": [
      "1. CHECK: Bypassing network controls."
    ]
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
    },
    "description": "Suppressing BITS notifications.",
    "response_steps": [
      "1. CHECK: Stealth."
    ]
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
    },
    "description": "Using BITS COM object in PowerShell.",
    "response_steps": [
      "1. CHECK: Script analysis."
    ]
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
    },
    "description": "Using BITS COM object in VBS.",
    "response_steps": [
      "1. CHECK: Script analysis."
    ]
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
    },
    "description": "Detection of BITS job persistence in Registry.",
    "response_steps": [
      "1. CLEAN: Delete registry key."
    ]
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
    },
    "description": "BITS Job created by user.",
    "response_steps": [
      "1. CHECK: User intent."
    ]
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
    },
    "description": "BITS job downloading executable content.",
    "response_steps": [
      "1. URL: Check source."
    ]
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
    },
    "description": "Non-system process accessing BITS database. Tampering.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
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
    },
    "description": "BITS transferring PE file.",
    "response_steps": [
      "1. URL: Check source."
    ]
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
    },
    "description": "BITS transferring script.",
    "response_steps": [
      "1. URL: Check source."
    ]
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
    },
    "description": "BITS transferring archive.",
    "response_steps": [
      "1. URL: Check destination/source."
    ]
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
    },
    "description": "BITS overwriting system files.",
    "response_steps": [
      "1. ISOLATE: Destructive attack."
    ]
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
    },
    "description": "Creating BITS job as SYSTEM.",
    "response_steps": [
      "1. CHECK: Privilege escalation."
    ]
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
    },
    "description": "Unknown process loading BITS DLL.",
    "response_steps": [
      "1. CHECK: Process using BITS."
    ]
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
    },
    "description": "BITS copying files locally or via localhost loopback.",
    "response_steps": [
      "1. CHECK: Lateral movement prep."
    ]
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
    },
    "description": "Completing a BITS job. Triggers downloaded file availability.",
    "response_steps": [
      "1. CONTEXT: End of transfer."
    ]
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
    },
    "description": "Canceling BITS job.",
    "response_steps": [
      "1. CONTEXT: Cleanup."
    ]
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
    },
    "description": "Resetting all BITS jobs. Mass cleanup.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  }
];