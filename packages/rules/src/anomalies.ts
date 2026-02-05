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
  }
];
