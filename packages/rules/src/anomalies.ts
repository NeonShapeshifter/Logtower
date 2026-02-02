import { Rule } from '@neonshapeshifter/logtower-engine';

export const ANOMALY_RULES: Rule[] = [
  {
    "id": "GEN_301_CALC_SPAWN",
    "title": "Calc.exe Spawning Process",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.parent_image": "*calc.exe",
        "process.image": ["*cmd.exe", "*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    "id": "GEN_302_NOTEPAD_SPAWN",
    "title": "Notepad Spawning Shell",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.parent_image": "*notepad.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    }
  },
  {
    "id": "GEN_303_MSPAINT_SPAWN",
    "title": "MsPaint Spawning Shell",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.parent_image": "*mspaint.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  }
];
