import { Rule } from '@neonshapeshifter/logtower-engine';

export const ADVANCED_RULES: Rule[] = [
  {
    "id": "LSASS_151_UNKNOWN_ACCESS",
    "title": "Unknown Process Touching LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.granted_access": ["*0x1010*", "*0x1F3FFF*", "*0x1410*"],
        "process.image": ["!*svchost.exe", "!*MsMpEng.exe", "!*csrss.exe", "!*taskmgr.exe"]
      }
    },
    "description": "Detects a process obtaining a handle to LSASS.exe with specific access rights often used for credential dumping (e.g., MiniDumpWriteDump).",
    "response_steps": [
      "1. ISOLATE: High risk of credential theft. Isolate host.",
      "2. ANALYZE: Identify the source process.",
      "3. VERIFY: Is it a legitimate security tool or EDR agent?"
    ]
  },
  {
    "id": "LSASS_152_POWERSHELL",
    "title": "PowerShell Accessing LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Detects PowerShell attempting to access LSASS. This is almost never legitimate and indicates tools like Mimikatz (Invoke-Mimikatz) or similar scripts.",
    "response_steps": [
      "1. TERMINATE: Kill the PowerShell process.",
      "2. ISOLATE: Isolate the host.",
      "3. HUNT: Check for script blocks (Event 4104) to see what was executed."
    ]
  },
  {
    "id": "LSASS_153_CMD_DUMP",
    "title": "CMD Accessing LSASS",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": "*cmd.exe"
      }
    },
    "description": "Detects cmd.exe accessing LSASS, likely using comsvcs.dll or similar native binaries to dump memory.",
    "response_steps": [
      "1. ISOLATE: Isolate host.",
      "2. INVESTIGATE: Check command line arguments for 'comsvcs' or 'minidump'."
    ]
  },
  {
    "id": "LSASS_154_RUNDLL32",
    "title": "Rundll32 Accessing LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": "*rundll32.exe"
      }
    },
    "description": "Detects Rundll32 accessing LSASS. Attackers use 'comsvcs.dll, MiniDump' via rundll32 to dump credentials stealthily.",
    "response_steps": [
      "1. ISOLATE: Immediate isolation.",
      "2. VERIFY: Check the command line for 'comsvcs.dll'.",
      "3. RECOVER: Assume admin creds are stolen."
    ]
  },
  {
    "id": "LSASS_155_REGSVR32",
    "title": "Regsvr32 Accessing LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": "*regsvr32.exe"
      }
    },
    "description": "Detects Regsvr32 accessing LSASS. This is an unusual pattern often associated with malware or proxy execution.",
    "response_steps": [
      "1. ISOLATE: Isolate host.",
      "2. INVESTIGATE: Identify the DLL being registered or executed."
    ]
  },
  {
    "id": "LSASS_156_MIMIKATZ_ACCESS",
    "title": "Mimikatz Specific Access Mask",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.granted_access": "0x1010"
      }
    },
    "description": "Detects specific access masks (0x1010) often requested by Mimikatz when touching LSASS.",
    "response_steps": [
      "1. CRITICAL: High fidelity Mimikatz detection.",
      "2. ISOLATE: Isolate immediately.",
      "3. RESET: Reset all active credentials."
    ]
  },
  {
    "id": "LSASS_157_TASKMGR_DUMP",
    "title": "Task Manager LSASS Dump",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": "*taskmgr.exe",
        "process.granted_access": "*0x1F3FFF*"
      }
    },
    "description": "Detects Task Manager being used to dump the LSASS process. Attackers can right-click LSASS -> 'Create Dump File'.",
    "response_steps": [
      "1. VERIFY: Did a user do this interactively?",
      "2. CHECK: Look for .dmp files in AppData/Local/Temp."
    ]
  },
  {
    "id": "LSASS_158_WERFAULT_ABUSE",
    "title": "WerFault LSASS Access (SilentDump)",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": "*WerFault.exe"
      }
    },
    "description": "Detects WerFault.exe (Windows Error Reporting) accessing LSASS. Attackers abuse the 'SilentProcessExit' mechanism to trigger a dump via WerFault.",
    "response_steps": [
      "1. ISOLATE: Isolate host.",
      "2. CHECK: Registry keys for SilentProcessExit.",
      "3. HUNT: Look for LSASS dumps in standard error reporting paths."
    ]
  },
  {
    "id": "LSASS_159_OFFICE_ACCESS",
    "title": "Office App Accessing LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": ["*winword.exe", "*excel.exe", "*powerpnt.exe"]
      }
    },
    "description": "Detects Office applications accessing LSASS. This typically indicates a macro or exploit attempting to steal credentials.",
    "response_steps": [
      "1. TERMINATE: Kill the Office process.",
      "2. ISOLATE: Isolate host.",
      "3. ANALYZE: Retrieve the document that was open."
    ]
  },
  {
    "id": "LSASS_160_JAVA_ACCESS",
    "title": "Java Accessing LSASS",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.target_image": "*lsass.exe",
        "process.image": ["*java.exe", "*javaw.exe"]
      }
    },
    "description": "Detects Java processes accessing LSASS. Often seen with web server exploitation (e.g., Tomcat) leading to credential harvesting.",
    "response_steps": [
      "1. ISOLATE: Isolate the server.",
      "2. CHECK: Web server logs for exploitation."
    ]
  },
  {
    "id": "REG_161_HKCU_RUN",
    "title": "Persistence via HKCU Run Key",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\CurrentVersion\\Run*"
      }
    },
    "description": "Detects changes to the HKCU Run key. Programs listed here start automatically when the user logs in.",
    "response_steps": [
      "1. INSPECT: Check the binary path added to the registry.",
      "2. DELETE: Remove the entry if malicious.",
      "3. INVESTIGATE: Identify the dropper."
    ]
  },
  {
    "id": "REG_162_HKLM_RUN",
    "title": "Persistence via HKLM Run Key",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\LocalMachine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
      }
    },
    "description": "Detects changes to the HKLM Run key. These programs run for ALL users, making it a high-value persistence location.",
    "response_steps": [
      "1. INSPECT: Check the binary path.",
      "2. DELETE: Remove unauthorized entries.",
      "3. CHECK: Requires Admin privileges, so the machine is likely rooted."
    ]
  },
  {
    "id": "REG_163_RUNONCE",
    "title": "Persistence via RunOnce Key",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\CurrentVersion\\RunOnce*"
      }
    },
    "description": "Detects changes to the RunOnce key. Malware uses this to execute one time after reboot, often to complete installation or cleanup.",
    "response_steps": [
      "1. INSPECT: Identify the target binary.",
      "2. DELETE: Remove the key."
    ]
  },
  {
    "id": "REG_164_IFEO_SETHC",
    "title": "Sticky Keys Backdoor (IFEO)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.008"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Image File Execution Options\\sethc.exe\\Debugger"
      }
    },
    "description": "Detects the 'Sticky Keys' backdoor. Attackers replace sethc.exe (activated by pressing Shift 5 times) with cmd.exe to get a SYSTEM shell at the login screen.",
    "response_steps": [
      "1. VERIFY: Check the Debugger value for sethc.exe in the registry.",
      "2. DELETE: Remove the Debugger value.",
      "3. ISOLATE: The host is compromised."
    ]
  },
  {
    "id": "REG_165_IFEO_UTILMAN",
    "title": "Utilman Backdoor (IFEO)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.008"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Image File Execution Options\\utilman.exe\\Debugger"
      }
    },
    "description": "Detects the 'Utilman' backdoor. Similar to Sticky Keys, replaces Ease of Access utility with a shell.",
    "response_steps": [
      "1. VERIFY: Check Debugger value for utilman.exe.",
      "2. DELETE: Remove the registry key.",
      "3. ISOLATE: Host is compromised."
    ]
  },
  {
    "id": "REG_166_WINLOGON_SHELL",
    "title": "Winlogon Shell Hijack",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.004"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
      }
    },
    "description": "Detects hijacking of the Winlogon Shell value. Instead of explorer.exe, malware can configure itself to run as the shell.",
    "response_steps": [
      "1. CRITICAL: High impact persistence.",
      "2. REVERT: Set Shell back to 'explorer.exe'.",
      "3. ISOLATE: Host is compromised."
    ]
  },
  {
    "id": "REG_167_WINLOGON_USERINIT",
    "title": "Winlogon Userinit Hijack",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.004"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
      }
    },
    "description": "Detects hijacking of the Userinit key. Malware appends itself to the comma-separated list of executables run at login.",
    "response_steps": [
      "1. INSPECT: Check the value of Userinit.",
      "2. REVERT: Restore to default (userinit.exe)."
    ]
  },
  {
    "id": "REG_168_APPCERTDLLS",
    "title": "AppCertDlls Injection",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.009"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls*"
      }
    },
    "description": "Detects AppCertDlls injection. DLLs listed here are loaded into every process that calls CreateProcess, effectively infecting the whole system.",
    "response_steps": [
      "1. CRITICAL: Powerful persistence mechanism.",
      "2. DELETE: Remove the registry entry.",
      "3. REBOOT: Required to unload the malicious DLL."
    ]
  },
  {
    "id": "REG_169_APPPATHS",
    "title": "App Paths Hijacking",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Microsoft\\Windows\\CurrentVersion\\App Paths*"
      }
    },
    "description": "Detects App Paths hijacking. Attackers can register a malicious executable to run instead of a legitimate system tool when called by name.",
    "response_steps": [
      "1. INSPECT: Check the path associated with the hijacked application.",
      "2. DELETE: Remove the malicious key."
    ]
  },
  {
    "id": "REG_170_COM_HIJACK",
    "title": "COM Object Hijacking (InprocServer32)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.015"],
    "detection": {
      "selection": {
        "registry.target_object": "*_Classes\\CLSID*\\InprocServer32\\(Default)"
      }
    },
    "description": "Detects COM Object hijacking via InprocServer32. When an application requests the COM object, the malicious DLL is loaded.",
    "response_steps": [
      "1. INSPECT: Identify the CLSID and the DLL path.",
      "2. DELETE: Remove the malicious InprocServer32 key."
    ]
  },
  {
    "id": "REG_171_LSA_NOTIFICATION",
    "title": "LSA Notification Package Persistence",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.004"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Control\\Lsa\\Notification Packages"
      }
    },
    "description": "Detects registration of a malicious LSA Notification Package. This DLL is loaded by LSASS and can capture passwords in cleartext.",
    "response_steps": [
      "1. CRITICAL: Mimikatz-style password filter.",
      "2. DELETE: Remove the package from the registry.",
      "3. REBOOT: Required to unload."
    ]
  },
  {
    "id": "REG_172_COR_PROFILER",
    "title": "Global .NET Profiler Hijack",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1574.012"],
    "detection": {
      "selection": {
        "registry.target_object": ["*COR_ENABLE_PROFILING", "*COR_PROFILER*"]
      }
    },
    "description": "Detects .NET Profiler hijacking. By setting environment variables in the registry, an attacker can force a DLL to load into every .NET process.",
    "response_steps": [
      "1. INSPECT: Check the COR_PROFILER GUID and path.",
      "2. DELETE: Remove the environment variables."
    ]
  },
  {
    "id": "REG_173_SHIM_DB",
    "title": "Shim Database Installation (Sdbinst)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.011"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB*"
      }
    },
    "description": "Detects installation of a Shim Database (SDB). Shims are used for application compatibility but can be abused to inject DLLs or bypass UAC.",
    "response_steps": [
      "1. INVESTIGATE: Use 'sdbinst -u' to remove the malicious database.",
      "2. ANALYZE: Use tools like python-sdb to parse the .sdb file."
    ]
  },
  {
    "id": "REG_174_SILENT_EXIT",
    "title": "SilentProcessExit Persistence",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.012"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Image File Execution Options*\\GlobalFlag",
        "registry.details": "*512*"
      }
    },
    "description": "Detects usage of SilentProcessExit monitoring. Attackers use this to launch a debugger (malware) whenever a specific process terminates.",
    "response_steps": [
      "1. INSPECT: Check the 'MonitorProcess' value in the registry.",
      "2. DELETE: Remove the GlobalFlag and SilentProcessExit keys."
    ]
  },
  {
    "id": "REG_175_TERM_SERVER",
    "title": "Terminal Server Initial Program",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram"
      }
    },
    "description": "Detects modification of Terminal Server InitialProgram. This specifies a program to run immediately when an RDP session starts.",
    "response_steps": [
      "1. INSPECT: Check the InitialProgram value.",
      "2. DELETE: Clear the value if unauthorized."
    ]
  },
  {
    "id": "SVC_176_CMD_SERVICE",
    "title": "Service Executing CMD",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    },
    "description": "Detects a service configured to execute cmd.exe. This is a common persistence technique.",
    "response_steps": [
      "1. INSPECT: Check the service name and image path.",
      "2. DELETE: Remove the malicious service (sc delete)."
    ]
  },
  {
    "id": "SVC_177_POWERSHELL_SERVICE",
    "title": "Service Executing PowerShell",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": ["*powershell.exe*", "*pwsh.exe*"]
      }
    },
    "description": "Detects a service configured to execute PowerShell. Often used by malware or for lateral movement.",
    "response_steps": [
      "1. INSPECT: Decode the PowerShell command (often base64).",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "SVC_178_TEMP_SERVICE",
    "title": "Service Executing from TEMP",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp*"]
      }
    },
    "description": "Detects a service executing a binary from a Temp directory. Legitimate services almost never run from Temp.",
    "response_steps": [
      "1. SUSPICIOUS: High probability of malware.",
      "2. DELETE: Remove the service and the binary."
    ]
  },
  {
    "id": "SVC_179_PUBLIC_SERVICE",
    "title": "Service Executing from Public",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": "*\\Users\\Public*"
      }
    },
    "description": "Detects a service executing from the Users/Public folder. Common drop location for malware.",
    "response_steps": [
      "1. SUSPICIOUS: High probability of malware.",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "SVC_180_RUNDLL_SERVICE",
    "title": "Service Executing Rundll32",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": "*rundll32.exe*"
      }
    },
    "description": "Detects a service configured to run Rundll32. Attackers use this to run malicious DLLs as a service.",
    "response_steps": [
      "1. INSPECT: What DLL is being loaded?",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "SVC_181_MSHTA_SERVICE",
    "title": "Service Executing Mshta",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": "*mshta.exe*"
      }
    },
    "description": "Detects a service configured to run Mshta. This allows execution of HTA/VBScript as a service.",
    "response_steps": [
      "1. MALICIOUS: Mshta should not be running as a service.",
      "2. DELETE: Remove the service immediately."
    ]
  },
  {
    "id": "SVC_182_PSEXEC_SERVICE",
    "title": "PSEXEC Service Detected",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "service.image_path": ["*PSEXESVC*", "*PSEXEC*"]
      }
    },
    "description": "Detects the installation of the PsExec service (PSEXESVC). Indicates lateral movement to this machine.",
    "response_steps": [
      "1. VERIFY: Authorized admin activity?",
      "2. MONITOR: Check what command was executed by the service."
    ]
  },
  {
    "id": "SVC_183_PERFLOGS_SERVICE",
    "title": "Service Executing from PerfLogs",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": "*\\PerfLogs*"
      }
    },
    "description": "Detects a service executing from C:\\PerfLogs. This is a common hidden directory used by attackers.",
    "response_steps": [
      "1. SUSPICIOUS: Legitimate apps don't use PerfLogs.",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "SVC_184_SCRIPT_SERVICE",
    "title": "Service Executing WScript/CScript",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": ["*wscript.exe*", "*cscript.exe*"]
      }
    },
    "description": "Detects a service executing WScript or CScript (VBS/JS files).",
    "response_steps": [
      "1. INSPECT: Analyze the script file.",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "SVC_185_REGSVR_SERVICE",
    "title": "Service Executing Regsvr32",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "service.image_path": "*regsvr32.exe*"
      }
    },
    "description": "Detects a service executing Regsvr32.",
    "response_steps": [
      "1. INSPECT: Check the DLL/Script object being registered.",
      "2. DELETE: Remove the service."
    ]
  },
  {
    "id": "LOAD_186_DLL_TEMP",
    "title": "DLL Sideloading from TEMP",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_path": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp*"]
      }
    },
    "description": "Detects a DLL being loaded from a Temp directory. This is often indicative of DLL sideloading or unpacking.",
    "response_steps": [
      "1. INVESTIGATE: Identify the process loading the DLL.",
      "2. ANALYZE: Hash the DLL."
    ]
  },
  {
    "id": "LOAD_187_DLL_PUBLIC",
    "title": "DLL Sideloading from Public",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_path": "*\\Users\\Public*"
      }
    },
    "description": "Detects a DLL being loaded from Users/Public.",
    "response_steps": [
      "1. SUSPICIOUS: Common malware staging area.",
      "2. ISOLATE: If the process is critical/system, it may be hijacked."
    ]
  },
  {
    "id": "LOAD_188_DLL_DOWNLOADS",
    "title": "DLL Sideloading from Downloads",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_path": "*\\Downloads*"
      }
    },
    "description": "Detects a DLL being loaded from Downloads. User might have run a downloaded executable that sideloads a malicious DLL.",
    "response_steps": [
      "1. VERIFY: Did the user download this?",
      "2. CHECK: Scan the file."
    ]
  },
  {
    "id": "LOAD_189_VERSION_DLL",
    "title": "Version.dll Sideloading",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_name": "version.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*", "!*\\WinSxS*"]
      }
    },
    "description": "Detects sideloading of version.dll. Attackers place a malicious version.dll next to a signed binary to gain execution.",
    "response_steps": [
      "1. CRITICAL: Common technique for persistence/evasion.",
      "2. DELETE: Remove the rogue version.dll."
    ]
  },
  {
    "id": "LOAD_190_USERENV_DLL",
    "title": "Userenv.dll Sideloading",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_name": "userenv.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*", "!*\\WinSxS*"]
      }
    },
    "description": "Detects sideloading of userenv.dll.",
    "response_steps": [
      "1. CRITICAL: Sideloading attempt.",
      "2. DELETE: Remove the malicious DLL."
    ]
  },
  {
    "id": "LOAD_191_UXTHEME_DLL",
    "title": "Uxtheme.dll Sideloading",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_name": "uxtheme.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*", "!*\\WinSxS*"]
      }
    },
    "description": "Detects sideloading of uxtheme.dll.",
    "response_steps": [
      "1. CRITICAL: Sideloading attempt.",
      "2. DELETE: Remove the malicious DLL."
    ]
  },
  {
    "id": "LOAD_192_DBGHELP_DLL",
    "title": "Dbghelp.dll Sideloading",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_name": "dbghelp.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*", "!*\\WinSxS*"]
      }
    },
    "description": "Detects sideloading of dbghelp.dll.",
    "response_steps": [
      "1. CRITICAL: Sideloading attempt.",
      "2. DELETE: Remove the malicious DLL."
    ]
  },
  {
    "id": "LOAD_193_WMIC_SIDELOAD",
    "title": "WMIC DLL Sideloading Attempt",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "process.image": "*wmic.exe",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*"]
      }
    },
    "description": "Detects WMIC loading a DLL from a non-standard path. WMIC is often used to launch sideloaded DLLs.",
    "response_steps": [
      "1. INVESTIGATE: Check the command line for the DLL path.",
      "2. ISOLATE: Potential lateral movement."
    ]
  },
  {
    "id": "LOAD_194_MSDT_SIDELOAD",
    "title": "MSDT (Follina) Sideloading",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1218"],
    "detection": {
      "selection": {
        "process.image": "*msdt.exe",
        "image_load.file_path": ["!*\\System32*"]
      }
    },
    "description": "Detects MSDT (Microsoft Support Diagnostic Tool) loading suspicious DLLs. Associated with 'Follina' exploits.",
    "response_steps": [
      "1. CRITICAL: Exploit attempt.",
      "2. ISOLATE: Isolate host.",
      "3. PATCH: Ensure Follina patch is applied."
    ]
  },
  {
    "id": "LOAD_195_AMSI_PATCH",
    "title": "AMSI DLL Loaded from Wrong Path",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "image_load.file_name": "amsi.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*"]
      }
    },
    "description": "Detects amsi.dll being loaded from a non-system path. This indicates an 'AMSI Patch' bypass where the attacker provides a fake amsi.dll to disable scanning.",
    "response_steps": [
      "1. ALERT: Attacker is bypassing security controls.",
      "2. ISOLATE: Isolate host."
    ]
  },
  {
    "id": "TASK_196_PS_TASK",
    "title": "Scheduled Task Executing PowerShell",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "raw.TaskContent": ["*powershell*", "*pwsh*"]
      }
    },
    "description": "Detects a Scheduled Task configured to run PowerShell. Common persistence mechanism.",
    "response_steps": [
      "1. INSPECT: Get the full task definition.",
      "2. DECODE: Decode any base64 payloads.",
      "3. DELETE: Remove the task."
    ]
  },
  {
    "id": "TASK_197_CMD_TASK",
    "title": "Scheduled Task Executing CMD",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "raw.TaskContent": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    },
    "description": "Detects a Scheduled Task configured to run CMD.",
    "response_steps": [
      "1. INSPECT: Check the arguments passed to CMD.",
      "2. DELETE: Remove the task."
    ]
  },
  {
    "id": "TASK_198_TEMP_TASK",
    "title": "Scheduled Task Executing from TEMP",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "raw.TaskContent": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp*"]
      }
    },
    "description": "Detects a Scheduled Task executing from Temp. Malicious: Task running from Temp is highly suspicious.",
    "response_steps": [
      "1. MALICIOUS: Task running from Temp is highly suspicious.",
      "2. DELETE: Remove the task and binary."
    ]
  },
  {
    "id": "TASK_199_REGSVR_TASK",
    "title": "Scheduled Task Executing Regsvr32",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "raw.TaskContent": "*regsvr32.exe*"
      }
    },
    "description": "Detects a Scheduled Task executing Regsvr32 (Squiblydoo technique).",
    "response_steps": [
      "1. INSPECT: Identify the DLL/Script object being registered.",
      "2. DELETE: Remove the task."
    ]
  },
  {
    "id": "TASK_200_MSHTA_TASK",
    "title": "Scheduled Task Executing Mshta",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1053.005"],
    "detection": {
      "selection": {
        "raw.TaskContent": "*mshta.exe*"
      }
    },
    "description": "Detects a Scheduled Task executing Mshta. Used for fileless persistence.",
    "response_steps": [
      "1. MALICIOUS: Mshta in a scheduled task is a strong indicator of compromise.",
      "2. DELETE: Remove the task."
    ]
  }
];
