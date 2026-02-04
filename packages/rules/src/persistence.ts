import { Rule } from '@neonshapeshifter/logtower-engine';

export const PERSISTENCE_RULES: Rule[] = [
  {
    id: 'PERSIST_001_REGISTRY_RUN',
    title: 'Registry Run Key Persistence',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1547.001'],
    detection: {
      selection: {
        'event_id': '4657', // Registry Modification (Audit required) or Sysmon 13
        "registry.path": ["*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*", "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"]
      }
    },
    description: "Attacker added an entry to the 'Run' or 'RunOnce' registry keys. Programs listed here start automatically when the user logs in.",
    response_steps: [
      "1. INSPECT: Check the value added. What executable does it point to?",
      "2. VERIFY: Is it signed by a trusted vendor? (e.g., GoogleUpdate is fine, random.exe is not).",
      "3. DELETE: Remove the registry value.",
      "4. FILE: Locate and delete the referenced malware binary."
    ]
  },
  {
    id: 'PERSIST_002_SERVICE_CREATION',
    title: 'New Service Creation',
    severity: 'MEDIUM', // High volume for admins, so Medium unless context is bad
    module: 'PERSISTENCE',
    mitre: ['T1543.003'],
    detection: {
      selection: {
        'event_id': '4697', // Security: A service was installed in the system
        'service_type': '0x10', // Win32 Own Process
        // 'service_file_name': '!*system32*' // Filter out obvious noise?
      }
    },
    description: "A new Windows Service was installed. Malware often installs itself as a service to run as SYSTEM and persist across reboots.",
    response_steps: [
      "1. CHECK: Look at the 'ServiceFileName' and 'ServiceName'.",
      "2. QUERY: 'sc qc <ServiceName>' to see details.",
      "3. STOP: 'sc stop <ServiceName>' and 'sc delete <ServiceName>'.",
      "4. HUNT: This requires Admin privileges. How did they get Admin?"
    ]
  },
  {
    id: 'PERSIST_003_WMI_EVENT_SUBSCRIPTION',
    title: 'WMI Event Subscription (Fileless)',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1546.003'],
    detection: {
      selection: {
        'event_id': '5861', // WMI Activity
        'message': ['*ActiveScriptEventConsumer*', '*CommandLineEventConsumer*']
      }
    },
    description: "Persistence via WMI Event Subscription. The attacker registers a WMI Consumer that executes a script/command whenever a specific system event (e.g., Startup) occurs. Extremely stealthy.",
    response_steps: [
      "1. LIST: Use PowerShell 'Get-WmiObject -Namespace rootsubscription ...' to list Consumers.",
      "2. ANALYZE: Look for 'ActiveScriptEventConsumer' (VBS/JS) or 'CommandLineEventConsumer'.",
      "3. REMOVE: Delete the Filter, Consumer, and Binding.",
      "4. NOTE: This is an advanced technique."
    ]
  },
  {
    id: 'PERSIST_004_STARTUP_FOLDER',
    title: 'Startup Folder Abuse',
    severity: 'MEDIUM',
    module: 'PERSISTENCE',
    mitre: ['T1547.001'],
    detection: {
      selection: {
        'event_id': '11', // Sysmon File Create
        'target_filename': [
          '*\\AppData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup*',
          '*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup*'
        ]
      }
    },
    description: "A file was dropped into the Windows Startup folder. Anything here runs when the user logs in.",
    response_steps: [
      "1. EXAMINE: Is it a shortcut (.lnk), script (.bat/.ps1), or executable?",
      "2. HASH: Check the hash of the file.",
      "3. DELETE: Remove the file from the directory.",
      "4. SCOPE: Check if it was put in 'All Users' (ProgramData) or a specific user's AppData."
    ]
  },
  {
    id: 'PERSIST_005_IFEO_DEBUGGER',
    title: 'IFEO / Image File Execution Options',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1546.012'],
    detection: {
      selection: {
        'event_id': '4657', // RegKey modification
        'target_object': '*\\Image File Execution Options*',
        'new_value': '*Debugger*'
      }
    },
    description: "Attacker modified IFEO 'Debugger' value for a legitimate binary (e.g., utilman.exe, sethc.exe). When that binary is called (e.g., Sticky Keys on Login Screen), the malware runs instead.",
    response_steps: [
      "1. IDENTIFY: Which binary was targeted? (sethc.exe, utilman.exe are common backdoors).",
      "2. RESTORE: Delete the 'Debugger' registry value.",
      "3. ALERT: If 'sethc.exe' was targeted, they likely have physical or RDP access."
    ]
  },
  {
    id: 'PERSIST_006_WINLOGON_HELPER',
    title: 'Winlogon Helper / Shell Modification',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1547.004'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': [
          '*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*',
          '*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit*'
        ]
      }
    },
    description: "Modification of Winlogon 'Shell' or 'Userinit' keys. Attackers append their malware here so it launches every time a user logs on, alongside explorer.exe.",
    response_steps: [
      "1. VERIFY: 'Shell' should be just 'explorer.exe'. 'Userinit' should end with a comma.",
      "2. FIX: Reset the registry key to default values.",
      "3. ISOLATE: High privileges are needed to change this."
    ]
  },
  {
    id: 'PERSIST_007_BITS_JOB',
    title: 'BITS Job Persistence',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1197'],
    detection: {
      selection: {
        'process.image': '*bitsadmin.exe',
        'process.command_line': ['*SetNotifyCmdLine*', '*minretrydelay*', '*customheaders*']
      }
    },
    description: "Configuring a BITS job to execute a command when a transfer completes or errors out. Used to run malware even if the transfer fails.",
    response_steps: [
      "1. LIST: 'bitsadmin /list /allusers'.",
      "2. PURGE: 'bitsadmin /reset /allusers'.",
      "3. MONITOR: Watch for recurring job creation (another persistence mechanism might be recreating it)."
    ]
  },
  {
    id: 'PERSIST_008_DLL_SIDELOADING_GENERIC',
    title: 'Potential DLL Sideloading',
    severity: 'MEDIUM',
    module: 'PERSISTENCE',
    mitre: ['T1574.002'],
    detection: {
      selection: {
        'event_id': '7', // Sysmon Image Load
        'process.image': ['!*\\Windows\\System32*', '!*\\Program Files*'], // Legitimate binary in weird spot
        'image_load.file_path': ['*user32.dll', '*kernel32.dll'] // Loading common DLLs from local dir?
        // Detection is hard without specific known bad pairings
      }
    },
    description: "An attacker placed a malicious DLL with a legitimate name (e.g., version.dll) in the same folder as a trusted application. The app loads the malicious DLL instead of the system one.",
    response_steps: [
      "1. CHECK: Look for 'legitimate' binaries running from Temp, Downloads, or Public.",
      "2. COMPARE: Check signatures of loaded DLLs. Is it Microsoft signed?",
      "3. CLEAN: Remove the folder containing the sideloaded pair."
    ]
  },
  {
    id: 'PERSIST_009_ACCOUNT_MANIPULATION',
    title: 'Account Manipulation (Shadow Admin)',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1098'],
    detection: {
      selection: {
        'event_id': '4738', // User Account Changed
        'sid_history': ['*-500*'] // SID History Injection
      }
    },
    description: "Adding SID History (e.g., Domain Admin SID) to a regular user account. This makes the user a 'Shadow Admin' - they look normal but have full rights.",
    response_steps: [
      "1. QUERY: Audit all users with SID History populated.",
      "2. CLEAN: Clear the SID History attribute (needs Domain Admin).",
      "3. ALERT: This attack requires Domain Admin rights to perform initially."
    ]
  },
  {
    id: 'PERSIST_010_CORRUPT_SERVICE_RECOVERY',
    title: 'Service Recovery Options Abuse',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1543.003'],
    detection: {
      selection: {
        'process.image': '*sc.exe',
        'process.command_line': ['*failure*', '*command=*']
      }
    },
    description: "Configuring a service to run a malicious command if it fails (Recovery Options). Attackers can then kill the service to trigger the payload.",
    response_steps: [
      "1. CHECK: 'sc qfailure <ServiceName>'.",
      "2. RESET: 'sc failure <ServiceName> reset= 86400 actions= restart/60000'.",
      "3. KILL: The payload specified in 'command'."
    ]
  },
  {
    id: 'PERSIST_011_DLL_SEARCH_ORDER',
    title: 'DLL Search Order Hijacking',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1574.001'],
    detection: {
      selection: {
        'event_id': '7', // Sysmon Image Load
        'image_load.file_path': ['*version.dll', '*sspicli.dll', '*userenv.dll', '*uxtheme.dll'], // Common targets
        'process.image': ['!c:\\windows\\system32*', '!c:\\windows\\syswow64*'] // Loaded by binary OUTSIDE of System32
      }
    },
    description: "Placing a malicious DLL with a legitimate name (e.g., version.dll) in the application's directory. Windows loads this DLL before the system one.",
    response_steps: [
      "1. LOCATE: Identify the folder containing the hijacked DLL.",
      "2. HASH: Confirm it is not the Microsoft signed version.",
      "3. REMOVE: Delete the malicious DLL."
    ]
  },
  {
    id: 'PERSIST_012_COM_HIJACKING',
    title: 'COM Object Hijacking',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1546.015'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': ['*\\InprocServer32\\(Default)', '*\\LocalServer32\\(Default)'],
        'new_value': ['*\\AppData*', '*\\Temp*', '*powershell*', '*cmd.exe*']
      }
    },
    description: "Modifying the Registry to point a legitimate COM Object (CLSID) to a malicious DLL/Script. When the system or user calls that object, the malware runs.",
    response_steps: [
      "1. REGISTRY: Check the CLSID modified.",
      "2. RESTORE: Delete the 'TreatAs' or malicious 'InprocServer32' key.",
      "3. SEARCH: Find what triggered the COM object (Scheduled Task? File Explorer?)."
    ]
  },
  {
    id: 'PERSIST_013_SHIM_DATABASE',
    title: 'Shim Database Persistence (Sdbinst)',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1546.011'],
    detection: {
      selection: {
        'process.image': '*sdbinst.exe',
        'process.command_line': ['*.sdb*']
      }
    },
    description: "Installing a malicious Application Compatibility Shim (.sdb) using sdbinst.exe. Shims can inject DLLs or patches into specific applications every time they run.",
    response_steps: [
      "1. LIST: 'sdbinst /q' (Query installed shims).",
      "2. ANALYZE: Use tools like python-sdb to parse the .sdb file.",
      "3. REMOVE: 'sdbinst /u <Guid>'."
    ]
  },
  {
    id: 'PERSIST_014_APPCERTDLLS',
    title: 'AppCertDlls Injection',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1546.009'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': '*\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls*'
      }
    },
    description: "Adding a DLL to the AppCertDlls registry key. Windows loads every DLL listed here into EVERY process that calls specific Win32 APIs. Massive system-wide injection.",
    response_steps: [
      "1. REGISTRY: Verify HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls.",
      "2. CLEAN: Remove the unauthorized entry.",
      "3. REBOOT: Required to unload the DLL from all running processes."
    ]
  },
  {
    id: 'PERSIST_015_ADMINSDHOLDER',
    title: 'AdminSDHolder Abuse (AD Persistence)',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1098'],
    detection: {
      selection: {
        'event_id': '5136', // Directory Service Change
        'object_dn': '*CN=AdminSDHolder,CN=System*',
        'attribute_ldap_display_name': 'nTSecurityDescriptor'
      }
    },
    description: "Modifying the ACL of the 'AdminSDHolder' object in AD. The 'SDProp' process automatically copies these permissions to all Protected Groups (Domain Admins, etc.) every hour.",
    response_steps: [
      "1. CHECK ACL: Who was added to AdminSDHolder permissions?",
      "2. REMOVE: Remove the backdoor account.",
      "3. WAIT: Force SDProp to run or wait 60 mins to verify permissions are reset on DA accounts."
    ]
  },
  {
    id: 'PERSIST_016_NETSH_HELPER',
    title: 'Netsh Helper DLL Persistence',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1546.007'],
    detection: {
      selection: {
        'process.image': '*netsh.exe',
        'process.command_line': ['*add helper*', '*.dll*']
      }
    },
    description: "Registering a malicious DLL as a Netsh Helper. The DLL is loaded every time netsh.exe is run (often by system scripts or VPNs).",
    response_steps: [
      "1. IDENTIFY: 'netsh show helper'.",
      "2. REMOVE: 'netsh delete helper <dllname>'.",
      "3. DELETE: The malicious DLL file."
    ]
  },
  {
    id: 'PERSIST_017_LOGON_SCRIPTS',
    title: 'Logon Scripts (UserInitMprLogonScript)',
    severity: 'MEDIUM',
    module: 'PERSISTENCE',
    mitre: ['T1037.001'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': '*\\Environment\\UserInitMprLogonScript*'
      }
    },
    description: "Modifying the UserInitMprLogonScript environment variable causes a script to run at logon for that user. Old school but effective.",
    response_steps: [
      "1. QUERY: Check User Environment variables.",
      "2. CLEAR: Delete the variable.",
      "3. SCRIPT: Find and analyze the script it was pointing to."
    ]
  },
  {
    id: 'PERSIST_018_WAITFOR',
    title: 'Waitfor.exe Persistence',
    severity: 'MEDIUM',
    module: 'PERSISTENCE',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*waitfor.exe',
        'process.command_line': ['*/si*', '*signal*'] // Sends or waits for signals
      }
    },
    description: "Waitfor.exe is a synchronization tool. Attackers use it to send signals across the network to trigger execution (acting as a bind shell or trigger).",
    response_steps: [
      "1. NETWORK: Waitfor uses UDP port 4350. Is it listening?",
      "2. TRIGGER: Identify the script waiting for the signal."
    ]
  },
  {
    id: 'PERSIST_019_SCREENSAVER',
    title: 'Screensaver Hijack',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1546.002'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': ['*\\Control Panel\\Desktop\\SCRNSAVE.EXE', '*\\Control Panel\\Desktop\\ScreenSaveActive'],
        'new_value': ['*.exe*', '*.scr*']
      }
    },
    description: "Modifying the registry to set a malicious executable as the user's screensaver. It runs automatically when the system goes idle.",
    response_steps: [
      "1. REGISTRY: Check HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE.",
      "2. RESTORE: Set back to a default .scr or None.",
      "3. LOCKOUT: This persists even if the user is locked out."
    ]
  },
  {
    id: 'PERSIST_020_OFFICE_TEMPLATE',
    title: 'Office Template Macro Persistence',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1137.001'],
    detection: {
      selection: {
        'event_id': '11', // File Create
        'target_filename': ['*\\Microsoft\\Templates\\Normal.dotm*', '*\\Microsoft\\Excel\\XLSTART*']
      }
    },
    description: "Modifying the Global Office Template (Normal.dotm) or XLSTART folder. Malicious macros here run every time Word/Excel is opened.",
    response_steps: [
      "1. FILE: Inspect Normal.dotm for VBA macros.",
      "2. DELETE: Remove the infected template (Office will regenerate a clean one).",
      "3. SCOPE: Check if it was deployed to all users via GPO."
    ]
  },
  {
    id: 'PERSIST_021_WMI_PERMANENT',
    title: 'WMI Permanent Event Consumer',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1546.003'],
    detection: {
      selection: {
        'event_id': '5861',
        'message': ['*ActiveScriptEventConsumer*', '*CommandLineEventConsumer*', '*LogFileEventConsumer*']
      }
    },
    description: "Deep WMI persistence using permanent consumers (ActiveScript or CommandLine). The script lives in the WMI repository (Objects.data), not as a file.",
    response_steps: [
      "1. REPO: The payload is in the WMI repository.",
      "2. CLEAN: Use PowerShell 'Get-WMIObject ... | Remove-WmiObject' to clean Filter, Consumer, and Binding.",
      "3. NOTE: Rebuilding the WMI repository is the nuclear option if cleaning fails."
    ]
  },
  {
    id: 'PERSIST_022_ACCESSIBILITY_BACKDOOR',
    title: 'Accessibility Features Backdoor',
    severity: 'CRITICAL',
    module: 'PERSISTENCE',
    mitre: ['T1546.008'],
    detection: {
      selection: {
        'event_id': '4657',
        'target_object': ['*\\Image File Execution Options\\sethc.exe*', '*\\Image File Execution Options\\utilman.exe*', '*\\Image File Execution Options\\magnify.exe*']
      }
    },
    description: "Replacing or debugging Accessibility tools (Sticky Keys, Magnifier, Utilman) to get a SYSTEM shell at the Logon Screen (Pre-Auth).",
    response_steps: [
      "1. CHECK: Press Shift 5 times at the login screen. Does a shell pop up?",
      "2. RESTORE: Delete the IFEO debugger key.",
      "3. FORENSICS: They had RDP or Physical access."
    ]
  }
];