import { Rule } from '@neonshapeshifter/logtower-engine';

export const SIGMA_COMPLIANCE_RULES: Rule[] = [
  {
    "id": "CMD_351_CARET_OBFUSCATION",
    "title": "CMD Caret Obfuscation",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1027", "T1059.003"],
    "detection": {
      "selection": {
        "process.image": "*cmd.exe",
        "process.command_line": ["*^*^*", "*c^md*", "*p^w^s^h*"]
      }
    },
    "description": "Detects the use of the caret (^) character to obfuscate command line arguments in cmd.exe. This is a common evasion technique to bypass signature-based detection.",
    "response_steps": [
      "1. ANALYZE: Decode the command by removing the carets.",
      "2. INVESTIGATE: Determine the intent of the de-obfuscated command."
    ]
  },
  {
    "id": "CMD_352_ENV_VAR_EXPANSION",
    "title": "Suspicious Env Var Expansion",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*%COMSPEC%*", "*%SystemRoot%*system32*"]
      }
    },
    "description": "Detects the use of environment variables like %COMSPEC% to run cmd.exe indirectly, often to evade process name-based detections.",
    "response_steps": [
      "1. VERIFY: Is this part of a legitimate script?",
      "2. INSPECT: Check what command was executed via the environment variable."
    ]
  },
  {
    "id": "CMD_353_CONCATENATION",
    "title": "Command Concatenation (Quote Abuse)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": ["*\"+\" *", "*'+'*", "*\"http\"+\"s* "]
      }
    },
    "description": "Detects command concatenation techniques (e.g. \"+\") used to break up strings and evade detection.",
    "response_steps": [
      "1. DECODE: Reassemble the command string.",
      "2. INVESTIGATE: Determine malicious intent."
    ]
  },
  {
    "id": "CMD_354_APPDATA_EXEC",
    "title": "Suspicious Execution from AppData",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.command_line": ["*\\AppData\\Local*.exe", "*\\AppData\\Roaming*.exe"],
        "process.image": ["!*\\Microsoft*", "!*\\Google*", "!*\\Zoom*"]
      }
    },
    "description": "Detects execution of binaries from AppData folders, a common location for user-mode malware installation.",
    "response_steps": [
      "1. ISOLATE: High likelihood of malware.",
      "2. ANALYZE: Check the binary's reputation and signature."
    ]
  },
  {
    "id": "CMD_355_PROGRAMDATA_EXEC",
    "title": "Suspicious Execution from ProgramData",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.command_line": "*\\ProgramData*.exe",
        "process.image": ["!*\\Microsoft*", "!*\\Defender*\""]
      }
    },
    "description": "Detects execution from the ProgramData directory. Malware often drops payloads here as it is writable by all users.",
    "response_steps": [
      "1. INSPECT: Identify the process.",
      "2. VERIFY: Is it a legitimate updater or tool?"
    ]
  },
  {
    "id": "CMD_356_MINUS_N_OBFUSCATION",
    "title": "Ping -n Delay Obfuscation",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.image": "*ping.exe",
        "process.command_line": ["*-n 60*", "*-n 100*"]
      }
    },
    "description": "Detects the use of 'ping -n' with a high count as a makeshift 'sleep' command in batch scripts to delay execution (sandbox evasion).",
    "response_steps": [
      "1. CONTEXT: Often precedes malicious activity.",
      "2. INVESTIGATE: Check the script containing this command."
    ]
  },
  {
    "id": "CMD_357_COPY_CMD",
    "title": "Copying CMD.exe",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy *cmd.exe*", "*copy *powershell.exe*"]
      }
    },
    "description": "Detects copying of cmd.exe or powershell.exe to a new name to bypass process monitoring.",
    "response_steps": [
      "1. CRITICAL: Evasion attempt.",
      "2. TERMINATE: Kill the renamed process.",
      "3. DELETE: Remove the copy."
    ]
  },
  {
    "id": "CMD_358_ECHO_PIPING",
    "title": "Echo Piping to File",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1059.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*echo * > *", "*type * > *"]
      }
    },
    "description": "Detects usage of echo or type piped to a file, often used to create scripts or payloads on disk.",
    "response_steps": [
      "1. INSPECT: Check the created file's content.",
      "2. INVESTIGATE: Source process."
    ]
  },
  {
    "id": "CMD_359_BREAK_COMMAND",
    "title": "Break Command Obfuscation",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1027"],
    "detection": {
      "selection": {
        "process.command_line": "*break && *"
      }
    },
    "description": "Detects the 'break' command combined with other operators, sometimes used in obfuscated batch scripts.",
    "response_steps": [
      "1. ANALYZE: Review the full script containing this command."
    ]
  },
  {
    "id": "CMD_360_FOR_LOOP_EXEC",
    "title": "Complex FOR Loop Execution",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1059.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*for /f *", "*do *call*"]
      }
    },
    "description": "Detects complex FOR loops in command lines, often used to iterate over files for encryption or reconnaissance.",
    "response_steps": [
      "1. ANALYZE: Determine what the loop is processing (e.g., searching for files or running commands)."
    ]
  },
  {
    "id": "IMG_361_CLR_INJECTION",
    "title": "CLR Loaded in Unmanaged Process",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1055"],
    "detection": {
      "selection": {
        "image_load.file_name": ["clr.dll", "mscoree.dll"],
        "process.image": ["*notepad.exe", "*calc.exe", "*spoolsv.exe"]
      }
    },
    "description": "Detects the Common Language Runtime (CLR) being loaded into an unmanaged process (like notepad.exe). This indicates 'Execute-Assembly' style injection.",
    "response_steps": [
      "1. CRITICAL: Process injection detected.",
      "2. ISOLATE: Isolate the host.",
      "3. DUMP: Capture process memory for analysis."
    ]
  },
  {
    "id": "IMG_362_SAMLIB_LOAD",
    "title": "Samlib.dll Loaded Unexpectedly",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "image_load.file_name": "samlib.dll",
        "process.image": ["!*lsass.exe", "!*taskhostw.exe"]
      }
    },
    "description": "Detects samlib.dll loading into a non-LSASS process. Attackers use this to query SAM data offline for credential harvesting.",
    "response_steps": [
      "1. CRITICAL: Credential theft attempt.",
      "2. ISOLATE: Isolate host immediately.",
      "3. IDENTIFY: Identify the source process."
    ]
  },
  {
    "id": "IMG_363_VAULTCLI_LOAD",
    "title": "Vaultcli.dll Loaded Unexpectedly",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.004"],
    "detection": {
      "selection": {
        "image_load.file_name": "vaultcli.dll",
        "process.image": ["!*lsass.exe", "!*vaultcmd.exe"]
      }
    },
    "description": "Detects vaultcli.dll loading, indicating an attempt to access Windows Vault credentials (saved passwords, web credentials).",
    "response_steps": [
      "1. INVESTIGATE: Identify the source process.",
      "2. RESET: Reset stored credentials for the affected user."
    ]
  },
  {
    "id": "IMG_364_WDIGEST_LOAD",
    "title": "WDigest.dll Loaded (Legacy Auth)",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "image_load.file_name": "wdigest.dll",
        "process.image": ["!*lsass.exe"]
      }
    },
    "description": "Detects WDigest.dll loading. Attackers often force this to enable cleartext credential caching in memory.",
    "response_steps": [
      "1. REMEDIATE: Ensure WDigest UseLogonCredential registry key is set to 0.",
      "2. RESET: Reset passwords for logged-in users."
    ]
  },
  {
    "id": "IMG_365_CRYPTO_MINER_DLL",
    "title": "Crypto Mining DLL Load (OpenCL)",
    "severity": "MEDIUM",
    "module": "IMPACT",
    "mitre": ["T1496"],
    "detection": {
      "selection": {
        "image_load.file_name": "OpenCL.dll",
        "process.image": ["*AppData*", "*Temp*"]
      }
    },
    "description": "Detects OpenCL.dll loading from Temp/AppData, which is typical behavior for crypto miners utilizing GPU resources.",
    "response_steps": [
      "1. TERMINATE: Kill the mining process.",
      "2. CLEAN: Remove the miner components and associated tasks."
    ]
  },
  {
    "id": "IMG_366_SYSTEM_DLL_ANOMALY",
    "title": "System DLL Loaded from Temp",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "image_load.file_path": ["*\\Temp\\kernel32.dll", "*\\Temp\\ntdll.dll"]
      }
    },
    "description": "Detects system DLLs (kernel32, ntdll) being loaded from a Temp directory. This is a clear indicator of DLL Search Order Hijacking or a malicious dropper.",
    "response_steps": [
      "1. CRITICAL: High-fidelity malware indicator.",
      "2. ISOLATE: Isolate the host.",
      "3. ANALYZE: Identify the process loading these DLLs."
    ]
  },
  {
    "id": "IMG_367_NETAPI32_LOAD",
    "title": "Netapi32.dll Loaded by Script Engine",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "image_load.file_name": "netapi32.dll",
        "process.image": ["*wscript.exe", "*cscript.exe"]
      }
    },
    "description": "Detects netapi32.dll being loaded by script engines (WScript/CScript), often used for network reconnaissance and user enumeration.",
    "response_steps": [
      "1. INVESTIGATE: Determine what script is running and its purpose.",
      "2. ANALYZE: Check script for network discovery logic."
    ]
  },
  {
    "id": "IMG_368_MIMI_DRIV_LOAD",
    "title": "Mimikatz Driver Load Attempt",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "image_load.file_name": "mimidrv.sys"
      }
    },
    "description": "Detects the loading of the Mimikatz kernel driver (mimidrv.sys). This driver allows for kernel-level credential manipulation and security bypasses.",
    "response_steps": [
      "1. CRITICAL: Mimikatz kernel driver detected.",
      "2. ISOLATE: Isolate host immediately.",
      "3. REIMAGE: System integrity is fully compromised."
    ]
  },
  {
    "id": "IMG_369_WINHTTP_LOAD",
    "title": "Winhttp.dll Loaded by Office",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "image_load.file_name": "winhttp.dll",
        "process.image": ["*winword.exe", "*excel.exe"]
      }
    },
    "description": "Detects WinHTTP.dll being loaded by Microsoft Office applications, indicating that a document is making web requests (typically a downloader macro).",
    "response_steps": [
      "1. TERMINATE: Kill the Office process.",
      "2. INVESTIGATE: Retrieve and analyze the malicious document.",
      "3. BLOCK: Block any external domains found in proxy logs."
    ]
  },
  {
    "id": "IMG_370_RICHED20_DLL",
    "title": "Riched20.dll Sideloading",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_name": "riched20.dll",
        "image_load.file_path": ["!*\\System32*", "!*\\SysWOW64*", "!*\\Office**"]
      }
    },
    "description": "Detects Riched20.dll sideloading from non-standard paths. This is a common technique used by persistent malware.",
    "response_steps": [
      "1. CRITICAL: Sideloading attempt detected.",
      "2. CLEAN: Remove the malicious DLL and its launcher process.",
      "3. ISOLATE: Isolate host."
    ]
  },
  {
    "id": "FILE_371_STARTUP_EXE",
    "title": "EXE Created in Startup Folder",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "file.path": "*\\Start Menu\\Programs\\Startup*",
        "file.name": "*.exe"
      }
    },
    "description": "Detects the creation of an executable file in the Startup folder. Programs here run automatically upon user login.",
    "response_steps": [
      "1. INSPECT: Check the reputation of the binary.",
      "2. DELETE: Remove the file.",
      "3. ISOLATE: Investigate the dropper process."
    ]
  },
  {
    "id": "FILE_372_STARTUP_BAT",
    "title": "Script Created in Startup Folder",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "file.path": "*\\Start Menu\\Programs\\Startup*",
        "file.name": ["*.bat", "*.cmd", "*.vbs", "*.ps1"]
      }
    },
    "description": "Detects scripts (BAT, VBS, PS1) created in the Startup folder for persistence.",
    "response_steps": [
      "1. INSPECT: Analyze the script content for malicious logic.",
      "2. DELETE: Remove the file.",
      "3. AUDIT: Identify how the script was created."
    ]
  },
  {
    "id": "FILE_373_STARTUP_LNK",
    "title": "Shortcut Created in Startup Folder",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "file.path": "*\\Start Menu\\Programs\\Startup*",
        "file.name": "*.lnk"
      }
    },
    "description": "Detects creation of shortcuts (.LNK) in the Startup folder.",
    "response_steps": [
      "1. INSPECT: Check the target path of the shortcut.",
      "2. DELETE: Remove the shortcut if unauthorized."
    ]
  },
  {
    "id": "FILE_374_OFFICE_DROP_EXE",
    "title": "Office Dropping Executable",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": ["*winword.exe", "*excel.exe", "*outlook.exe"],
        "file.name": ["*.exe", "*.dll", "*.scr"]
      }
    },
    "description": "Detects Office applications creating executable files. High confidence indicator of a malicious macro or exploit delivery.",
    "response_steps": [
      "1. ISOLATE: Isolate the host immediately.",
      "2. RETRIEVE: Get the dropped sample for analysis.",
      "3. TERMINATE: Kill the parent Office process."
    ]
  },
  {
    "id": "FILE_375_OFFICE_DROP_ISO",
    "title": "Office Dropping ISO/IMG",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1553.005"],
    "detection": {
      "selection": {
        "process.image": ["*winword.exe", "*excel.exe", "*outlook.exe"],
        "file.name": ["*.iso", "*.img", "*.vhd"]
      }
    },
    "description": "Detects Office dropping disk image files (ISO/IMG). This is used to bypass Mark-of-the-Web (MOTW) and SmartScreen protections.",
    "response_steps": [
      "1. ISOLATE: Isolate host.",
      "2. INVESTIGATE: Check if the user successfully mounted or opened the image.",
      "3. SEARCH: Look for binaries run from the mounted drive."
    ]
  },
  {
    "id": "FILE_376_PS_DROP_EXE",
    "title": "PowerShell Dropping EXE",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": ["*powershell.exe", "*pwsh.exe"],
        "file.name": "*.exe"
      }
    },
    "description": "Detects PowerShell creating an executable file on disk, typically after a DownloadString or DownloadFile command.",
    "response_steps": [
      "1. INVESTIGATE: Identify the parent PowerShell script.",
      "2. ANALYZE: Analyze the dropped binary for malicious intent."
    ]
  },
  {
    "id": "FILE_377_CERTUTIL_DROP",
    "title": "Certutil Dropping File",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*certutil.exe",
        "file.name": "*"
      }
    },
    "description": "Detects Certutil.exe being used to decode or download a file to disk.",
    "response_steps": [
      "1. INVESTIGATE: Check the command line for decode or urlcache parameters.",
      "2. DELETE: Remove the dropped file."
    ]
  },
  {
    "id": "FILE_378_BITS_DROP",
    "title": "BITS Dropping File",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "process.image": "*bitsadmin.exe",
        "file.name": "*"
      }
    },
    "description": "Detects BITSAdmin creating a file, indicating a background download completion.",
    "response_steps": [
      "1. INVESTIGATE: Identify the source URL from BITS logs if available.",
      "2. DELETE: Remove the downloaded file."
    ]
  },
  {
    "id": "FILE_379_TEMP_SCR",
    "title": "Screensaver Created in Temp",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "file.path": "*\\AppData\\Local\\Temp*",
        "file.name": "*.scr"
      }
    },
    "description": "Detects .SCR (Screensaver) files created in Temp directories. These are often used as executable payloads by malware.",
    "response_steps": [
      "1. MALICIOUS: Treat as an executable binary.",
      "2. DELETE: Remove the file immediately."
    ]
  },
  {
    "id": "FILE_380_HOSTS_MOD",
    "title": "Hosts File Modification",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1565.001"],
    "detection": {
      "selection": {
        "file.path": "*\\System32\\drivers\\etc\\hosts"
      }
    },
    "description": "Detects modification of the local 'hosts' file. This is used by malware to redirect traffic or block access to security updates.",
    "response_steps": [
      "1. INSPECT: Check the file content for unauthorized entries.",
      "2. REVERT: Restore the hosts file to its original state."
    ]
  },
  {
    "id": "PIPE_381_COBALT_DEFAULT",
    "title": "Cobalt Strike Default Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": ["*\\msagent_*", "*\\mojo.*"]
      }
    },
    "description": "Detects default named pipes used by Cobalt Strike Beacon for communication.",
    "response_steps": [
      "1. CRITICAL: Confirmed active Cobalt Strike Beacon.",
      "2. ISOLATE: Isolate the system immediately."
    ]
  },
  {
    "id": "PIPE_382_COVENANT_GRUNT",
    "title": "Covenant Grunt Pipe",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*\\gruntsvc*"
      }
    },
    "description": "Detects named pipes associated with Covenant Grunt C2 agents.",
    "response_steps": [
      "1. CRITICAL: Covenant agent detected.",
      "2. ISOLATE: Immediate host isolation."
    ]
  },
  {
    "id": "PIPE_383_PSEXEC_SERVICE",
    "title": "PsExec Service Pipe",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*\\PSEXESVC*"
      }
    },
    "description": "Detects the named pipe used by PsExec for remote execution.",
    "response_steps": [
      "1. VERIFY: Confirm if this is authorized administrator activity.",
      "2. MONITOR: Check for lateral movement across the network."
    ]
  },
  {
    "id": "PIPE_384_EMPIRE_DEFAULTS",
    "title": "Empire Default Pipes",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": ["*\\empire*", "*\\covenant*"]
      }
    },
    "description": "Detects default named pipes for Empire or Covenant C2 frameworks.",
    "response_steps": [
      "1. CRITICAL: Active C2 session detected.",
      "2. ISOLATE: Isolate the host immediately."
    ]
  },
  {
    "id": "PIPE_385_CREDS_PIPE",
    "title": "Credentials Pipe Pattern",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "pipe.name": ["*\\creds_pipe*", "*\\password_pipe*"]
      }
    },
    "description": "Detects named pipes with names that suggest credential harvesting or password theft.",
    "response_steps": [
      "1. INVESTIGATE: Identify the source process using the pipe.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "DNS_386_IPIFY",
    "title": "DNS Lookup for Ipify (Ext Recon)",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1016"],
    "detection": {
      "selection": {
        "dns.query_name": ["*api.ipify.org*", "*whatismyip.com*"]
      }
    },
    "description": "Detects DNS lookups for services that report the public IP of the host. Often used by malware during the initial beaconing phase.",
    "response_steps": [
      "1. MONITOR: Watch for subsequent suspicious network activity."
    ]
  },
  {
    "id": "DNS_387_WHOAMI_AKAMAI",
    "title": "DNS Lookup Whoami Akamai",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1016"],
    "detection": {
      "selection": {
        "dns.query_name": "*whoami.akamai.net*"
      }
    },
    "description": "Detects DNS lookup for Akamai's whoami service, often used by malware for external IP reconnaissance.",
    "response_steps": [
      "1. MONITOR: Check for other reconnaissance signals."
    ]
  },
  {
    "id": "DNS_388_PORTQUIZ",
    "title": "DNS Lookup Portquiz (Egress Test)",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "dns.query_name": "*portquiz.net*"
      }
    },
    "description": "Detects DNS lookups for Portquiz, a service used to test if specific ports are open for egress.",
    "response_steps": [
      "1. BLOCK: Block the domain at the firewall.",
      "2. INVESTIGATE: Identify the process making the query."
    ]
  },
  {
    "id": "DNS_389_TELEGRAM_API",
    "title": "DNS Lookup Telegram API (C2)",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "dns.query_name": "*api.telegram.org*"
      }
    },
    "description": "Detects DNS lookups for the Telegram API. This can indicate C2 traffic or data exfiltration over Telegram.",
    "response_steps": [
      "1. VERIFY: Is there a legitimate business use for Telegram on this host?",
      "2. BLOCK: Block the API if unauthorized."
    ]
  },
  {
    "id": "DNS_390_DISCORD_CDN",
    "title": "DNS Lookup Discord CDN (C2/Drop)",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "dns.query_name": "*cdn.discordapp.com*"
      }
    },
    "description": "Detects DNS lookups for Discord's CDN, frequently used to host and deliver malware payloads.",
    "response_steps": [
      "1. VERIFY: Context of the request.",
      "2. BLOCK: Block if suspicious file downloads are detected."
    ]
  },
  {
    "id": "DNS_391_PASTEBIN",
    "title": "DNS Lookup Pastebin (Drop/Exfil)",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1102"],
    "detection": {
      "selection": {
        "dns.query_name": "*pastebin.com*"
      }
    },
    "description": "Detects DNS lookup for Pastebin, which is used by many malware families to host configuration or as an exfiltration point.",
    "response_steps": [
      "1. INVESTIGATE: Determine the full URL being accessed.",
      "2. MONITOR: Check for unusual data volume to Pastebin."
    ]
  },
  {
    "id": "DNS_392_GITHUB_USER_CONTENT",
    "title": "DNS Lookup Raw Github (Drop)",
    "severity": "LOW",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1102"],
    "detection": {
      "selection": {
        "dns.query_name": "*raw.githubusercontent.com*"
      }
    },
    "description": "Detects DNS lookups for raw GitHub content, often used to host secondary stages of malware or scripts.",
    "response_steps": [
      "1. INVESTIGATE: Identify the repository and file being accessed."
    ]
  },
  {
    "id": "DNS_393_CRYPTO_XMR",
    "title": "DNS Lookup Monero Mining",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1496"],
    "detection": {
      "selection": {
        "dns.query_name": ["*xmr.*", "*monero*", "*nanopool*"]
      }
    },
    "description": "Detects DNS queries for known Monero mining pools.",
    "response_steps": [
      "1. TERMINATE: Identify and kill the mining process.",
      "2. CLEAN: Remove the cryptomining software."
    ]
  },
  {
    "id": "DNS_394_CRYPTO_NICEHASH",
    "title": "DNS Lookup Nicehash Mining",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1496"],
    "detection": {
      "selection": {
        "dns.query_name": "*nicehash.com*"
      }
    },
    "description": "Detects DNS queries for Nicehash crypto mining service.",
    "response_steps": [
      "1. TERMINATE: Kill the process performing the queries."
    ]
  },
  {
    "id": "DNS_395_NGROK_DNS",
    "title": "DNS Lookup Ngrok Tunnel",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "dns.query_name": "*.ngrok.io*"
      }
    },
    "description": "Detects DNS queries for Ngrok subdomains, indicating an active tunnel.",
    "response_steps": [
      "1. BLOCK: Block Ngrok traffic at the network edge.",
      "2. INVESTIGATE: Determine what internal service is being tunneled."
    ]
  },
  {
    "id": "DNS_396_DGA_TOP_TLD",
    "title": "DNS Lookup .TOP TLD (Common Malware)",
    "severity": "LOW",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1568.002"],
    "detection": {
      "selection": {
        "dns.query_name": "*.top"
      }
    },
    "description": "Detects DNS queries for the .top TLD, which is statistically associated with a high volume of malware DGA domains.",
    "response_steps": [
      "1. INVESTIGATE: Check for a large number of NXDOMAIN responses."
    ]
  },
  {
    "id": "DNS_397_DGA_XYZ_TLD",
    "title": "DNS Lookup .XYZ TLD (Common Malware)",
    "severity": "LOW",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1568.002"],
    "detection": {
      "selection": {
        "dns.query_name": "*.xyz"
      }
    },
    "description": "Detects DNS queries for the .xyz TLD, often used for disposable malicious domains.",
    "response_steps": [
      "1. INVESTIGATE: Check the reputation of the queried domains."
    ]
  },
  {
    "id": "DNS_398_TRANSFER_SH",
    "title": "DNS Lookup Transfer.sh (Exfil)",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1567"],
    "detection": {
      "selection": {
        "dns.query_name": "*transfer.sh*"
      }
    },
    "description": "Detects DNS queries for transfer.sh, a command-line file sharing service often used for data exfiltration.",
    "response_steps": [
      "1. BLOCK: Block the domain at the firewall.",
      "2. ISOLATE: Isolate the host if unauthorized data transfer is suspected."
    ]
  },
  {
    "id": "DNS_399_ ANONFILES",
    "title": "DNS Lookup Anonfiles (Exfil)",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1567"],
    "detection": {
      "selection": {
        "dns.query_name": "*anonfiles.com*"
      }
    },
    "description": "Detects DNS lookups for anonfiles.com, another common service used for data exfiltration.",
    "response_steps": [
      "1. BLOCK: Block the domain.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "DNS_400_MEGA_UPLOAD",
    "title": "DNS Lookup MEGA (Exfil)",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1567"],
    "detection": {
      "selection": {
        "dns.query_name": ["*mega.nz*", "*mega.co.nz*"]
      }
    },
    "description": "Detects DNS lookups for the MEGA cloud storage service, often used for large-scale data exfiltration.",
    "response_steps": [
      "1. BLOCK: Block MEGA if unauthorized for business use.",
      "2. INVESTIGATE: Check for high volumes of outbound traffic."
    ]
  }
];