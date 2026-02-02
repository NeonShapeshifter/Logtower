import { Rule } from '@neonshapeshifter/logtower-engine';

export const LOLBAS_RULES: Rule[] = [
  {
    id: 'LOLBAS_001_CERTUTIL',
    title: 'Certutil Suspicious Activity',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*certutil.exe',
        'process.command_line': ['*urlcache*', '*verifyctl*', '*-decode*', '*-decodehex*', '*:stream*']
      }
    },
    description: "Certutil.exe is a native tool for certificate management, but attackers use it to download files (urlcache/verifyctl) or decode base64/hex-encoded payloads to evade AV.",
    response_steps: [
      "1. CHECK: What file was downloaded or decoded? (Check command line arguments).",
      "2. HASH: Get the SHA256 of the resulting file.",
      "3. DELETE: Remove the dropped file.",
      "4. NETWORK: Check the URL it connected to. Block the domain/IP."
    ]
  },
  {
    id: 'LOLBAS_002_BITSADMIN',
    title: 'Bitsadmin Download or Persistence',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1197'],
    detection: {
      selection: {
        'process.image': '*bitsadmin.exe',
        'process.command_line': ['*/transfer*', '*/create*', '*/addfile*', '*/SetNotifyCmdLine*', '*/resume*', '*/complete*']
      }
    },
    description: "Bitsadmin.exe manages background file transfers (BITS). Attackers use it to download malware reliably (it retries on failure) or achieve persistence (SetNotifyCmdLine executes code when transfer completes).",
    response_steps: [
      "1. INSPECT: Run 'bitsadmin /list /allusers' to see active jobs.",
      "2. CANCEL: Run 'bitsadmin /reset /allusers' to clear malicious jobs.",
      "3. INVESTIGATE: Check the source URL and the destination file path."
    ]
  },
  {
    id: 'LOLBAS_003_POWERSHELL',
    title: 'PowerShell Obfuscation and Download',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1059.001'],
    detection: {
      selection: {
        'process.image': ['*powershell.exe', '*pwsh.exe'],
        'process.command_line': ['*-enc*', '*-encodedcommand*', '*-w hidden*', '*-windowstyle hidden*', '*iex*', '*invoke-expression*', '*downloadstring*', '*invoke-webrequest*', '*frombase64string*']
      }
    },
    description: "Detects common malicious PowerShell patterns: Encoded commands (Base64), hidden windows, internet downloads (DownloadString), or in-memory execution (IEX).",
    response_steps: [
      "1. DECODE: Base64 decode the '-enc' payload to see what it does.",
      "2. SCOPE: Did it download a file or run a script in memory?",
      "3. LOGS: Check PowerShell Script Block Logging (Event 4104) for full de-obfuscated code.",
      "4. TERMINATE: Kill the powershell process tree."
    ]
  },
  {
    id: 'LOLBAS_004_MSHTA',
    title: 'Mshta Remote Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.005'],
    detection: {
      selection: {
        'process.image': '*mshta.exe',
        'process.command_line': ['*javascript:*', '*vbscript:*', '*.hta*', '*http://*', '*https://*']
      }
    },
    description: "Mshta.exe executes Microsoft HTML Applications (.hta). Attackers use it to execute malicious VBScript/JScript directly from a URL or embedded in a command line.",
    response_steps: [
      "1. NETWORK: Identify the URL passed to mshta.exe.",
      "2. ISOLATE: Mshta connecting to the internet is rarely legitimate for servers.",
      "3. PROCESS: Check what child processes mshta spawned (often cmd.exe or powershell.exe)."
    ]
  },
  {
    id: 'LOLBAS_005_RUNDLL32',
    title: 'Rundll32 Proxy Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.011'],
    detection: {
      selection: {
        'process.image': '*rundll32.exe',
        'process.command_line': ['*javascript:*', '*mshtml*', '*RunHTMLApplication*', '*url.dll*', '*Control_RunDLL*', '*GetObject*', '*pcwutl.dll*', '*LaunchApplication*']
      }
    },
    description: "Rundll32.exe loads and executes DLLs. Attackers abuse it to run malicious code masked as a system process, often using 'mshtml,RunHTMLApplication' to execute scripts.",
    response_steps: [
      "1. ANALYZE: What DLL and Function is being called? (e.g., shell32.dll,Control_RunDLL).",
      "2. DECODE: If 'javascript:' is used, extract the script logic.",
      "3. PARENT: Check the parent process. Did Word or Excel spawn this?"
    ]
  },
  {
    id: 'LOLBAS_006_REGSVR32',
    title: 'Regsvr32 Squiblydoo',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1218.010'],
    detection: {
      selection: {
        'process.image': '*regsvr32.exe',
        'process.command_line': ['*scrobj.dll*', '*.sct*', '*/i:http*', '*/i:https*']
      }
    },
    description: "The 'Squiblydoo' technique. Regsvr32 fetches a remote COM Scriptlet (.sct file) and executes it using scrobj.dll. Bypasses AppLocker (sometimes) and leaves no file on disk.",
    response_steps: [
      "1. BLOCK: Block the domain hosting the .sct file immediately.",
      "2. INVESTIGATE: This is almost 100% confirmed malicious activity.",
      "3. CONTEXT: Check for persistence mechanisms dropped by the scriptlet."
    ]
  },
  {
    id: 'LOLBAS_007_WMIC',
    title: 'Wmic Remote Execution / Recon',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1047'],
    detection: {
      selection: {
        'process.image': '*wmic.exe',
        'process.command_line': ['*/node:*', '*process call create*', '*/format:*', '*.xsl*']
      }
    },
    description: "WMIC is used for WMI interaction. Attackers use '/node:' for lateral movement, 'process call create' to run commands, or '/format:' with a malicious XSL stylesheet to execute scripts.",
    response_steps: [
      "1. TARGET: If '/node:' was used, identify the remote victim machine.",
      "2. PAYLOAD: What command was executed via 'process call create'?",
      "3. CLEANUP: If XSL usage, delete the malicious .xsl file."
    ]
  },
  {
    id: 'LOLBAS_008_SCHTASKS_GENERIC',
    title: 'Schtasks Task Creation',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1053.005'],
    detection: {
      selection: {
        'process.image': '*schtasks.exe',
        'process.command_line': ['*/create*', '!*onlogon*', '!*onstart*', '!*ru SYSTEM*', '!*sc SYSTEM*']
      }
    },
    description: "Creation of a scheduled task. While common for admins, it's a primary persistence method for attackers.",
    response_steps: [
      "1. REVIEW: Check the task name and action (program to run).",
      "2. CONTEXT: Is the program in a temporary folder (AppData, Temp)?",
      "3. REMOVE: 'schtasks /delete /tn <TaskName>'"
    ]
  },
  {
    id: 'LOLBAS_008_SCHTASKS_PERSISTENCE',
    title: 'Schtasks Persistence or SYSTEM',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1053.005'],
    detection: {
      selection: {
        'process.image': '*schtasks.exe',
        'process.command_line': ['*/create* *onlogon*', '*/create* *onstart*', '*/create* *ru SYSTEM*', '*/create* *sc SYSTEM*']
      }
    },
    description: "Creating a scheduled task that runs as SYSTEM or on user logon/startup. This guarantees the malware runs automatically with high privileges.",
    response_steps: [
      "1. INSPECT: Identify the task name. 'schtasks /query /tn <name> /v'.",
      "2. PAYLOAD: Locate the executable triggered by the task.",
      "3. REMEDIATE: Delete the task and the binary."
    ]
  },
  {
    id: 'LOLBAS_009_CMD_GENERIC',
    title: 'Cmd LOLBin Chaining (Generic)',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1059.003'],
    detection: {
      selection: {
        'process.image': '*cmd.exe',
        'process.command_line': [
          '*/c powershell*', '*/c bitsadmin*', '*/c certutil*', '*/c mshta*', '*/c rundll32*', '*/c regsvr32*', '*/k powershell*',
          '!*powershell* -enc*', '!*powershell*http*', '!*mshta*http*', '!*rundll32*javascript*', '!*regsvr32*/i:http*'
        ]
      }
    },
    description: "Cmd.exe spawning other LOLBins (PowerShell, Certutil, etc.). This 'chaining' is typical of malicious batch scripts or exploits.",
    response_steps: [
      "1. PARENT: What spawned this cmd.exe? (Exploit? Macro?)",
      "2. CHILD: What did it execute next?",
      "3. INVESTIGATE: Review the command arguments for encoded payloads."
    ]
  },
  {
    id: 'LOLBAS_010_WSCRIPT',
    title: 'Wscript/Cscript Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1059.005'],
    detection: {
      selection: {
        'process.image': ['*wscript.exe', '*cscript.exe'],
        'process.command_line': ['*:stream*', '*/e:vbscript*', '*/e:jscript*', '*vbscript:*', '*jscript:*', '*GetObject*']
      }
    },
    description: "Execution of VBScript or JScript files. Attackers use this to run payloads disguised as harmless scripts, often using 'Alternate Data Streams' (:stream) to hide.",
    response_steps: [
      "1. CAPTURE: Obtain the script file (.vbs/.js) for analysis.",
      "2. DEOBFUSCATE: Scripts are often heavily obfuscated.",
      "3. PARENT: Did this come from an email attachment (Outlook) or Browser?"
    ]
  },
  {
    id: 'LOLBAS_011_MSBUILD',
    title: 'MSBuild Code Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1127.001'],
    detection: {
      selection: {
        'process.image': '*msbuild.exe',
        'process.command_line': ['*csproj*', '*.xml*', '*/noconsolelogger*', '*AppData*', '*Temp*', '*Public*']
      }
    },
    description: "MSBuild.exe can compile and execute C# code inline from a .csproj or .xml file. Attackers use this to bypass AppLocker since MSBuild is a trusted binary.",
    response_steps: [
      "1. RETRIEVE: Get the project file (.xml/.csproj) passed to MSBuild.",
      "2. ANALYZE: Look for 'UsingTask' or 'Inline Tasks' which contain the C# payload.",
      "3. BLOCK: Restrict MSBuild execution to developer directories/users."
    ]
  },
  {
    id: 'LOLBAS_012_INSTALLUTIL',
    title: 'InstallUtil Proxy Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.004'],
    detection: {
      selection: {
        'process.image': '*installutil.exe',
        'process.command_line': ['*/u*', '*/logfile=*', '*/LogToConsole=false*', '*AppData*', '*Temp*']
      }
    },
    description: "InstallUtil.exe can execute code inside .NET assemblies during the 'uninstall' (/u) method. Classic AppLocker bypass.",
    response_steps: [
      "1. SAMPLE: Isolate the target binary (.exe/.dll) being 'installed/uninstalled'.",
      "2. DECOMPILE: Use dnSpy to inspect the 'Uninstall' method of the assembly.",
      "3. ISOLATE: Likely a C2 beacon or loader."
    ]
  },
  {
    id: 'LOLBAS_015_ODBCCONF',
    title: 'Odbcconf Proxy Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.008'],
    detection: {
      selection: {
        'process.image': '*odbcconf.exe',
        'process.command_line': ['*/a*', '*/s*', '*REGSVR*', '*.dll*', '*.rsp*']
      }
    },
    description: "Odbcconf.exe allows managing ODBC drivers but can also load and execute arbitrary DLLs using the 'REGSVR' action.",
    response_steps: [
      "1. IDENTIFY: Which DLL was loaded?",
      "2. CONTEXT: Is this a legitimate database setup? (Unlikely with REGSVR flag from command line).",
      "3. TERMINATE: Kill the process."
    ]
  },
  {
    id: 'LOLBAS_016_PCALUA',
    title: 'Pcalua Program Compatibility Assistant',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*pcalua.exe',
        'process.command_line': ['*-a*']
      }
    },
    description: "Pcalua.exe is the Program Compatibility Assistant. It can be abused to execute binaries that might otherwise be blocked.",
    response_steps: [
      "1. CHECK ARG: Look at the '-a' argument. That's the malicious binary.",
      "2. PARENT: What spawned this? Likely an attempt to evade behavioral monitoring."
    ]
  },
  {
    id: 'LOLBAS_017_CMSTP',
    title: 'CMSTP Proxy Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.003'],
    detection: {
      selection: {
        'process.image': '*cmstp.exe',
        'process.command_line': ['*/s*', '*/au*', '*.inf*']
      }
    },
    description: "CMSTP.exe installs Connection Manager profiles. It can execute malicious scripts/COM objects embedded in an .INF file. Known UAC Bypass technique.",
    response_steps: [
      "1. INF FILE: Find and analyze the .INF file provided.",
      "2. UAC: Check if this was used to bypass User Account Control (auto-elevation).",
      "3. ISOLATE: High confidence threat."
    ]
  },
  {
    id: 'LOLBAS_018_FTP',
    title: 'FTP Script Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*ftp.exe',
        'process.command_line': ['*-s:*']
      }
    },
    description: "FTP.exe running in script mode (-s:filename). Attackers use this to download tools non-interactively in legacy environments.",
    response_steps: [
      "1. SCRIPT: Retrieve the script file used.",
      "2. IP: Identify the remote FTP server.",
      "3. BLOCK: Outbound FTP is rarely allowed for servers."
    ]
  },
  {
    id: 'LOLBAS_020_FORFILES',
    title: 'Forfiles Command Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1202'],
    detection: {
      selection: {
        'process.image': '*forfiles.exe',
        'process.command_line': ['*/c* *cmd*', '*/c* *powershell*']
      }
    },
    description: "Forfiles.exe selects files and runs a command on them. Attackers use it to spawn a child process (cmd/powershell) to break parent-child detection chains.",
    response_steps: [
      "1. DECODE: Look at the '/c' argument for the actual command.",
      "2. MONITOR: Watch for the spawned child process."
    ]
  },
  {
    id: 'LOLBAS_024_NETSH_PORTPROXY_HIGH',
    title: 'Netsh Port Proxy',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1090'],
    detection: {
      selection: {
        'process.image': '*netsh.exe',
        'process.command_line': ['*interface*portproxy*add*v4tov4*']
      }
    },
    description: "Netsh portproxy creates a port forward on the host, redirecting traffic to another internal IP. Used to tunnel C2 traffic deeper into the network.",
    response_steps: [
      "1. LIST: 'netsh interface portproxy show all'.",
      "2. ANALYZE: What is the 'connectaddress'? That's the next hop target.",
      "3. DELETE: 'netsh interface portproxy delete ...'."
    ]
  },
  {
    id: 'LOLBAS_025_REGASM_REGSVCS',
    title: 'RegAsm/RegSvcs Code Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.009'],
    detection: {
      selection: {
        'process.image': ['*regasm.exe', '*regsvcs.exe'],
        'process.command_line': ['*/u*', '*/codebase*']
      }
    },
    description: "RegAsm and RegSvcs are .NET utilities that can be abused to execute malicious code within a trusted Microsoft binary, bypassing AppLocker.",
    response_steps: [
      "1. BINARY: Identify the .dll or .exe passed to the tool.",
      "2. DECOMPILE: Check the file for malicious 'Unregistration' hooks.",
      "3. BLOCK: These tools should rarely be used in production by users."
    ]
  },
  {
    id: 'LOLBAS_026_IEEXEC',
    title: 'IEExec Remote DotNet Execution',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*ieexec.exe',
        'process.command_line': ['*http*', '*.exe*']
      }
    },
    description: "IEExec.exe allows executing .NET managed applications hosted on a web server. It downloads and runs the executable in one go.",
    response_steps: [
      "1. URL: Identify the remote URL hosting the malicious app.",
      "2. ISOLATE: High confidence C2 loader.",
      "3. NETWORK: Check for other hosts contacting that URL."
    ]
  },
  {
    id: 'LOLBAS_027_MSIEXEC',
    title: 'Msiexec Remote Install',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1218.007'],
    detection: {
      selection: {
        'process.image': '*msiexec.exe',
        'process.command_line': ['*/i*', '*http*', '*https*', '*/q*']
      }
    },
    description: "Msiexec installing an MSI package directly from a URL. Attackers use this to deploy ransomware or RATs without dropping files manually.",
    response_steps: [
      "1. URL: Block the source domain.",
      "2. MSI: If possible, retrieve the MSI for analysis.",
      "3. LOGS: Check Application logs for MSIInstaller events to see what it installed."
    ]
  },
  {
    id: 'LOLBAS_028_ROBOCOPY',
    title: 'Robocopy Mirror to Share',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1048'],
    detection: {
      selection: {
        'process.image': '*robocopy.exe',
        'process.command_line': ['*/mir* \\\\**']
      }
    },
    description: "Using Robocopy with the /MIR (Mirror) flag to a network share. Often used for data exfiltration or massive lateral movement of tools.",
    response_steps: [
      "1. DESTINATION: Where is the data going? (External or Internal share).",
      "2. SIZE: How much data was moved?",
      "3. STOP: Kill the process."
    ]
  },
  {
    id: 'LOLBAS_029_WSL_BASH',
    title: 'WSL/Bash Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1202'],
    detection: {
      selection: {
        'process.image': ['*bash.exe', '*wsl.exe'],
        'process.command_line': ['*-c*', '*/mnt/c/*']
      }
    },
    description: "Execution of commands via the Windows Subsystem for Linux (WSL). Malware uses this to hide from Windows-based EDRs that don't monitor Linux syscalls.",
    response_steps: [
      "1. INSPECT: Check the bash history file if possible.",
      "2. COMMAND: What windows binary did it call from Linux? (/mnt/c/...)",
      "3. SCOPE: Is WSL supposed to be installed on this server?"
    ]
  },
  {
    id: 'LOLBAS_030_MAVINJECT',
    title: 'Mavinject DLL Injection',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1218.013'],
    detection: {
      selection: {
        'process.image': '*mavinject.exe',
        'process.command_line': ['*/INJECTRUNNING*', '*.dll*']
      }
    },
    description: "Mavinject is a component of App-V that can be abused to inject arbitrary DLLs into running processes.",
    response_steps: [
      "1. TARGET: Which PID was injected?",
      "2. DLL: Locate the malicious DLL.",
      "3. ALERT: This is a built-in injection tool provided by Microsoft."
    ]
  },
  {
    id: 'LOLBAS_031_PUBPRN',
    title: 'Pubprn Scriptlet Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1216'],
    detection: {
      selection: {
        'process.image': ['*cscript.exe', '*wscript.exe'],
        'process.command_line': ['*pubprn.vbs*', '*script:*', '*http*']
      }
    },
    description: "Pubprn.vbs is a Microsoft signed script that can be abused to execute remote COM scriptlets (SCT files).",
    response_steps: [
      "1. URL: Identify the remote scriptlet URL.",
      "2. BLOCK: Block internet access for cscript.exe.",
      "3. REMEDIATE: Disable WSH (Windows Script Host) if not needed."
    ]
  },
  {
    id: 'LOLBAS_032_SYNCAPPV',
    title: 'SyncAppvPublishingServer PowerShell Bypass',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*syncappvpublishingserver.exe',
        'process.command_line': ['*powershell*', '*\\"n;*']
      }
    },
    description: "SyncAppvPublishingServer.exe can be used to execute PowerShell commands, effectively bypassing some restrictions on direct powershell.exe usage.",
    response_steps: [
      "1. COMMAND: Decode the PowerShell command embedded in the arguments.",
      "2. ALERT: Rare usage pattern."
    ]
  },
  {
    id: 'LOLBAS_033_DESKTOPIMG',
    title: 'Desktopimgdownldr URL Download',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*desktopimgdownldr.exe',
        'process.command_line': ['*/lockscreenurl:*http*']
      }
    },
    description: "Desktopimgdownldr.exe is used to configure lock screen images, but can be forced to download any file from a URL to a temporary directory.",
    response_steps: [
      "1. FILE: Check C:\\Windows\\Temp for the downloaded file.",
      "2. URL: Block the source.",
      "3. CLEAN: Delete the artifact."
    ]
  },
  {
    id: 'LOLBAS_034_SQLDUMPER',
    title: 'Sqldumper LSASS Dump',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1003.001'],
    detection: {
      selection: {
        'process.image': '*sqldumper.exe',
        'process.command_line': ['*0x01100*', '*lsass*']
      }
    },
    description: "Sqldumper.exe is a legitimate Microsoft tool included with SQL Server/Office. It can be used to dump LSASS memory without triggering some AVs.",
    response_steps: [
      "1. DUMP: Locate the generated .dmp file.",
      "2. CREDENTIALS: Reset passwords immediately.",
      "3. ISOLATE: The host is compromised."
    ]
  },
  {
    id: 'LOLBAS_035_CONTROL',
    title: 'Control.exe Suspicious Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218.002'],
    detection: {
      selection: {
        'process.image': '*control.exe',
        'process.command_line': ['*.cpl*', '*.inf*', '*\\Users*', '*\\Temp*']
      }
    },
    description: "Control.exe (Control Panel) usually loads from System32. Loading .cpl files from user directories indicates malware using it as a proxy loader.",
    response_steps: [
      "1. FILE: Identify the .cpl or .inf file loaded.",
      "2. HASH: Check if it's a renamed DLL (control panel applets are DLLs).",
      "3. KILL: Terminate the process."
    ]
  },
  {
    id: 'LOLBAS_036_DFSVC',
    title: 'Dfsvc ClickOnce Execution',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1127'],
    detection: {
      selection: {
        'process.image': '*dfsvc.exe',
        'process.command_line': ['*http*', '*.application*']
      }
    },
    description: "Dfsvc.exe handles ClickOnce applications. It can be used to download and run applications from the web.",
    response_steps: [
      "1. APP: What application was launched?",
      "2. SOURCE: Is the domain trusted?",
      "3. CHECK: User intent (did they click a link?)."
    ]
  },
  {
    id: 'LOLBAS_037_DNSCMD',
    title: 'Dnscmd Plugin DLL Loading',
    severity: 'CRITICAL',
    module: 'LOLBAS',
    mitre: ['T1574.002'],
    detection: {
      selection: {
        'process.image': '*dnscmd.exe',
        'process.command_line': ['*/config*', '*serverlevelplugindll*', '*.dll*']
      }
    },
    description: "Configuring the DNS Server to load a custom DLL as a plugin. The DLL runs as SYSTEM on the Domain Controller. Extremely dangerous persistence/privesc.",
    response_steps: [
      "1. CHECK: 'dnscmd /info /serverlevelplugindll'.",
      "2. REMOVE: 'dnscmd /config /serverlevelplugindll <null>'.",
      "3. PANIC: Your Domain Controller is owned."
    ]
  },
  {
    id: 'LOLBAS_038_EXTRAC32',
    title: 'Extrac32 UNC File Copy',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*extrac32.exe',
        'process.command_line': ['*/C*', '*\\\\**']
      }
    },
    description: "Using Extrac32.exe to copy files from a network share (UNC path) or overwrite system files.",
    response_steps: [
      "1. PATH: Check source and destination.",
      "2. OVERWRITE: Did it replace a legitimate file?",
      "3. BLOCK: Restrict usage."
    ]
  },
  {
    id: 'LOLBAS_039_CSC_JSC',
    title: 'CSC/JSC Compile-On-The-Fly',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1027.004'],
    detection: {
      selection: {
        'process.image': ['*csc.exe', '*jsc.exe'],
        'process.command_line': ['*/target:exe*', '*/out:*', '*.cs*', '*.js*']
      }
    },
    description: "The C# (CSC) or JScript (JSC) compilers were used to compile source code into an executable on the victim machine. Bypasses static analysis of binaries.",
    response_steps: [
      "1. SOURCE: Retrieve the .cs or .js source code file.",
      "2. COMPILED: Retrieve the output .exe.",
      "3. ALERT: Developers might do this, regular users do not."
    ]
  },
  {
    id: 'LOLBAS_040_TAR_CURL',
    title: 'Native Tar/Curl Abuse',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': ['*curl.exe', '*tar.exe'],
        'process.command_line': ['*http*', '*-O*', '*-F*', '*-cf*', '*Users*']
      }
    },
    description: "Using Windows native curl.exe to download/upload data or tar.exe to compress files for exfiltration.",
    response_steps: [
      "1. NETWORK: Where did Curl connect to?",
      "2. DATA: What did Tar compress? (Check file list in args).",
      "3. CONTEXT: Is this a developer machine?"
    ]
  },
  {
    id: 'LOLBAS_041_AGENTEXECUTOR',
    title: 'AgentExecutor PowerShell Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*agentexecutor.exe',
        'process.command_line': ['*-powershell*', '*remediation.ps1*']
      }
    },
    description: "AgentExecutor.exe is used by Intune Management Extension to run PowerShell scripts. Attackers can abuse it to run their own scripts if they have local admin.",
    response_steps: [
      "1. SOURCE: Identify the script being executed.",
      "2. INTUNE: Verify if this is a legitimate deployment or a local abuse.",
      "3. LOGS: Check Intune Management Extension logs."
    ]
  },
  {
    id: 'LOLBAS_042_APPVLP',
    title: 'AppVLP Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*appvlp.exe',
        'process.command_line': ['*.exe*', '*.bat*', '*.ps1*']
      }
    },
    description: "AppVLP.exe allows executing binaries defined in an App-V package context. Can be used to bypass some execution restrictions.",
    response_steps: [
      "1. PAYLOAD: What binary did it launch?",
      "2. PARENT: Check parent process context."
    ]
  },
  {
    id: 'LOLBAS_043_BGINFO',
    title: 'Bginfo Script Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*bginfo.exe',
        'process.command_line': ['*/popup*', '*/i*', '*.bgi*']
      }
    },
    description: "Bginfo.exe (Sysinternals) can execute VBScript embedded in a configuration file (.bgi) or via command line triggers.",
    response_steps: [
      "1. CONFIG: Retrieve the .bgi file.",
      "2. SCRIPT: Extract VBScript from the configuration.",
      "3. BLOCK: Restrict Bginfo usage."
    ]
  },
  {
    id: 'LOLBAS_044_DISKSHADOW_SCRIPT',
    title: 'Diskshadow Script Mode',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*diskshadow.exe',
        'process.command_line': ['*/s*', '*.txt*'] // /s executes a script file
      }
    },
    description: "Diskshadow.exe in script mode (/s) can execute commands. It is also used to dump NTDS.dit (shadow copy creation).",
    response_steps: [
      "1. SCRIPT: Get the text file passed to /s.",
      "2. NTDS: Did it attempt to dump credentials?",
      "3. ALERT: Rare administrative action."
    ]
  },
  {
    id: 'LOLBAS_045_EXPAND',
    title: 'Expand File Expansion/Copy',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*expand.exe',
        'process.command_line': ['*Users*', '*Program Files*', '*Windows*']
      }
    },
    description: "Expand.exe is used to unpack cab files, but can be used to copy files to sensitive locations (like System32) to overwrite DLLs.",
    response_steps: [
      "1. PATH: Check destination file.",
      "2. OVERWRITE: Did it replace a system binary?"
    ]
  },
  {
    id: 'LOLBAS_046_FINGER',
    title: 'Finger Data Exfiltration',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1048'],
    detection: {
      selection: {
        'process.image': '*finger.exe',
        'process.command_line': ['*@*']
      }
    },
    description: "Finger.exe is a legacy tool. Attackers use it to exfiltrate data or download files by connecting to a malicious Finger server.",
    response_steps: [
      "1. NETWORK: Where did it connect?",
      "2. DATA: What was sent? (Check command line arguments often contain data).",
      "3. BLOCK: Port 79 should be blocked."
    ]
  },
  {
    id: 'LOLBAS_047_GPSCRIPT',
    title: 'Gpscript Logon Script Abuse',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*gpscript.exe',
        'process.command_line': ['*/logon*', '*/startup*']
      }
    },
    description: "Gpscript.exe runs Group Policy scripts. Attackers can manually invoke it to run their own logon/startup scripts with System privileges.",
    response_steps: [
      "1. SCRIPT: Identify the script executed.",
      "2. GPO: Check if a malicious GPO was added."
    ]
  },
  {
    id: 'LOLBAS_048_HH',
    title: 'HTML Help Executable Abuse',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218.001'],
    detection: {
      selection: {
        'process.image': '*hh.exe',
        'process.command_line': ['*.chm*']
      }
    },
    description: "Hh.exe opens Compiled HTML Help (.chm) files. CHM files can contain embedded scripts that run when opened (e.g., via ActiveX).",
    response_steps: [
      "1. FILE: Retrieve the .chm file.",
      "2. DECOMPILE: Extract HTML content to find the payload.",
      "3. SOURCE: Downloaded from internet?"
    ]
  },
  {
    id: 'LOLBAS_049_MPCMDRUN',
    title: 'Windows Defender Download',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1105'],
    detection: {
      selection: {
        'process.image': '*mpcmdrun.exe',
        'process.command_line': ['*-downloadfile*', '*-url*']
      }
    },
    description: "MpCmdRun.exe (Defender CLI) has a flag to download a file from a URL. Attackers use the security tool itself to download malware.",
    response_steps: [
      "1. URL: Block the source.",
      "2. FILE: What file was downloaded?",
      "3. NOTE: Microsoft removed this flag in newer versions, but it persists in older ones."
    ]
  },
  {
    id: 'LOLBAS_050_MSCONFIG',
    title: 'Msconfig Persistence/Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*msconfig.exe',
        'process.command_line': ['*-5*'] // UAC bypass flag often
      }
    },
    description: "Msconfig.exe can be used to execute commands or configure persistence (services/startup).",
    response_steps: [
      "1. COMMAND: Check arguments.",
      "2. UAC: Check for elevation attempts."
    ]
  },
  {
    id: 'LOLBAS_051_PRESENTATIONHOST',
    title: 'PresentationHost XBAP Execution',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*presentationhost.exe',
        'process.command_line': ['*.xbap*']
      }
    },
    description: "PresentationHost.exe executes XAML Browser Applications (XBAP). These are .NET apps that can run from the web, similar to Java Applets.",
    response_steps: [
      "1. URL: Check the source of the .xbap.",
      "2. SANDBOX: XBAP usually runs in sandbox, did it break out?"
    ]
  },
  {
    id: 'LOLBAS_052_PRINT',
    title: 'Print.exe Alternate Data Stream Write',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1564.004'],
    detection: {
      selection: {
        'process.image': '*print.exe',
        'process.command_line': ['*:stream*'] // Copying to ADS
      }
    },
    description: "Print.exe can copy files to Alternate Data Streams (ADS) to hide them from the user.",
    response_steps: [
      "1. FILE: 'dir /r' to see ADS.",
      "2. EXTRACT: Analyze the hidden stream content."
    ]
  },
  {
    id: 'LOLBAS_053_RUNONCE',
    title: 'Runonce.exe Persistence Run',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1547.001'],
    detection: {
      selection: {
        'process.image': '*runonce.exe',
        'process.command_line': ['*/RunOnce*']
      }
    },
    description: "Runonce.exe is used by Windows to process the RunOnce registry key. Attackers invoke it manually to execute persistent payloads immediately.",
    response_steps: [
      "1. REGISTRY: Check HKLM\\...\\RunOnce keys.",
      "2. PAYLOAD: Identify the binary configured to run."
    ]
  },
  {
    id: 'LOLBAS_054_SCRIPTRUNNER',
    title: 'ScriptRunner Execution',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*scriptrunner.exe',
        'process.command_line': ['*-appvscript*', '*.ps1*', '*.exe*']
      }
    },
    description: "ScriptRunner.exe executes scripts defined in App-V manifests. Can be used to run arbitrary binaries/scripts.",
    response_steps: [
      "1. ARGS: Check the command line for the payload.",
      "2. CONTEXT: Is App-V actually used?"
    ]
  },
  {
    id: 'LOLBAS_055_TTTRACER',
    title: 'Time Travel Tracer DLL Injection',
    severity: 'HIGH',
    module: 'LOLBAS',
    mitre: ['T1055'],
    detection: {
      selection: {
        'process.image': '*tttracer.exe',
        'process.command_line': ['*-dump*', '*.dll*']
      }
    },
    description: "Tttracer.exe (Time Travel Debugging) can load arbitrary DLLs during the tracing process.",
    response_steps: [
      "1. DLL: Identify the loaded DLL.",
      "2. TARGET: Which process was being traced?"
    ]
  },
  {
    id: 'LOLBAS_056_VERCLSID',
    title: 'Verclsid COM Instantiation',
    severity: 'MEDIUM',
    module: 'LOLBAS',
    mitre: ['T1218.012'],
    detection: {
      selection: {
        'process.image': '*verclsid.exe',
        'process.command_line': ['*/clsid*']
      }
    },
    description: "Verclsid.exe validates COM objects. It instantiates the COM object to check it. Attackers use this to trigger malicious COM objects (COM Hijacking).",
    response_steps: [
      "1. CLSID: Check the CLSID GUID passed.",
      "2. REGISTRY: Look up that CLSID in HKCU/HKLM to see what DLL it maps to."
    ]
  },
  {
    id: 'LOLBAS_057_WAB',
    title: 'Wab.exe DLL Loading',
    severity: 'LOW',
    module: 'LOLBAS',
    mitre: ['T1218'],
    detection: {
      selection: {
        'process.image': '*wab.exe', // Windows Address Book
        // Usually paired with DLL sideloading (wab32.dll)
      }
    },
    description: "Windows Address Book (wab.exe) is often vulnerable to DLL Search Order Hijacking (wab32.dll).",
    response_steps: [
      "1. DIRECTORY: Is wab.exe running from a non-standard folder?",
      "2. DLL: Check for wab32.dll in the same folder."
    ]
  }
];