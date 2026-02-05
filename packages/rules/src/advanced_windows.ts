import { Rule } from '@neonshapeshifter/logtower-engine';

export const ADVANCED_WINDOWS_RULES: Rule[] = [
  { 
    "id": "WMI_861_CMD_CONSUMER_DETECT", 
    "title": "WMI CommandLine Consumer Created", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.destination": "*CommandLineEventConsumer*" } },
    "description": "Detects the creation of a WMI CommandLineEventConsumer. This is a mechanism that executes a command line instruction when a specific event occurs.",
    "response_steps": [
      "1. COMMAND: Identify the command executed by the consumer.",
      "2. TRIGGER: Find the associated Filter (Event 19) to see when it runs.",
      "3. CLEAN: Remove the WMI Consumer and Filter."
    ]
  },
  { 
    "id": "WMI_862_SCRIPT_CONSUMER_DETECT", 
    "title": "WMI ActiveScript Consumer Created", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.destination": "*ActiveScriptEventConsumer*" } },
    "description": "Detects the creation of a WMI ActiveScriptEventConsumer. This allows executing embedded VBScript/JScript directly from the WMI repository (fileless).",
    "response_steps": [
      "1. PAYLOAD: Extract the ScriptText from the consumer.",
      "2. DEOBFUSCATE: Scripts are often obfuscated.",
      "3. REMOVE: Delete the WMI object."
    ]
  },
  { 
    "id": "WMI_863_BINDING_DETECT", 
    "title": "WMI FilterToConsumerBinding Created", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "21", "wmi.consumer": "*Consumer*" } },
    "description": "Detects the creation of a WMI Binding. This links a Trigger (Filter) to an Action (Consumer).",
    "response_steps": [
      "1. LINK: Identify the linked Consumer and Filter.",
      "2. BREAK: Deleting the binding stops the persistence, but leaves the objects."
    ]
  },
  { 
    "id": "WMI_864_FILTER_DETECT", 
    "title": "WMI Event Filter Created", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*SELECT*" } },
    "description": "Detects the creation of a WMI Event Filter. Filters define the condition (trigger) for execution.",
    "response_steps": [
      "1. QUERY: Analyze the WQL query (e.g., 'SELECT * FROM Win32_ProcessStartTrace').",
      "2. CONTEXT: Is this a standard monitoring tool or malicious?"
    ]
  },
  { 
    "id": "WMI_865_POWERSHELL_CONSUMER", 
    "title": "WMI Consumer Executing PowerShell", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*powershell*", "*pwsh*"] } },
    "description": "A WMI Consumer configured to run PowerShell. Highly indicative of fileless malware persistence.",
    "response_steps": [
      "1. ARGS: Check for EncodedCommand or DownloadString.",
      "2. ISOLATE: High confidence threat."
    ]
  },
  { 
    "id": "WMI_866_CMD_CONSUMER_SUSP", 
    "title": "WMI Consumer Executing CMD", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*cmd.exe*", "*%COMSPEC%*"] } },
    "description": "A WMI Consumer configured to run cmd.exe.",
    "response_steps": [
      "1. COMMAND: Review the command line template."
    ]
  },
  { 
    "id": "WMI_867_VBS_CONSUMER_PAYLOAD", 
    "title": "WMI ActiveScript VBS Payload", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.script_text": ["*vbscript*", "*CreateObject*"] } },
    "description": "WMI ActiveScript Consumer containing VBScript code.",
    "response_steps": [
      "1. EXTRACT: Get the script code.",
      "2. ANALYZE: Check for 'CreateObject' or network calls."
    ]
  },
  { 
    "id": "WMI_868_JS_CONSUMER_PAYLOAD", 
    "title": "WMI ActiveScript JScript Payload", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.script_text": ["*JScript*", "*ActiveXObject*"] } },
    "description": "WMI ActiveScript Consumer containing JScript code.",
    "response_steps": [
      "1. EXTRACT: Get the script code.",
      "2. ANALYZE: Check for 'ActiveXObject(\"WScript.Shell\")'."
    ]
  },
  { 
    "id": "WMI_869_SYSTEM_UPTIME_TRIGGER", 
    "title": "WMI Trigger on System Uptime", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*SystemUpTime*" } },
    "description": "WMI Filter triggering based on System Uptime (e.g., run 5 minutes after boot).",
    "response_steps": [
      "1. CHECK: Often used to delay execution to bypass sandboxes."
    ]
  },
  { 
    "id": "WMI_870_LOGON_TRIGGER", 
    "title": "WMI Trigger on Logon", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*Win32_LogonSession*" } },
    "description": "WMI Filter triggering on user logon.",
    "response_steps": [
      "1. CHECK: Standard persistence trigger."
    ]
  },
  { 
    "id": "WMI_871_PROCESS_START_TRIGGER", 
    "title": "WMI Trigger on Process Start", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*Win32_ProcessStartTrace*" } },
    "description": "WMI Filter triggering when a specific process starts. Used to inject code or migrate into target processes.",
    "response_steps": [
      "1. TARGET: What process name is in the query?"
    ]
  },
  { 
    "id": "WMI_872_USB_INSERT_TRIGGER", 
    "title": "WMI Trigger on USB Insert", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*Win32_VolumeChangeEvent*" } },
    "description": "WMI Filter triggering on volume changes (USB insertion). Used by USB spreaders/worms.",
    "response_steps": [
      "1. CHECK: Look for replication behavior."
    ]
  },
  { 
    "id": "WMI_873_TIME_TRIGGER", 
    "title": "WMI Trigger on Specific Time", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*__IntervalTimerInstruction*" } },
    "description": "WMI Filter triggering at specific intervals (Timer).",
    "response_steps": [
      "1. PERIOD: How often does it run?"
    ]
  },
  { 
    "id": "WMI_874_SERVICE_MOD_TRIGGER", 
    "title": "WMI Trigger on Service Modification", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*Win32_Service*" } },
    "description": "WMI Filter triggering when a service is modified. Can be used for defense evasion (monitoring security services).",
    "response_steps": [
      "1. TARGET: Which service is being watched?"
    ]
  },
  { 
    "id": "WMI_875_POWERSPLOIT_PERSISTENCE", 
    "title": "PowerSploit WMI Persistence", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.name": "*PowerSploit*" } },
    "description": "Detects WMI objects named 'PowerSploit'. Default artifacts from the PowerSploit framework.",
    "response_steps": [
      "1. CONFIRM: Known tool signature.",
      "2. REMOVE: Delete the objects."
    ]
  },
  { 
    "id": "WMI_876_EMPIRE_PERSISTENCE", 
    "title": "Empire WMI Persistence", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.name": "*Updater*" } },
    "description": "Detects WMI objects named 'Updater'. Common default for Empire C2.",
    "response_steps": [
      "1. CONFIRM: Likely Empire agent.",
      "2. REMOVE: Delete the objects."
    ]
  },
  { 
    "id": "WMI_877_IMPACKET_WMI", 
    "title": "Impacket WMI Consumer", 
    "severity": "CRITICAL", 
    "module": "LATERAL", 
    "mitre": ["T1047"], 
    "detection": { "selection": { "event_id": "20", "wmi.name": "*Bayer*" } },
    "description": "Detects WMI consumers created by Impacket (often named 'Bayer' in older versions).",
    "response_steps": [
      "1. SOURCE: Identify lateral movement source."
    ]
  },
  { 
    "id": "WMI_878_TEMP_FILE_CONSUMER", 
    "title": "WMI Consumer Executing from Temp", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp**"] } },
    "description": "WMI Consumer executing a binary from a temporary directory.",
    "response_steps": [
      "1. FILE: Locate the dropped binary."
    ]
  },
  { 
    "id": "WMI_879_PUBLIC_FILE_CONSUMER", 
    "title": "WMI Consumer Executing from Public", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*\\Users\\Public**" } },
    "description": "WMI Consumer executing a binary from C:\\Users\\Public.",
    "response_steps": [
      "1. FILE: Locate the dropped binary."
    ]
  },
  { 
    "id": "WMI_880_RUNDLL_CONSUMER", 
    "title": "WMI Consumer Executing Rundll32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*rundll32*" } },
    "description": "WMI Consumer executing rundll32.exe.",
    "response_steps": [
      "1. DLL: Identify the DLL loaded."
    ]
  },
  { 
    "id": "WMI_881_REGSVR_CONSUMER", 
    "title": "WMI Consumer Executing Regsvr32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*regsvr32*" } },
    "description": "WMI Consumer executing regsvr32.exe.",
    "response_steps": [
      "1. PAYLOAD: Check for .sct or .dll execution."
    ]
  },
  { 
    "id": "WMI_882_MSHTA_CONSUMER", 
    "title": "WMI Consumer Executing Mshta", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*mshta*" } },
    "description": "WMI Consumer executing mshta.exe. High probability of HTA payload execution.",
    "response_steps": [
      "1. SOURCE: Identify HTA URL/File."
    ]
  },
  { 
    "id": "WMI_883_CERTUTIL_CONSUMER", 
    "title": "WMI Consumer Executing Certutil", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*certutil*" } },
    "description": "WMI Consumer executing certutil.exe (likely for download/decode).",
    "response_steps": [
      "1. ARGS: Check command line."
    ]
  },
  { 
    "id": "WMI_884_BITS_CONSUMER", 
    "title": "WMI Consumer Executing BITS", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*bitsadmin*" } },
    "description": "WMI Consumer executing bitsadmin.exe.",
    "response_steps": [
      "1. ARGS: Check command line."
    ]
  },
  { 
    "id": "WMI_885_ENCODED_CONSUMER", 
    "title": "WMI Encoded PowerShell Consumer", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*-enc*", "*-encodedcommand*"] } },
    "description": "WMI Consumer running encoded PowerShell.",
    "response_steps": [
      "1. DECODE: Base64 decode the payload."
    ]
  },
  { 
    "id": "WMI_886_HIDDEN_WINDOW_CONSUMER", 
    "title": "WMI Hidden Window Consumer", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*-w hidden*", "*-windowstyle hidden*"] } },
    "description": "WMI Consumer running hidden PowerShell.",
    "response_steps": [
      "1. CHECK: Evasion tactic."
    ]
  },
  { 
    "id": "WMI_887_NOPROFILE_CONSUMER", 
    "title": "WMI NoProfile Consumer", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": ["*-nop*", "*-noprofile*"] } },
    "description": "WMI Consumer using NoProfile switch.",
    "response_steps": [
      "1. CHECK: Evasion tactic."
    ]
  },
  { 
    "id": "WMI_888_EVIL_VBS_CONSUMER", 
    "title": "WMI Consumer VBS Download", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.script_text": "*Microsoft.XMLHTTP*" } },
    "description": "WMI VBScript performing network request (Downloader).",
    "response_steps": [
      "1. URL: Extract URL from script text."
    ]
  },
  { 
    "id": "WMI_889_EVIL_JS_CONSUMER", 
    "title": "WMI Consumer JS Shell", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.script_text": "*WScript.Shell*" } },
    "description": "WMI JScript instantiating WScript.Shell (Execution).",
    "response_steps": [
      "1. COMMAND: Check what is being executed."
    ]
  },
  { 
    "id": "WMI_890_KRYPTON_BINDING", 
    "title": "Krypton Persistence Binding", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "21", "wmi.consumer": "*Krypton*" } },
    "description": "Detection of 'Krypton' named WMI binding.",
    "response_steps": [
      "1. CONFIRM: Malware signature."
    ]
  },
  { 
    "id": "WMI_891_SCM_EVENT_FILTER", 
    "title": "Service Control Manager Filter", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*TargetInstance ISA 'Win32_Service'*" } },
    "description": "WMI Filter targeting Service modifications.",
    "response_steps": [
      "1. CHECK: What action is taken on service change?"
    ]
  },
  { 
    "id": "WMI_892_REGISTRY_EVENT_FILTER", 
    "title": "Registry Key Change Filter", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*RegistryKeyChangeEvent*" } },
    "description": "WMI Filter targeting Registry changes.",
    "response_steps": [
      "1. CHECK: Used for persistence monitoring."
    ]
  },
  { 
    "id": "WMI_893_FILE_CHANGE_FILTER", 
    "title": "File Change Detection Filter", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*CIM_DataFile*" } },
    "description": "WMI Filter targeting file changes.",
    "response_steps": [
      "1. CHECK: Used for persistence monitoring."
    ]
  },
  { 
    "id": "WMI_894_PROCESS_STOP_FILTER", 
    "title": "Process Stop Filter (Persistence)", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "19", "wmi.query": "*Win32_ProcessStopTrace*" } },
    "description": "WMI Filter triggering on process termination. Often used to restart a killed malware process.",
    "response_steps": [
      "1. CHECK: Is it restarting a payload?"
    ]
  },
  { 
    "id": "WMI_895_MOFCOMP_CONSUMER", 
    "title": "WMI Consumer Compiling MOF", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "event_id": "20", "wmi.command_line": "*mofcomp*" } },
    "description": "WMI Consumer running mofcomp.exe. Indicates compilation of a Managed Object Format file (WMI Repository injection).",
    "response_steps": [
      "1. MOF: Identify the MOF file."
    ]
  },
  { 
    "id": "WMI_896_SCRCONS_NET", 
    "title": "Scrcons.exe Network Connection", 
    "severity": "CRITICAL", 
    "module": "COMMAND_AND_CONTROL", 
    "mitre": ["T1071"], 
    "detection": { "selection": { "process.image": "*scrcons.exe", "network.dst_ip": "*" } },
    "description": "Scrcons.exe (WMI Standard Consumer) making a network connection. WMI scripts should not typically make outbound connections directly.",
    "response_steps": [
      "1. ISOLATE: Confirmed malicious script execution via WMI."
    ]
  },
  { 
    "id": "WMI_897_SCRCONS_SUSP_CHILD", 
    "title": "Scrcons.exe Spawning Unknown", 
    "severity": "HIGH", 
    "module": "EXECUTION", 
    "mitre": ["T1047"], 
    "detection": { "selection": { "process.parent_image": "*scrcons.exe", "process.image": ["!*cmd.exe", "!*powershell.exe", "!*wscript.exe", "!*cscript.exe"] } },
    "description": "Scrcons.exe spawning a non-standard child process.",
    "response_steps": [
      "1. PROCESS: What process was spawned?"
    ]
  },
  { 
    "id": "WMI_898_WMIPRVSE_NET_CONN", 
    "title": "Wmiprvse Network Connection", 
    "severity": "MEDIUM", 
    "module": "LATERAL", 
    "mitre": ["T1047"], 
    "detection": { "selection": { "process.image": "*wmiprvse.exe", "network.dst_ip": ["!127.0.0.1", "!::1"] } },
    "description": "Wmiprvse.exe making network connections. Normal for some remote admin, but key indicator of lateral movement.",
    "response_steps": [
      "1. CONTEXT: Authorized management?"
    ]
  },
  { 
    "id": "WMI_899_WMIC_EVENT_CREATE", 
    "title": "WMIC Creating WMI Event", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*namespace*", "*create*"] } },
    "description": "Using WMIC to create WMI namespaces or events manually.",
    "response_steps": [
      "1. CHECK: What was created?"
    ]
  },
  { 
    "id": "WMI_900_POWERSHELL_WMI_EVENT", 
    "title": "PowerShell Register-WmiEvent", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": "*Register-WmiEvent*" } },
    "description": "PowerShell registering a WMI event.",
    "response_steps": [
      "1. CHECK: Script source."
    ]
  },
  { 
    "id": "WMI_901_POWERSHELL_CIM_EVENT", 
    "title": "PowerShell Register-CimIndication", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": "*Register-CimIndicationEvent*" } },
    "description": "PowerShell registering a CIM indication (modern WMI event).",
    "response_steps": [
      "1. CHECK: Script source."
    ]
  },
  { 
    "id": "WMI_902_POWERSHELL_WMI_FILTER", 
    "title": "PowerShell Creating WMI Filter", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": ["*Set-WmiInstance*", "*__EventFilter*"] } },
    "description": "PowerShell creating a WMI Filter.",
    "response_steps": [
      "1. CHECK: What is the query?"
    ]
  },
  { 
    "id": "WMI_903_POWERSHELL_WMI_CONSUMER", 
    "title": "PowerShell Creating WMI Consumer", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": ["*Set-WmiInstance*", "*EventConsumer*"] } },
    "description": "PowerShell creating a WMI Consumer.",
    "response_steps": [
      "1. CHECK: What is the payload?"
    ]
  },
  { 
    "id": "WMI_904_POWERSHELL_WMI_BINDING", 
    "title": "PowerShell Creating WMI Binding", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1546.003"], 
    "detection": { "selection": { "process.command_line": ["*Set-WmiInstance*", "*__FilterToConsumerBinding*"] } },
    "description": "PowerShell binding WMI components.",
    "response_steps": [
      "1. CHECK: Confirms persistence establishment."
    ]
  },
  { 
    "id": "WMI_905_WBEMTEST_EXEC", 
    "title": "Wbemtest GUI Usage (Suspicious)", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1047"], 
    "detection": { "selection": { "process.image": "*wbemtest.exe" } },
    "description": "Usage of wbemtest.exe (WMI Tester). Sometimes used by attackers for manual WMI interaction.",
    "response_steps": [
      "1. CONTEXT: Is this an admin debugging?"
    ]
  },
  { 
    "id": "WMI_906_WMIC_NODE_EXEC", 
    "title": "WMIC Remote Node Execution", 
    "severity": "HIGH", 
    "module": "LATERAL", 
    "mitre": ["T1047"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*/node:*", "*process call create*"] } },
    "description": "WMIC execution on a remote node.",
    "response_steps": [
      "1. TARGET: Identify remote machine."
    ]
  },
  { 
    "id": "WMI_907_WMIC_PROCESS_GET", 
    "title": "WMIC Process Listing", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1057"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*process list*", "*brief*"] } },
    "description": "WMIC process enumeration.",
    "response_steps": [
      "1. CONTEXT: Reconnaissance."
    ]
  },
  { 
    "id": "WMI_908_WMIC_SERVICE_GET", 
    "title": "WMIC Service Listing", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1007"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*service list*"] } },
    "description": "WMIC service enumeration.",
    "response_steps": [
      "1. CONTEXT: Reconnaissance."
    ]
  },
  { 
    "id": "WMI_909_WMIC_NIC_GET", 
    "title": "WMIC Network Config Recon", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1016"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*nicconfig*"] } },
    "description": "WMIC network configuration enumeration.",
    "response_steps": [
      "1. CONTEXT: Reconnaissance."
    ]
  },
  { 
    "id": "WMI_910_WMIC_USER_GET", 
    "title": "WMIC User Recon", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1087"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*useraccount*"] } },
    "description": "WMIC user account enumeration.",
    "response_steps": [
      "1. CONTEXT: Reconnaissance."
    ]
  },
  { 
    "id": "INJ_911_CRT_UNKNOWN_SOURCE", 
    "title": "CreateRemoteThread from Unknown Process", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": ["*\\AppData\\Local\\Temp*", "*\\Users\\Public**"] } },
    "description": "A process running from a temporary location injected code into another process (CreateRemoteThread).",
    "response_steps": [
      "1. SOURCE: Identify the injector process.",
      "2. ISOLATE: Likely malware injection."
    ]
  },
  { 
    "id": "INJ_912_CRT_LSASS", 
    "title": "Remote Thread in LSASS", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1003.001"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*lsass.exe", "process.source_image": ["!*svchost.exe", "!*MsMpEng.exe"] } },
    "description": "Code injection into LSASS. This is how Mimikatz and other credential dumpers work.",
    "response_steps": [
      "1. ISOLATE: Credential theft attempt.",
      "2. RESET: Reset passwords."
    ]
  },
  { 
    "id": "INJ_913_CRT_WINLOGON", 
    "title": "Remote Thread in Winlogon", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1547.004"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*winlogon.exe", "process.source_image": ["!*csrss.exe", "!*smss.exe", "!*svchost.exe"] } },
    "description": "Injection into Winlogon.exe. Used for credential stealing or persistence.",
    "response_steps": [
      "1. ISOLATE: High privilege compromise."
    ]
  },
  { 
    "id": "INJ_914_CRT_CSRSS", 
    "title": "Remote Thread in CSRSS", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*csrss.exe", "process.source_image": ["!*smss.exe", "!*svchost.exe"] } },
    "description": "Injection into CSRSS.exe. Used to hide from tools or gain system privileges.",
    "response_steps": [
      "1. ISOLATE: High privilege compromise."
    ]
  },
  { 
    "id": "INJ_915_CRT_SERVICES", 
    "title": "Remote Thread in Services.exe", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*services.exe", "process.source_image": ["!*wininit.exe"] } },
    "description": "Injection into Services.exe.",
    "response_steps": [
      "1. ISOLATE: High privilege compromise."
    ]
  },
  { 
    "id": "INJ_916_CRT_SVCHOST", 
    "title": "Suspicious Injection into Svchost", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*svchost.exe", "process.source_image": ["*powershell.exe", "*cmd.exe", "*winword.exe", "*excel.exe"] } },
    "description": "A script or document injected code into svchost.exe. Common malware behavior to hide payload.",
    "response_steps": [
      "1. KILL: Terminate the specific svchost PID."
    ]
  },
  { 
    "id": "INJ_917_CRT_EXPLORER", 
    "title": "Suspicious Injection into Explorer", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": "*explorer.exe", "process.source_image": ["*powershell.exe", "*cmd.exe", "*rundll32.exe"] } },
    "description": "Injection into Explorer.exe. Used to persist in the user's session.",
    "response_steps": [
      "1. CHECK: Malware or legitimate overlay tool?"
    ]
  },
  { 
    "id": "INJ_918_CRT_BROWSER", 
    "title": "Injection into Browser (Man-in-the-Browser)", 
    "severity": "HIGH", 
    "module": "CRED", 
    "mitre": ["T1185"], 
    "detection": { "selection": { "event_id": "8", "process.target_image": ["*chrome.exe", "*firefox.exe", "*msedge.exe"], "process.source_image": ["!*chrome.exe", "!*firefox.exe", "!*msedge.exe", "!*GoogleUpdate.exe"] } },
    "description": "Injection into a browser process from an external source. Used to steal banking credentials or cookies.",
    "response_steps": [
      "1. SOURCE: Identify injector.",
      "2. CLEAN: Reinstall browser."
    ]
  },
  { 
    "id": "INJ_919_CRT_OFFICE_SOURCE", 
    "title": "Office Process Injecting Code", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": ["*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe"] } },
    "description": "Office process performing code injection. Confirmed malicious macro activity.",
    "response_steps": [
      "1. ISOLATE: Active exploit."
    ]
  },
  { 
    "id": "INJ_920_CRT_PS_SOURCE", 
    "title": "PowerShell Injecting Code", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": ["*powershell.exe", "*pwsh.exe"] } },
    "description": "PowerShell injecting code (e.g., Invoke-Shellcode).",
    "response_steps": [
      "1. ISOLATE: Fileless malware."
    ]
  },
  { 
    "id": "INJ_921_CRT_CMD_SOURCE", 
    "title": "CMD Injecting Code", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*cmd.exe" } },
    "description": "CMD process performing injection. Very unusual.",
    "response_steps": [
      "1. ISOLATE: Likely malicious."
    ]
  },
  { 
    "id": "INJ_922_CRT_RUNDLL_SOURCE", 
    "title": "Rundll32 Injecting Code", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*rundll32.exe" } },
    "description": "Rundll32 injecting code. Often Cobalt Strike beacon.",
    "response_steps": [
      "1. ISOLATE: High confidence threat."
    ]
  },
  { 
    "id": "INJ_923_CRT_REGSVR_SOURCE", 
    "title": "Regsvr32 Injecting Code", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*regsvr32.exe" } },
    "description": "Regsvr32 injecting code.",
    "response_steps": [
      "1. ISOLATE: Malicious."
    ]
  },
  { 
    "id": "INJ_924_CRT_WMIC_SOURCE", 
    "title": "WMIC Injecting Code", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*wmic.exe" } },
    "description": "WMIC injecting code. Rare and suspicious.",
    "response_steps": [
      "1. ISOLATE: Malicious."
    ]
  },
  { 
    "id": "INJ_925_CRT_MSHTA_SOURCE", 
    "title": "Mshta Injecting Code", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*mshta.exe" } },
    "description": "Mshta (HTA) injecting code.",
    "response_steps": [
      "1. ISOLATE: Malicious."
    ]
  },
  { 
    "id": "INJ_926_CRT_VERCLSID_SOURCE", 
    "title": "Verclsid Injecting Code", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.source_image": "*verclsid.exe" } },
    "description": "Verclsid injecting code (COM Hijack).",
    "response_steps": [
      "1. ISOLATE: Malicious."
    ]
  },
  { 
    "id": "INJ_927_CRT_CROSS_SESSION", 
    "title": "Cross-Session Injection", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8" } },
    "description": "Injection across different user sessions.",
    "response_steps": [
      "1. CHECK: Privilege escalation."
    ]
  },
  { 
    "id": "INJ_928_CRT_LOADLIBRARY", 
    "title": "Injection via LoadLibrary", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055.001"], 
    "detection": { "selection": { "event_id": "8", "process.start_function": "*LoadLibrary*" } },
    "description": "Remote thread started at LoadLibrary address. DLL Injection.",
    "response_steps": [
      "1. CHECK: Which DLL?"
    ]
  },
  { 
    "id": "INJ_929_CRT_WOW64_TRANSITION", 
    "title": "Wow64 Transition Injection", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "8", "process.start_address": "*0x00000000*" } },
    "description": "Injection involving Wow64 transition (32-bit to 64-bit).",
    "response_steps": [
      "1. CONTEXT: Often seen in Heaven's Gate technique."
    ]
  },
  { 
    "id": "INJ_930_PROCESS_HOLLOWING_GENERIC", 
    "title": "Potential Process Hollowing (Image Mismatch)", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "event_id": "25", "raw.Type": "ImageMismatch" } },
    "description": "Sysmon Event 25 (Process Tampering) detecting Image Mismatch. Strong indicator of Process Hollowing.",
    "response_steps": [
      "1. ISOLATE: Confirmed process replacement."
    ]
  },
  { 
    "id": "INJ_931_PROCESS_HERPADERPING", 
    "title": "Process Herpaderping Activity", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "event_id": "25" } },
    "description": "Process Tampering event potentially indicating Herpaderping (modifying file on disk after mapping).",
    "response_steps": [
      "1. ISOLATE: Advanced evasion."
    ]
  },
  { 
    "id": "INJ_932_ATOM_BOMBING", 
    "title": "Atom Bombing Injection", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.005"], 
    "detection": { "selection": { "event_id": "8", "process.start_function": "*NtQueueApcThread*" } },
    "description": "Injection using APCs and Atom Tables.",
    "response_steps": [
      "1. ISOLATE: Advanced technique."
    ]
  },
  { 
    "id": "INJ_933_APC_INJECTION", 
    "title": "APC Injection Pattern", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055.004"], 
    "detection": { "selection": { "event_id": "8", "process.start_function": "*QueueUserAPC*" } },
    "description": "Injection using QueueUserAPC.",
    "response_steps": [
      "1. ISOLATE: Common in modern malware."
    ]
  },
  { 
    "id": "INJ_934_EARLY_BIRD", 
    "title": "Early Bird Injection", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.004"], 
    "detection": { "selection": { "process.command_line": ["*QueueUserAPC*", "*ResumeThread*"] } },
    "description": "Early Bird injection technique (Queue APC before thread start).",
    "response_steps": [
      "1. ISOLATE: Evasion technique."
    ]
  },
  { 
    "id": "INJ_935_REFLECTIVE_LOADER", 
    "title": "Reflective DLL Loader Artifact", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.001"], 
    "detection": { "selection": { "event_id": "8", "process.start_function": "*ReflectiveLoader*" } },
    "description": "Artifact of Reflective DLL Injection (start function named ReflectiveLoader).",
    "response_steps": [
      "1. ISOLATE: Metasploit/Cobalt Strike artifact."
    ]
  },
  { 
    "id": "INJ_936_SUSP_PARENT_SVCHOST", 
    "title": "Svchost with Non-Services Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*svchost.exe", "process.parent_image": ["!*services.exe", "!*MsMpEng.exe"] } },
    "description": "Svchost.exe spawned by something other than services.exe. Likely Process Hollowing or Fake Process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_937_SUSP_PARENT_SMSS", 
    "title": "Smss with Non-System Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*smss.exe", "process.parent_image": ["!*System*", "!*smss.exe"] } },
    "description": "Smss.exe spawned by non-System process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_938_SUSP_PARENT_CSRSS", 
    "title": "Csrss with Non-Smss Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*csrss.exe", "process.parent_image": ["!*smss.exe", "!*svchost.exe"] } },
    "description": "Csrss.exe spawned by non-Smss process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_939_SUSP_PARENT_WININIT", 
    "title": "Wininit with Non-Smss Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*wininit.exe", "process.parent_image": ["!*smss.exe"] } },
    "description": "Wininit.exe spawned by non-Smss process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_940_SUSP_PARENT_WINLOGON", 
    "title": "Winlogon with Non-Smss Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*winlogon.exe", "process.parent_image": ["!*smss.exe"] } },
    "description": "Winlogon.exe spawned by non-Smss process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_941_SUSP_PARENT_LSASS", 
    "title": "Lsass with Non-Wininit Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*lsass.exe", "process.parent_image": ["!*wininit.exe"] } },
    "description": "Lsass.exe spawned by non-Wininit process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_942_SUSP_PARENT_SERVICES", 
    "title": "Services with Non-Wininit Parent", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1036.005"], 
    "detection": { "selection": { "process.image": "*services.exe", "process.parent_image": ["!*wininit.exe"] } },
    "description": "Services.exe spawned by non-Wininit process.",
    "response_steps": [
      "1. KILL: Fake process."
    ]
  },
  { 
    "id": "INJ_943_SPOOFED_PARENT", 
    "title": "Parent Process ID Spoofing", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1134.004"], 
    "detection": { "selection": { "process.command_line": "*UpdateProcThreadAttribute*" } },
    "description": "Usage of UpdateProcThreadAttribute to spoof parent PID.",
    "response_steps": [
      "1. CHECK: Evasion technique."
    ]
  },
  { 
    "id": "INJ_944_PROCESSHACKER_DRIVER", 
    "title": "KProcessHacker Loaded (Injection Tool)", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1562"], 
    "detection": { "selection": { "image_load.file_name": "kprocesshacker.sys" } },
    "description": "Loading of Process Hacker driver. Can be used to terminate security tools.",
    "response_steps": [
      "1. CHECK: Admin tool or malware?"
    ]
  },
  { 
    "id": "INJ_945_MIMIDRV_LOAD", 
    "title": "Mimidrv Loaded (Injection Tool)", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562"], 
    "detection": { "selection": { "image_load.file_name": "mimidrv.sys" } },
    "description": "Loading of Mimikatz driver (mimidrv).",
    "response_steps": [
      "1. ISOLATE: Credential theft."
    ]
  },
  { 
    "id": "INJ_946_GDRV_LOAD", 
    "title": "GDRV Loaded (Vulnerable Driver)", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1068"], 
    "detection": { "selection": { "image_load.file_name": "gdrv.sys" } },
    "description": "Loading of vulnerable Gigabyte driver (BYOVD attack).",
    "response_steps": [
      "1. CHECK: Exploit attempt."
    ]
  },
  { 
    "id": "INJ_947_CAPCOM_LOAD", 
    "title": "Capcom Loaded (Vulnerable Driver)", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1068"], 
    "detection": { "selection": { "image_load.file_name": "capcom.sys" } },
    "description": "Loading of vulnerable Capcom driver (BYOVD attack).",
    "response_steps": [
      "1. CHECK: Exploit attempt."
    ]
  },
  { 
    "id": "INJ_948_WINRING0_LOAD", 
    "title": "WinRing0 Loaded (Vulnerable Driver)", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1068"], 
    "detection": { "selection": { "image_load.file_name": "WinRing0.sys" } },
    "description": "Loading of vulnerable WinRing0 driver (BYOVD attack).",
    "response_steps": [
      "1. CHECK: Exploit attempt."
    ]
  },
  { 
    "id": "INJ_949_PROCESSHOLLOW_WERFAULT", 
    "title": "WerFault Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*WerFault.exe", "process.parent_image": ["!*svchost.exe", "!*wermgr.exe"] } },
    "description": "WerFault.exe hollowed out. Common target.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_950_PROCESSHOLLOW_DLLHOST", 
    "title": "DllHost Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*dllhost.exe", "process.parent_image": ["!*svchost.exe", "!*services.exe"] } },
    "description": "DllHost.exe hollowed out.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_951_PROCESSHOLLOW_RUNDLL", 
    "title": "Rundll32 Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*rundll32.exe", "process.parent_image": ["!*cmd.exe", "!*powershell.exe", "!*explorer.exe"] } },
    "description": "Rundll32.exe hollowed out.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_952_PROCESSHOLLOW_REGASM", 
    "title": "RegAsm Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*regasm.exe", "process.parent_image": ["!*msiexec.exe"] } },
    "description": "RegAsm.exe hollowed out.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_953_PROCESSHOLLOW_REGSVCS", 
    "title": "RegSvcs Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*regsvcs.exe", "process.parent_image": ["!*msiexec.exe"] } },
    "description": "RegSvcs.exe hollowed out.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_954_PROCESSHOLLOW_CVTRES", 
    "title": "Cvtures Process Hollowing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*cvtres.exe" } },
    "description": "Cvtures.exe hollowed out.",
    "response_steps": [
      "1. ISOLATE: Hollowing detected."
    ]
  },
  { 
    "id": "INJ_955_PROCESSHOLLOW_CALC", 
    "title": "Calc Process Hollowing (Anomaly)", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*calc.exe", "network.dst_ip": "*" } },
    "description": "Calc.exe making network connections. Impossible unless hollowed.",
    "response_steps": [
      "1. ISOLATE: Anomaly confirmed."
    ]
  },
  { 
    "id": "INJ_956_PROCESSHOLLOW_NOTEPAD", 
    "title": "Notepad Process Hollowing (Anomaly)", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*notepad.exe", "network.dst_ip": "*" } },
    "description": "Notepad.exe making network connections.",
    "response_steps": [
      "1. ISOLATE: Anomaly confirmed."
    ]
  },
  { 
    "id": "INJ_957_PROCESSHOLLOW_MSPAINT", 
    "title": "MsPaint Process Hollowing (Anomaly)", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1055.012"], 
    "detection": { "selection": { "process.image": "*mspaint.exe", "network.dst_ip": "*" } },
    "description": "MsPaint.exe making network connections.",
    "response_steps": [
      "1. ISOLATE: Anomaly confirmed."
    ]
  },
  { 
    "id": "INJ_958_DOTNET_TO_JS_LOAD", 
    "title": "DotNetToJScript Injection", 
    "severity": "HIGH", 
    "module": "EXECUTION", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "process.command_line": "*DotNetToJScript*" } },
    "description": "Execution of DotNetToJScript tool.",
    "response_steps": [
      "1. ISOLATE: Malicious tool."
    ]
  },
  { 
    "id": "INJ_959_GADGETTOJCRIPT", 
    "title": "GadgetToJScript Injection", 
    "severity": "HIGH", 
    "module": "EXECUTION", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "process.command_line": "*GadgetToJScript*" } },
    "description": "Execution of GadgetToJScript tool.",
    "response_steps": [
      "1. ISOLATE: Malicious tool."
    ]
  },
  { 
    "id": "INJ_960_CACTUSTORCH", 
    "title": "CactusTorch Injection", 
    "severity": "CRITICAL", 
    "module": "EXECUTION", 
    "mitre": ["T1055"], 
    "detection": { "selection": { "process.command_line": "*CactusTorch*" } },
    "description": "Execution of CactusTorch shellcode launcher.",
    "response_steps": [
      "1. ISOLATE: Malicious tool."
    ]
  },
  { 
    "id": "GPO_961_SYSVOL_WRITE", 
    "title": "Write to SYSVOL Scripts", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.path": "*\\SYSVOL*\\scripts**" } },
    "description": "File write to SYSVOL scripts folder. Replicates to all DCs and runs on clients.",
    "response_steps": [
      "1. ISOLATE: Domain compromise."
    ]
  },
  { 
    "id": "GPO_962_GPT_INI_MOD", 
    "title": "GPO gpt.ini Modification", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.name": "gpt.ini" } },
    "description": "Modification of gpt.ini in GPO.",
    "response_steps": [
      "1. CHECK: Unauthorized GPO change."
    ]
  },
  { 
    "id": "GPO_963_SCHEDULED_TASK_GPO", 
    "title": "Scheduled Task via GPO", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"], 
    "detection": { "selection": { "file.path": "*\\Preferences\\ScheduledTasks\\ScheduledTasks.xml" } },
    "description": "Creating scheduled task via GPO. Mass persistence.",
    "response_steps": [
      "1. CHECK: What task is deployed?"
    ]
  },
  { 
    "id": "GPO_964_REGISTRY_POL_MOD", 
    "title": "Registry.pol Modification", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.name": "Registry.pol" } },
    "description": "Modification of Registry.pol (GPO settings).",
    "response_steps": [
      "1. CHECK: What setting is changed?"
    ]
  },
  { 
    "id": "GPO_965_GPO_SCRIPT_ADD", 
    "title": "GPO Logon/Startup Script Add", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1037"], 
    "detection": { "selection": { "file.path": ["*\\Scripts\\Startup*", "*\\Scripts\\Logon*", "*\\Scripts\\Shutdown**"] } },
    "description": "Adding scripts to GPO Logon/Startup paths.",
    "response_steps": [
      "1. ISOLATE: Mass execution risk."
    ]
  },
  { 
    "id": "GPO_966_NEW_GPO_CREATE", 
    "title": "New GPO Created", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "event_id": "5137" } },
    "description": "A new Group Policy Object was created.",
    "response_steps": [
      "1. VERIFY: Authorized change?"
    ]
  },
  { 
    "id": "GPO_967_GPO_DELETED", 
    "title": "GPO Deleted", 
    "severity": "MEDIUM", 
    "module": "IMPACT", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "event_id": "5141" } },
    "description": "A GPO was deleted.",
    "response_steps": [
      "1. VERIFY: Authorized?"
    ]
  },
  { 
    "id": "GPO_968_GPO_LINK_CHANGE", 
    "title": "GPO Link Changed", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.attribute": "gPLink" } },
    "description": "GPO linked to a new OU or Domain root.",
    "response_steps": [
      "1. SCOPE: Where does it apply now?"
    ]
  },
  { 
    "id": "GPO_969_GPO_PERMISSION_CHANGE", 
    "title": "GPO Permissions Changed", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.attribute": "nTSecurityDescriptor" } },
    "description": "Permissions on a GPO were changed. Can be used to hide it or allow editing by unauthorized users.",
    "response_steps": [
      "1. VERIFY: Who was granted access?"
    ]
  },
  { 
    "id": "GPO_970_SHARP_GPO_ABUSE", 
    "title": "SharpGPOAbuse Tool", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": ["*SharpGPOAbuse*", "*--AddLocalAdmin*", "*--AddUserRights*"] } },
    "description": "Execution of SharpGPOAbuse tool.",
    "response_steps": [
      "1. ISOLATE: Malicious tool usage."
    ]
  },
  { 
    "id": "GPO_971_POWERSPLIOT_NEW_GPO", 
    "title": "PowerSploit New-GPOImmediateTask", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": "*New-GPOImmediateTask*" } },
    "description": "Execution of PowerSploit GPO persistence module.",
    "response_steps": [
      "1. ISOLATE: Malicious tool usage."
    ]
  },
  { 
    "id": "GPO_972_STANDALONE_GPO_TOOL", 
    "title": "LGPO.exe Tool Usage", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.image": "*LGPO.exe" } },
    "description": "Usage of LGPO.exe tool for local GPO manipulation.",
    "response_steps": [
      "1. CONTEXT: Admin or attacker?"
    ]
  },
  { 
    "id": "ACL_973_DS_ACL_CHANGE", 
    "title": "Directory Service ACL Change", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.attribute": "nTSecurityDescriptor" } },
    "description": "ACL change on an AD object.",
    "response_steps": [
      "1. CHECK: Which object?"
    ]
  },
  { 
    "id": "ACL_974_OWNER_CHANGE", 
    "title": "Directory Service Owner Change", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.attribute": "nTOwner" } },
    "description": "Owner change on an AD object.",
    "response_steps": [
      "1. CHECK: Who took ownership?"
    ]
  },
  { 
    "id": "ACL_975_ADMINSDHOLDER_ACL", 
    "title": "AdminSDHolder ACL Change", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.object_dn": "*CN=AdminSDHolder,CN=System*" } },
    "description": "ACL change on AdminSDHolder. Persistence via SDProp.",
    "response_steps": [
      "1. ISOLATE: Domain backdoor."
    ]
  },
  { 
    "id": "ACL_976_DOMAIN_HEAD_ACL", 
    "title": "Domain Head ACL Change", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.object_dn": "DC=*,DC=*" } },
    "description": "ACL change on the Domain root object (DCSync preparation).",
    "response_steps": [
      "1. ISOLATE: Domain compromise."
    ]
  },
  { 
    "id": "ACL_977_KRBTGT_ACL", 
    "title": "KRBTGT ACL Change", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.object_dn": "*CN=krbtgt*" } },
    "description": "ACL change on KRBTGT account.",
    "response_steps": [
      "1. ISOLATE: Golden Ticket prep."
    ]
  },
  { 
    "id": "ACL_978_GPO_FILESYSTEM_ACL", 
    "title": "GPO FileSystem ACL Change", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "file.path": "*\\Policies*\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" } },
    "description": "GPO FileSystem ACL modification.",
    "response_steps": [
      "1. CHECK: What permissions are pushed?"
    ]
  },
  { 
    "id": "ACL_979_ICACLS_GRANT", 
    "title": "Icacls Grant Permissions", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222.001"], 
    "detection": { "selection": { "process.command_line": ["*icacls*", "*/grant*"] } },
    "description": "Using icacls to grant permissions.",
    "response_steps": [
      "1. CHECK: To whom and what file?"
    ]
  },
  { 
    "id": "ACL_980_TAKEOWN_EXEC", 
    "title": "Takeown Ownership", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222.001"], 
    "detection": { "selection": { "process.command_line": ["*takeown*", "*/f*"] } },
    "description": "Taking ownership of a file.",
    "response_steps": [
      "1. CHECK: Why is this needed?"
    ]
  },
  { 
    "id": "ACL_981_ATTRIB_HIDDEN", 
    "title": "Attrib Hide File", 
    "severity": "LOW", 
    "module": "DEFENSE", 
    "mitre": ["T1564.001"], 
    "detection": { "selection": { "process.command_line": ["*attrib*", "*+h*"] } },
    "description": "Hiding a file with attrib +h.",
    "response_steps": [
      "1. CHECK: What file?"
    ]
  },
  { 
    "id": "ACL_982_ATTRIB_SYSTEM", 
    "title": "Attrib System File", 
    "severity": "LOW", 
    "module": "DEFENSE", 
    "mitre": ["T1564.001"], 
    "detection": { "selection": { "process.command_line": ["*attrib*", "*+s*"] } },
    "description": "Setting system attribute with attrib +s.",
    "response_steps": [
      "1. CHECK: What file?"
    ]
  },
  { 
    "id": "ACL_983_DSACLS_USAGE", 
    "title": "Dsacls Usage", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "process.image": "*dsacls.exe" } },
    "description": "Usage of dsacls to modify AD ACLs.",
    "response_steps": [
      "1. CHECK: Critical permission changes."
    ]
  },
  { 
    "id": "ACL_984_SDDL_MODIFICATION", 
    "title": "SDDL String Modification", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "process.command_line": "*D:(A;*" } },
    "description": "Manual SDDL string usage in command line.",
    "response_steps": [
      "1. CHECK: Advanced permission setting."
    ]
  },
  { 
    "id": "GPO_985_RESTRICTED_GROUPS", 
    "title": "Restricted Groups GPO Mod", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "file.path": "*\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" } },
    "description": "GPO Restricted Groups modification.",
    "response_steps": [
      "1. CHECK: Group membership enforcement."
    ]
  },
  { 
    "id": "GPO_986_SOFTWARE_INSTALL_GPO", 
    "title": "Software Installation GPO", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.path": "*\\User\\Applications*.aap" } },
    "description": "GPO Software Installation payload.",
    "response_steps": [
      "1. CHECK: What software?"
    ]
  },
  { 
    "id": "GPO_987_FOLDER_REDIRECTION", 
    "title": "Folder Redirection GPO", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.path": "*\\Documents & Settings\\fdeploy.ini" } },
    "description": "GPO Folder Redirection.",
    "response_steps": [
      "1. CHECK: Redirecting where?"
    ]
  },
  { 
    "id": "GPO_988_IE_SETTINGS_GPO", 
    "title": "IE Settings GPO Mod", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "file.path": "*\\Internet Explorer*.ins" } },
    "description": "GPO Internet Explorer settings.",
    "response_steps": [
      "1. CHECK: Proxy or home page change?"
    ]
  },
  { 
    "id": "GPO_989_GPO_WMI_FILTER", 
    "title": "GPO WMI Filter Modification", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "event_id": "5136", "ad_change.class": "msWMI-Som" } },
    "description": "GPO WMI Filter change.",
    "response_steps": [
      "1. CHECK: Targeting specific machines."
    ]
  },
  { 
    "id": "GPO_990_GPO_BACKUP", 
    "title": "GPO Backup Operation", 
    "severity": "MEDIUM", 
    "module": "COLLECTION", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": ["*Backup-GPO*", "*BackupGPO*"] } },
    "description": "Backup of GPO settings.",
    "response_steps": [
      "1. VERIFY: Authorized?"
    ]
  },
  { 
    "id": "GPO_991_GPO_RESTORE", 
    "title": "GPO Restore Operation", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": ["*Restore-GPO*", "*RestoreGPO*"] } },
    "description": "Restoring a GPO (potentially from malicious backup).",
    "response_steps": [
      "1. VERIFY: Integrity of backup."
    ]
  },
  { 
    "id": "GPO_992_GPO_IMPORT", 
    "title": "GPO Import Operation", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": "*Import-GPO*" } },
    "description": "Importing GPO settings.",
    "response_steps": [
      "1. VERIFY: Source of settings."
    ]
  },
  { 
    "id": "GPO_993_GPUPDATE_FORCE", 
    "title": "Gpupdate Force (Suspicious)", 
    "severity": "LOW", 
    "module": "EXECUTION", 
    "mitre": ["T1484.001"], 
    "detection": { "selection": { "process.command_line": ["*gpupdate*", "*/force*"] } },
    "description": "Forcing GPO update. Attackers do this to apply their malicious GPO immediately.",
    "response_steps": [
      "1. CONTEXT: Usually admin."
    ]
  },
  { 
    "id": "GPO_994_GPRESULT_RECON", 
    "title": "Gpresult Reconnaissance", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1615"], 
    "detection": { "selection": { "process.command_line": ["*gpresult*", "*/z*"] } },
    "description": "GPO result enumeration.",
    "response_steps": [
      "1. INFO: Gathering applied settings."
    ]
  },
  { 
    "id": "GPO_995_GET_GPO_ALL", 
    "title": "Get-GPO All (Recon)", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1615"], 
    "detection": { "selection": { "process.command_line": ["*Get-GPO*", "*-All*"] } },
    "description": "Enumerating all GPOs in domain.",
    "response_steps": [
      "1. RECON: Mapping policies."
    ]
  },
  { 
    "id": "GPO_996_GET_GPO_REPORT", 
    "title": "Get-GPOReport (Recon)", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1615"], 
    "detection": { "selection": { "process.command_line": "*Get-GPOReport*" } },
    "description": "Exporting GPO report.",
    "response_steps": [
      "1. INFO: Detailed policy analysis."
    ]
  },
  { 
    "id": "ACL_997_CACLS_USAGE", 
    "title": "Cacls Legacy Tool Usage", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "process.image": "*cacls.exe" } },
    "description": "Usage of legacy cacls.exe.",
    "response_steps": [
      "1. CHECK: ACL modification."
    ]
  },
  { 
    "id": "ACL_998_XCACLS_USAGE", 
    "title": "XCacls Tool Usage", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "process.image": "*xcacls.exe" } },
    "description": "Usage of xcacls.exe.",
    "response_steps": [
      "1. CHECK: ACL modification."
    ]
  },
  { 
    "id": "ACL_999_SUBINACL_USAGE", 
    "title": "SubInACL Tool Usage", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1222"], 
    "detection": { "selection": { "process.image": "*subinacl.exe" } },
    "description": "Usage of subinacl.exe.",
    "response_steps": [
      "1. CHECK: Advanced ACL modification."
    ]
  },
  { 
    "id": "FINAL_1000_LOGTOWER_SENTINEL", 
    "title": "Logtower Sentinel Check", 
    "severity": "INFO", 
    "module": "INTERNAL", 
    "mitre": ["N/A"], 
    "detection": { "selection": { "process.command_line": "LOGTOWER_SENTINEL_CHECK_1000" } },
    "description": "Internal health check rule.",
    "response_steps": [
      "1. IGNORE: System check."
    ]
  }
];