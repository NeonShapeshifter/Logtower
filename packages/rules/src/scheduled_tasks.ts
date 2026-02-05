import { Rule } from '@neonshapeshifter/logtower-engine';

export const SCHEDULED_TASKS_RULES: Rule[] = [
  { 
    "id": "TSK_761_SCHTASKS_CREATE_XML", 
    "title": "Schtasks Create from XML", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": ["*/create*", "*/xml*"] } },
    "description": "Creation of a scheduled task from an XML file. Attackers use XML imports to configure complex trigger conditions (like 'on idle') or hidden attributes that are hard to set via command line flags.",
    "response_steps": [
      "1. XML: Retrieve the XML file used for creation.",
      "2. ANALYZE: Check the <Command> and <Arguments> tags in the XML.",
      "3. REMOVE: Delete the task."
    ]
  },
  { 
    "id": "TSK_762_SCHTASKS_SYSTEM_PATH", 
    "title": "Schtasks Masquerading System Path", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tn*", "*\\Microsoft\\Windows*"] } },
    "description": "Creation of a task pretending to be a system task (using 'Microsoft\\Windows' in the path). Attackers do this to hide in plain sight among thousands of legitimate system tasks.",
    "response_steps": [
      "1. VERIFY: Is it a legitimate Windows task re-creation?",
      "2. HASH: Check the hash of the executable it runs.",
      "3. DELETE: Remove the impostor task."
    ]
  },
  { 
    "id": "TSK_763_SCHTASKS_CHANGE", 
    "title": "Schtasks Modify Task", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": ["*/change*", "*/tr*"] } },
    "description": "Modification of an existing scheduled task (/change /tr). Attackers hijack legitimate tasks (like GoogleUpdate) to run their malware instead.",
    "response_steps": [
      "1. TARGET: Which task was modified?",
      "2. NEW PATH: What is the new 'Run' command (/tr)?",
      "3. RESTORE: Revert the task to its original state."
    ]
  },
  { 
    "id": "TSK_764_SCHTASKS_RUN", 
    "title": "Schtasks Run Immediately", 
    "severity": "LOW", 
    "module": "EXECUTION", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": "*/run*" } },
    "description": "Manual execution of a scheduled task (/run). Used by attackers to test their persistence or trigger execution on demand.",
    "response_steps": [
      "1. TASK: Which task was run?",
      "2. CONTEXT: Was this user-initiated or script-initiated?"
    ]
  },
  { 
    "id": "TSK_765_SCHTASKS_ONLOGON", 
    "title": "Schtasks OnLogon Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onlogon*"] } },
    "description": "Creation of a task that runs at user logon. Classic persistence method ensuring the malware runs every time the user signs in.",
    "response_steps": [
      "1. PAYLOAD: Identify the executable.",
      "2. USER: Does it run for all users or a specific one?",
      "3. REMOVE: Delete the task."
    ]
  },
  { 
    "id": "TSK_766_SCHTASKS_ONSTART", 
    "title": "Schtasks OnStart Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onstart*"] } },
    "description": "Creation of a task that runs at system startup (boot). This runs before any user logs in, usually as SYSTEM.",
    "response_steps": [
      "1. PRIVILEGE: This grants SYSTEM level persistence.",
      "2. ISOLATE: High risk.",
      "3. REMOVE: Delete the task."
    ]
  },
  { 
    "id": "TSK_767_SCHTASKS_ONIDLE", 
    "title": "Schtasks OnIdle Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onidle*"] } },
    "description": "Creation of a task that runs when the system is idle. Crypto-miners and heavy malware often use this to avoid user detection.",
    "response_steps": [
      "1. MONITOR: Watch CPU usage when the user is away.",
      "2. REMOVE: Delete the task."
    ]
  },
  { 
    "id": "TSK_768_SCHTASKS_MINUTE", 
    "title": "Schtasks Minute Trigger (Beacon)", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc minute*"] } },
    "description": "Creation of a task that runs every X minutes. Used for frequent C2 beaconing or re-infecting the host if the process is killed.",
    "response_steps": [
      "1. FREQUENCY: How often does it run?",
      "2. NETWORK: Check for periodic network connections matching the task schedule."
    ]
  },
  { 
    "id": "TSK_769_SCHTASKS_SYSTEM_USER", 
    "title": "Schtasks Run as SYSTEM", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/ru SYSTEM*"] } },
    "description": "Creation of a task explicitly configured to run as 'NT AUTHORITY\\SYSTEM'. This provides the highest level of privilege on the local machine.",
    "response_steps": [
      "1. AUTHOR: Who created this task?",
      "2. PAYLOAD: What code requires SYSTEM access?",
      "3. ALERT: Privilege escalation indicator."
    ]
  },
  { 
    "id": "TSK_770_AT_EXEC", 
    "title": "At.exe Scheduled Task", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.002"],
    "detection": { "selection": { "process.image": "*at.exe" } },
    "description": "Usage of the legacy 'at.exe' command. It is deprecated in modern Windows. Its use is highly suspicious and often indicates older malware or lateral movement.",
    "response_steps": [
      "1. LEGACY: This tool shouldn't be used.",
      "2. LATERAL: Often used with 'psexec' or 'smb' attacks.",
      "3. INVESTIGATE: Check scheduled jobs created."
    ]
  },
  { 
    "id": "TSK_771_PS_NEW_TASK", 
    "title": "PowerShell New-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*New-ScheduledTask*" } },
    "description": "Detects usage of the PowerShell ScheduledTasks module to define a new task object.",
    "response_steps": [
      "1. SCRIPT: Identify the script creating the task.",
      "2. INTENT: Is it administrative automation or malware?"
    ]
  },
  { 
    "id": "TSK_772_PS_REGISTER_TASK", 
    "title": "PowerShell Register-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*Register-ScheduledTask*" } },
    "description": "Detects usage of Register-ScheduledTask to save a task definition to the system.",
    "response_steps": [
      "1. DETAILS: Check the task name and action.",
      "2. VERIFY: Confirm with admin."
    ]
  },
  { 
    "id": "TSK_773_PS_SET_TASK", 
    "title": "PowerShell Set-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*Set-ScheduledTask*" } },
    "description": "Detects usage of Set-ScheduledTask to modify an existing task.",
    "response_steps": [
      "1. CHANGE: What attribute was changed? (Action, Principal, Trigger).",
      "2. TARGET: Which task was modified?"
    ]
  },
  { 
    "id": "TSK_774_TASK_TEMP_EXEC", 
    "title": "Task Executing from Temp", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*\\Temp*"] } },
    "description": "Creation of a task that executes a binary located in a Temporary folder. This is a very common malware pattern (dropper + persistence).",
    "response_steps": [
      "1. FILE: Locate the binary in Temp.",
      "2. SAMPLE: Submit to sandbox.",
      "3. REMOVE: Delete task and file."
    ]
  },
  { 
    "id": "TSK_775_TASK_PUBLIC_EXEC", 
    "title": "Task Executing from Public", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*\\Users\\Public*"] } },
    "description": "Creation of a task executing from C:\\Users\\Public. Malware uses this folder because it's writable by all users.",
    "response_steps": [
      "1. ISOLATE: Likely malware persistence.",
      "2. CLEAN: Remove task and payload."
    ]
  },
  { 
    "id": "TSK_776_TASK_POWERSHELL", 
    "title": "Task Executing PowerShell", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*powershell*"] } },
    "description": "Creation of a task that runs PowerShell directly. Attackers use this for fileless persistence (executing an encoded script block).",
    "response_steps": [
      "1. ARGS: Check the task arguments for Base64 code.",
      "2. DECODE: Decode the payload.",
      "3. REMOVE: Delete the task."
    ]
  },
  { 
    "id": "TSK_777_TASK_CMD", 
    "title": "Task Executing CMD", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*cmd.exe*"] } },
    "description": "Creation of a task that runs cmd.exe.",
    "response_steps": [
      "1. COMMAND: What command is being passed to cmd?",
      "2. PURPOSE: Persistence or lateral movement execution?"
    ]
  },
  { 
    "id": "TSK_778_TASK_RUNDLL", 
    "title": "Task Executing Rundll32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*rundll32*"] } },
    "description": "Creation of a task that runs rundll32.exe. Used to persistently load a malicious DLL.",
    "response_steps": [
      "1. DLL: Identify the DLL being loaded.",
      "2. REMOVE: Delete the task and DLL."
    ]
  },
  { 
    "id": "TSK_779_TASK_REGSVR", 
    "title": "Task Executing Regsvr32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*regsvr32*"] } },
    "description": "Creation of a task that runs regsvr32.exe (Squiblydoo technique).",
    "response_steps": [
      "1. URL/FILE: Check arguments for .sct URL or DLL path.",
      "2. BLOCK: Network block if URL based."
    ]
  },
  { 
    "id": "TSK_780_TASK_MSHTA", 
    "title": "Task Executing Mshta", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*mshta*"] } },
    "description": "Creation of a task that runs mshta.exe. Highly indicative of a 'living off the land' attack executing an HTA payload.",
    "response_steps": [
      "1. SOURCE: Identify the HTA source (URL or File).",
      "2. ISOLATE: High confidence malware."
    ]
  },
  { 
    "id": "TSK_781_TASK_WSCRIPT", 
    "title": "Task Executing WScript", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*wscript*"] } },
    "description": "Creation of a task that runs wscript.exe (VBScript/JScript).",
    "response_steps": [
      "1. SCRIPT: Locate the .vbs/.js file.",
      "2. ANALYZE: Deobfuscate script content."
    ]
  },
  { 
    "id": "TSK_782_TASK_CSCRIPT", 
    "title": "Task Executing CScript", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*cscript*"] } },
    "description": "Creation of a task that runs cscript.exe (Command-line script host).",
    "response_steps": [
      "1. SCRIPT: Locate the script file.",
      "2. ANALYZE: Check for malicious logic."
    ]
  },
  { 
    "id": "TSK_783_TASK_ENCODED", 
    "title": "Task with Encoded Command", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*-enc*"] } },
    "description": "Creation of a task with an encoded PowerShell command directly in the arguments. Attempt to hide the payload logic.",
    "response_steps": [
      "1. DECODE: Base64 decode the arguments.",
      "2. ISOLATE: Confirmed malicious persistence."
    ]
  },
  { 
    "id": "TSK_784_TASK_HIDDEN_ATTR", 
    "title": "Task Created Hidden", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*Hidden*"] } },
    "description": "Creation of a task with the 'Hidden' setting enabled. It won't show up in the Task Scheduler GUI by default.",
    "response_steps": [
      "1. LIST: Use 'Get-ScheduledTask' (PowerShell shows hidden tasks).",
      "2. INSPECT: Why hide it?"
    ]
  },
  { 
    "id": "TSK_785_TASK_COMPAT", 
    "title": "Task Compatibility Mode", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*Compatibility*"] } },
    "description": "Setting task compatibility mode. Sometimes used to enable legacy features or hide behavior.",
    "response_steps": [
      "1. CONTEXT: Check other task settings."
    ]
  },
  { 
    "id": "TSK_786_TASK_WAKE", 
    "title": "Task Wake To Run", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*WakeToRun*"] } },
    "description": "Setting a task to wake the computer to run. Ensures the malware runs even if the PC sleeps.",
    "response_steps": [
      "1. CHECK: Often used for maintenance, but also for consistent C2."
    ]
  },
  { 
    "id": "TSK_787_TASK_ALLOW_START", 
    "title": "Task Allow Start If On Batteries", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*AllowStartIfOnBatteries*"] } },
    "description": "Forcing a task to start even on battery power. Default is to stop.",
    "response_steps": [
      "1. CHECK: Aggressive persistence setting."
    ]
  },
  { 
    "id": "TSK_788_TASK_EXEC_BYPASS", 
    "title": "Task Execution Policy Bypass", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*Bypass*"] } },
    "description": "Creation of a task that runs PowerShell with '-ExecutionPolicy Bypass'.",
    "response_steps": [
      "1. PAYLOAD: Review the script.",
      "2. INTENT: Circumventing security controls."
    ]
  },
  { 
    "id": "TSK_789_TASK_WINDOW_HIDDEN", 
    "title": "Task Window Style Hidden", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*Hidden*"] } },
    "description": "Creation of a task that runs PowerShell with '-WindowStyle Hidden'.",
    "response_steps": [
      "1. INVISIBLE: User will see nothing.",
      "2. CHECK: Standard malware tradecraft."
    ]
  },
  { 
    "id": "TSK_790_TASK_NOPROFILE", 
    "title": "Task NoProfile", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*NoProfile*"] } },
    "description": "Creation of a task using '-NoProfile'. Performance optimization for attackers and admins alike.",
    "response_steps": [
      "1. CONTEXT: Check other flags."
    ]
  },
  { 
    "id": "TSK_791_TASK_NONINTERACTIVE", 
    "title": "Task NonInteractive", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*NonInteractive*"] } },
    "description": "Creation of a task using '-NonInteractive'.",
    "response_steps": [
      "1. CONTEXT: Check for background malicious activity."
    ]
  },
  { 
    "id": "TSK_792_TASK_DELETE", 
    "title": "Schtasks Delete Task", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1070"],
    "detection": { "selection": { "process.command_line": ["*/delete*", "*/tn*"] } },
    "description": "Deletion of a scheduled task. Can be cleanup after an attack or legitimate maintenance.",
    "response_steps": [
      "1. TASK: What task was deleted?",
      "2. RECOVER: Check backups if it was a critical task."
    ]
  },
  { 
    "id": "TSK_793_TASK_QUERY", 
    "title": "Schtasks Query Task", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/query*" } },
    "description": "Querying scheduled tasks. Attackers use this to enumerate existing persistence or find vulnerabilities in existing tasks.",
    "response_steps": [
      "1. RECON: Part of situational awareness."
    ]
  },
  { 
    "id": "TSK_794_TASK_FOLDER_CREATE", 
    "title": "Schtasks Create Folder", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/xml*", "*/tn **"] } },
    "description": "Creating a folder structure for tasks.",
    "response_steps": [
      "1. CHECK: What tasks are put inside?"
    ]
  },
  { 
    "id": "TSK_795_TASK_END", 
    "title": "Schtasks End Task", 
    "severity": "LOW", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/end*" } },
    "description": "Manually stopping a running task.",
    "response_steps": [
      "1. CONTEXT: Why was it stopped?"
    ]
  },
  { 
    "id": "TSK_796_TASK_SHOW_SID", 
    "title": "Schtasks Show SID", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/showsid*" } },
    "description": "Showing the Security Identifier (SID) for a task.",
    "response_steps": [
      "1. INFO: Low impact info gathering."
    ]
  },
  { 
    "id": "TSK_797_TASK_DISABLE", 
    "title": "Schtasks Disable Task", 
    "severity": "MEDIUM", 
    "module": "IMPACT", 
    "mitre": ["T1489"],
    "detection": { "selection": { "process.command_line": "*/disable*" } },
    "description": "Disabling a scheduled task. Attackers might disable security update tasks or AV scans.",
    "response_steps": [
      "1. TASK: What was disabled?",
      "2. RESTORE: Re-enable if critical."
    ]
  },
  { 
    "id": "TSK_798_TASK_ENABLE", 
    "title": "Schtasks Enable Task", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/enable*" } },
    "description": "Enabling a scheduled task. Could be re-enabling a disabled payload.",
    "response_steps": [
      "1. TASK: What was enabled?",
      "2. CHECK: Is it malicious?"
    ]
  },
  { 
    "id": "TSK_799_TASK_PARAMS", 
    "title": "Schtasks With Parameters", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr * * *"] } },
    "description": "Creating a task with parameters passed to the executable.",
    "response_steps": [
      "1. ARGS: Check the arguments passed in /tr."
    ]
  },
  { 
    "id": "TSK_800_TASK_DELAY", 
    "title": "Schtasks Delay Modifier", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/delay*"] } },
    "description": "Creating a task with a delay after the trigger. Used to evade sandbox analysis (sleep before execute).",
    "response_steps": [
      "1. EVASION: Delay tactic."
    ]
  },
  { 
    "id": "TSK_801_TASK_RANDOM", 
    "title": "Schtasks Random Delay", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/randomdelay*"] } },
    "description": "Creating a task with a random delay. Used to randomize C2 callbacks and avoid traffic patterns.",
    "response_steps": [
      "1. PATTERN: Harder to detect via network timing analysis."
    ]
  },
  { 
    "id": "TSK_802_TASK_DURATION", 
    "title": "Schtasks Duration Modifier", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/du*"] } },
    "description": "Setting task duration limits.",
    "response_steps": [
      "1. CONTEXT: Usually admin tuning."
    ]
  },
  { 
    "id": "TSK_803_TASK_KILL", 
    "title": "Schtasks Kill If Going On Bat", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/k*"] } },
    "description": "Setting task to kill if computer goes on battery.",
    "response_steps": [
      "1. CONTEXT: Usually admin tuning."
    ]
  },
  { 
    "id": "TSK_804_TASK_RESTART", 
    "title": "Schtasks Restart On Idle", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/ri*"] } },
    "description": "Setting task to restart on idle state.",
    "response_steps": [
      "1. PERSISTENCE: Ensuring execution happens."
    ]
  },
  { 
    "id": "TSK_805_TASK_XML_RAW_EVENT", 
    "title": "Task Creation Raw XML Event", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Command>powershell.exe</Command>*\n" } },
    "description": "Event 4698 (Task Creation) where the Action is PowerShell. Very common for malware.",
    "response_steps": [
      "1. ARGS: Extract arguments from the XML event data.",
      "2. DECODE: Look for base64 payloads."
    ]
  },
  { 
    "id": "TSK_806_TASK_XML_HIDDEN_EVENT", 
    "title": "Task Creation Hidden Attribute", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Hidden>true</Hidden>*\n" } },
    "description": "Event 4698 where the Hidden attribute is true. The task will be invisible in the UI.",
    "response_steps": [
      "1. TASK: Identify the name.",
      "2. INSPECT: Why is it hidden?"
    ]
  },
  { 
    "id": "TSK_807_TASK_XML_AUTHOR_EVENT", 
    "title": "Task Creation Suspicious Author", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Author>System</Author>*\n" } },
    "description": "Event 4698 where Author claims to be 'System'. Malware sometimes spoofs this field.",
    "response_steps": [
      "1. VERIFY: Is it truly a system task?"
    ]
  },
  { 
    "id": "TSK_808_TASK_XML_LOGON_EVENT", 
    "title": "Task Creation Logon Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<LogonTrigger>*\n" } },
    "description": "Event 4698 with a LogonTrigger. Persists at user logon.",
    "response_steps": [
      "1. USER: Which user does it target?",
      "2. ACTION: What does it run?"
    ]
  },
  { 
    "id": "TSK_809_TASK_XML_BOOT_EVENT", 
    "title": "Task Creation Boot Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<BootTrigger>*\n" } },
    "description": "Event 4698 with a BootTrigger. Persists at system startup.",
    "response_steps": [
      "1. SYSTEM: Runs as SYSTEM usually.",
      "2. CHECK: Critical persistence."
    ]
  },
  { 
    "id": "TSK_810_TASK_XML_REGISTRATION_EVENT", 
    "title": "Task Creation Registration Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<RegistrationTrigger>*\n" } },
    "description": "Event 4698 with a RegistrationTrigger. Runs immediately upon creation/registration.",
    "response_steps": [
      "1. EXECUTION: Immediate code execution upon install."
    ]
  }
];
