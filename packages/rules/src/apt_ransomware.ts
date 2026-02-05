import { Rule } from '@neonshapeshifter/logtower-engine';

export const APT_RANSOMWARE_RULES: Rule[] = [
  {
    "id": "WMI_201_CMD_CONSUMER",
    "title": "WMI CommandLine Consumer Created",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.destination": "*CommandLineEventConsumer*"
      }
    },
    "description": "A WMI CommandLineEventConsumer was created. This allows executing a command when a specific system event occurs. A favorite persistence mechanism for APTs.",
    "response_steps": [
      "1. COMMAND: Identify the command being executed by the consumer.",
      "2. TRIGGER: Check the associated Filter to see WHEN it runs (Startup, Logon, Timer).",
      "3. CLEAN: Remove the Consumer, Filter, and Binding using PowerShell."
    ]
  },
  {
    "id": "WMI_201_CMD_CONSUMER_RAW",
    "title": "WMI CommandLine Consumer Created (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Type": "*CommandLineEventConsumer*"
      }
    },
    "description": "Raw WMI Event (ID 20) detection for CommandLineEventConsumer creation.",
    "response_steps": [
      "1. COMMAND: Review 'CommandLineTemplate' in the raw event data.",
      "2. REMOVE: Use 'Get-WmiObject' to find and delete the malicious consumer."
    ]
  },
  {
    "id": "WMI_202_SCRIPT_CONSUMER",
    "title": "WMI ActiveScript Consumer Created",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.destination": "*ActiveScriptEventConsumer*"
      }
    },
    "description": "A WMI ActiveScriptEventConsumer was created. This executes embedded VBScript or JScript from the WMI repository (Fileless persistence).",
    "response_steps": [
      "1. EXTRACT: The script payload is stored inside the WMI object. Extract it for analysis.",
      "2. REPO: The payload resides in Objects.data, not as a standard file.",
      "3. CLEAN: Remove the WMI object."
    ]
  },
  {
    "id": "WMI_202_SCRIPT_CONSUMER_RAW",
    "title": "WMI ActiveScript Consumer Created (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Type": "*ActiveScriptEventConsumer*"
      }
    },
    "description": "Raw WMI Event (ID 20) detection for ActiveScriptEventConsumer creation.",
    "response_steps": [
      "1. PAYLOAD: Look at the 'ScriptText' field in the event log.",
      "2. DEOBFUSCATE: The script is likely obfuscated VBS/JS."
    ]
  },
  {
    "id": "WMI_203_BINDING",
    "title": "WMI Filter to Consumer Binding",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.operation": "*FilterToConsumerBinding*"
      }
    },
    "description": "A WMI Binding was created. This links a Trigger (Filter) to an Action (Consumer), completing the persistence chain.",
    "response_steps": [
      "1. LINK: Identify which Filter is linked to which Consumer.",
      "2. COMPLETE: You must delete the Binding to break the chain, then delete the components."
    ]
  },
  {
    "id": "WMI_203_BINDING_RAW",
    "title": "WMI Filter to Consumer Binding (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "21",
        "raw.Consumer": "*",
        "raw.Filter": "*"
      }
    },
    "description": "Raw WMI Event (ID 21) detection for Binding creation.",
    "response_steps": [
      "1. IDENTIFY: The event lists the paths to the Consumer and Filter.",
      "2. FOLLOW: Investigate both objects referenced."
    ]
  },
  {
    "id": "WMI_204_POWERSHELL_CONSUMER",
    "title": "WMI Consumer Executing PowerShell",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.command_line": ["*powershell*", "*pwsh*"]
      }
    },
    "description": "A WMI Consumer is configured to execute PowerShell. This is a very common method for fileless malware to bootstrap itself.",
    "response_steps": [
      "1. DECODE: Check for Base64 encoded payloads in the command line.",
      "2. SOURCE: Is it downloading content or running a script block?"
    ]
  },
  {
    "id": "WMI_204_POWERSHELL_CONSUMER_RAW",
    "title": "WMI Consumer Executing PowerShell (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Destination": ["*powershell*", "*pwsh*"]
      }
    },
    "description": "Raw WMI detection of PowerShell execution via WMI Consumer.",
    "response_steps": [
      "1. ANALYZE: Review the command line arguments.",
      "2. REMOVE: Delete the malicious consumer."
    ]
  },
  {
    "id": "WMI_205_CMD_CONSUMER_EXEC",
    "title": "WMI Consumer Executing CMD",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.command_line": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    },
    "description": "A WMI Consumer is configured to execute Command Prompt commands.",
    "response_steps": [
      "1. COMMAND: What is being executed? (e.g., net user add, reg add).",
      "2. CONTEXT: Is this legitimate admin maintenance or malicious?"
    ]
  },
  {
    "id": "WMI_205_CMD_CONSUMER_EXEC_RAW",
    "title": "WMI Consumer Executing CMD (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Destination": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    },
    "description": "Raw WMI detection of CMD execution via WMI Consumer.",
    "response_steps": [
      "1. REVIEW: Check the CommandLineTemplate.",
      "2. ACTION: Determine if the command is destructive or establishing persistence."
    ]
  },
  {
    "id": "WMI_206_VBS_CONSUMER",
    "title": "WMI Consumer Executing VBS/JS",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.script_text": ["*vbscript*", "*JScript*"]
      }
    },
    "description": "A WMI Consumer containing VBScript or JScript code was found.",
    "response_steps": [
      "1. EXTRACT: Get the full script text.",
      "2. ANALYZE: Look for obfuscation or downloaders."
    ]
  },
  {
    "id": "WMI_206_VBS_CONSUMER_RAW",
    "title": "WMI Consumer Executing VBS/JS (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.ScriptText": ["*vbscript*", "*JScript*", "*jscript*"]
      }
    },
    "description": "Raw detection of VBS/JS code inside a WMI Consumer.",
    "response_steps": [
      "1. INVESTIGATE: This is likely a 'fileless' malware stager.",
      "2. CLEAN: Remove the WMI object."
    ]
  },
  {
    "id": "WMI_207_SCRCONS_SPAWN",
    "title": "Scrcons.exe Spawning Process",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*scrcons.exe",
        "process.image": ["*cmd.exe", "*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Scrcons.exe (WMI Standard Event Consumer) spawned a shell. This happens when an ActiveScriptEventConsumer executes a script that launches a process.",
    "response_steps": [
      "1. TRACE: The parent is WMI. You must find the WMI Consumer that caused this.",
      "2. KILL: Terminate the child process."
    ]
  },
  {
    "id": "WMI_208_WMI_PRVSE_SPAWN",
    "title": "Wmiprvse.exe Spawning PowerShell",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.parent_image": "*wmiprvse.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Wmiprvse.exe (WMI Provider Host) spawned PowerShell. This usually indicates lateral movement via WMI (Impacket/WmiExec) or a malicious WMI Provider.",
    "response_steps": [
      "1. COMMAND: Check the command line of the PowerShell process.",
      "2. LATERAL: If it's encoded, it's likely a remote execution attempt."
    ]
  },
  {
    "id": "WMI_209_KRYPTON_WMI",
    "title": "Krypton/Empire WMI Persistence",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.name": "*Updater*",
        "wmi.query": "*SELECT * FROM __InstanceModificationEvent*"
      }
    },
    "description": "Detects specific WMI persistence patterns used by Empire and Krypton (e.g., naming consumers 'Updater' and using InstanceModification triggers).",
    "response_steps": [
      "1. CONFIRM: This is a high-fidelity indicator for specific malware families.",
      "2. REMOVE: Targeted cleanup of the 'Updater' consumer."
    ]
  },
  {
    "id": "WMI_209_KRYPTON_WMI_RAW",
    "title": "Krypton/Empire WMI Persistence (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "19",
        "raw.Name": "*Updater*",
        "raw.Query": "*SELECT * FROM __InstanceModificationEvent*"
      }
    },
    "description": "Raw event detection for Empire/Krypton WMI persistence signatures.",
    "response_steps": [
      "1. ISOLATE: Known malware signature.",
      "2. SCAN: Run full AV scan."
    ]
  },
  {
    "id": "WMI_210_IMPACKET_WMI",
    "title": "Impacket WMI Exec",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.parent_image": "*wmiprvse.exe",
        "process.command_line": ["*cmd.exe /Q /c *", "*cmd.exe /c *"]
      }
    },
    "description": "Detects Impacket's wmiexec.py. It executes commands via WMI by spawning 'cmd.exe /Q /c <command>' and redirecting output to a file.",
    "response_steps": [
      "1. SOURCE: Identify the source IP (requires Network logs or correlating 4624 events).",
      "2. COMMAND: What did they run?",
      "3. FILES: Impacket often writes output to \\Admin$\\temp\\...",
    ]
  },

  {
    "id": "ACC_211_USER_CREATED",
    "title": "Local User Account Created",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720"
      }
    },
    "description": "A local user account was created. While normal for admins, attackers create backdoor accounts to maintain access.",
    "response_steps": [
      "1. WHO: Who created the account? (SubjectUserName)",
      "2. WHAT: What is the new account name? (TargetUserName)",
      "3. VERIFY: Confirm with the admin if this was authorized."
    ]
  },
  {
    "id": "ACC_212_ADMIN_GROUP_ADD",
    "title": "User Added to Local Administrators",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4732", "4728"],
        "group.name": ["*Administrators*", "*Administradores*"]
      }
    },
    "description": "A user was added to the local Administrators group. This grants full control over the machine.",
    "response_steps": [
      "1. TARGET: Which account was promoted?",
      "2. AUTHOR: Who performed the addition?",
      "3. REVERT: Remove the user if unauthorized."
    ]
  },
  {
    "id": "ACC_212_ADMIN_GROUP_ADD_RAW",
    "title": "User Added to Local Administrators (Raw)",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4732", "4728"],
        "raw.GroupName": ["*Administrators*", "*Administradores*", "*Domain Admins*", "*Admins*", "*Administradores del dominio*"]
      }
    },
    "description": "Raw detection of user addition to administrative groups.",
    "response_steps": [
      "1. VERIFY: Check the group name in the raw event.",
      "2. ALERT: Unplanned admin additions are a critical security incident."
    ]
  },
  {
    "id": "ACC_213_USER_ENABLED",
    "title": "User Account Enabled",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4722"
      }
    },
    "description": "A disabled user account was enabled. Attackers often re-enable built-in Guest or Administrator accounts.",
    "response_steps": [
      "1. ACCOUNT: Which account was enabled?",
      "2. CONTEXT: Was it the 'Guest' account? (High risk)."
    ]
  },
  {
    "id": "ACC_214_PWD_RESET",
    "title": "Password Reset Attempt",
    "severity": "MEDIUM",
    "module": "CRED",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4724",
      }
    },
    "description": "An attempt was made to reset an account's password by an administrator.",
    "response_steps": [
      "1. SOURCE: Who reset the password?",
      "2. TARGET: Whose password was reset?",
      "3. INTENT: Is this an attacker locking out a user or hijacking an account?"
    ]
  },
  {
    "id": "ACC_215_USER_DELETED",
    "title": "User Account Deleted",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1070"],
    "detection": {
      "selection": {
        "event_id": "4726",
      }
    },
    "description": "A user account was deleted. Attackers delete their backdoor accounts after use to hide tracks.",
    "response_steps": [
      "1. ACCOUNT: Which account was deleted?",
      "2. DURATION: How long did the account exist? (Short lifetime = suspicious)."
    ]
  },
  {
    "id": "ACC_216_GUEST_ENABLED",
    "title": "Guest Account Enabled",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1078"],
    "detection": {
      "selection": {
        "event_id": "4722",
        "user.target_name": ["*Guest*", "*Invitado*"]
      }
    },
    "description": "The built-in Guest account was enabled. This is a severe security misconfiguration often exploited for anonymous access.",
    "response_steps": [
      "1. DISABLE: Disable the Guest account immediately.",
      "2. INVESTIGATE: Check for logon events (4624) using the Guest account."
    ]
  },
  {
    "id": "ACC_216_GUEST_ENABLED_RAW",
    "title": "Guest Account Enabled (Raw)",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1078"],
    "detection": {
      "selection": {
        "event_id": "4722",
        "raw.TargetUserName": ["*Guest*", "*Invitado*"]
      }
    },
    "description": "Raw detection of Guest account enabling.",
    "response_steps": [
      "1. POLICY: Ensure GPO enforces Guest account disabled.",
      "2. CHECK: Who enabled it?"
    ]
  },
  {
    "id": "ACC_217_SUPPORT_USER",
    "title": "Suspicious 'Support' User Created",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "user.target_name": ["*Support*", "*HelpDesk*", "*Admin*", "*Kiosk*"]
      }
    },
    "description": "Creation of a user with a generic name like 'Support' or 'Admin'. Attackers use these to blend in with legitimate accounts.",
    "response_steps": [
      "1. VERIFY: Is there an open ticket requiring a new support account?",
      "2. VALIDATE: Does the account follow standard naming conventions (e.g., adm-username)?"
    ]
  },
  {
    "id": "ACC_217_SUPPORT_USER_RAW",
    "title": "Suspicious 'Support' User Created (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "raw.TargetUserName": ["*Support*", "*HelpDesk*", "*Admin*", "*Kiosk*"]
      }
    },
    "description": "Raw detection of suspicious username creation.",
    "response_steps": [
      "1. MONITOR: Watch activity of this new account closely.",
      "2. DISABLE: If unverified, disable immediately."
    ]
  },
  {
    "id": "ACC_218_HIDDEN_USER",
    "title": "Hidden/Suspicious User Created ($)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "user.target_name": "*$*"
      }
    },
    "description": "Creation of a user account ending with '$'. This mimics machine accounts to hide from 'net user' listings (which filter out accounts with $).",
    "response_steps": [
      "1. ALERT: This is almost certainly malicious intent.",
      "2. DELETE: Remove the account.",
      "3. CHECK: Check if it was added to Domain Admins."
    ]
  },
  {
    "id": "ACC_218_HIDDEN_USER_RAW",
    "title": "Hidden/Suspicious User Created ($) (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "raw.TargetUserName": "*$*"
      }
    },
    "description": "Raw detection of hidden '$' user creation.",
    "response_steps": [
      "1. CONFIRM: Verify it's not a legitimate machine join (which uses 4741, not 4720).",
      "2. PURGE: Remove the backdoor."
    ]
  },
  {
    "id": "ACC_219_SEC_GROUP_MOD",
    "title": "Security-Enabled Group Modification",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4735", "4737"],
      }
    },
    "description": "A security-enabled local group was changed (Type, Scope, or Attributes).",
    "response_steps": [
      "1. DETAILS: Review the event to see what attribute changed.",
      "2. SCOPE: Attackers may weaken group security settings."
    ]
  },
  {
    "id": "ACC_220_DOMAIN_ADMIN_ADD",
    "title": "Added to Domain Admins",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4728",
        "group.name": "*Domain Admins*"
      }
    },
    "description": "A user was added to the 'Domain Admins' global group. This is the 'Keys to the Kingdom' event.",
    "response_steps": [
      "1. PANIC: Unless this is a scheduled change record, assume the Domain is compromised.",
      "2. REMOVE: Remove the user immediately.",
      "3. RESET: Reset the KRBTGT password (Golden Ticket protection)."
    ]
  },
  {
    "id": "ACC_220_DOMAIN_ADMIN_ADD_RAW",
    "title": "Added to Domain Admins (Raw)",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4728",
        "raw.GroupName": "*Domain Admins*"
      }
    },
    "description": "Raw detection of Domain Admin group addition.",
    "response_steps": [
      "1. VERIFY: Confirm the group name in the raw event log.",
      "2. RESPONSE: Activate Incident Response plan for Domain Compromise."
    ]
  },

  {
    "id": "PIPE_221_PSEXEC",
    "title": "PsExec Named Pipe",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": ["*PSEXESVC*", "*PaExec*"]
      }
    },
    "description": "Named Pipe 'PSEXESVC' detected. Indicates PsExec usage for lateral movement/execution.",
    "response_steps": [
      "1. SOURCE: Identify where the connection came from.",
      "2. AUTHORIZED: Is this IT support or an attacker?",
      "3. BLOCK: Ensure SMB/RPC is restricted between workstations."
    ]
  },
  {
    "id": "PIPE_221_PSEXEC_RAW",
    "title": "PsExec Named Pipe (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": ["*PSEXESVC*", "*PaExec*"]
      }
    },
    "description": "Raw detection of PsExec named pipe.",
    "response_steps": [
      "1. MONITOR: Watch for service creation events (4697/7045) which typically follow PsExec."
    ]
  },
  {
    "id": "PIPE_222_COBALT_MOJO",
    "title": "Cobalt Strike Mojo Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*mojo.5688.8052.*"
      }
    },
    "description": "Specific Named Pipe pattern associated with Cobalt Strike (Mojo).",
    "response_steps": [
      "1. ISOLATE: High-confidence C2 indicator.",
      "2. PROCESS: Identify the process hosting this pipe."
    ]
  },
  {
    "id": "PIPE_222_COBALT_MOJO_RAW",
    "title": "Cobalt Strike Mojo Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*mojo.5688.8052.*"
      }
    },
    "description": "Raw detection of Cobalt Strike Mojo pipe.",
    "response_steps": [
      "1. CONFIRM: Check against known Threat Intel feeds.",
      "2. TERMINATE: Kill the process tree."
    ]
  },
  {
    "id": "PIPE_223_COBALT_POSTEX",
    "title": "Cobalt Strike PostEx Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*postex_*"
      }
    },
    "description": "Named Pipe 'postex_' detected. Default pattern for Cobalt Strike Post-Exploitation jobs.",
    "response_steps": [
      "1. ISOLATE: Active post-exploitation in progress.",
      "2. MEMORY: The payload is likely running in memory."
    ]
  },
  {
    "id": "PIPE_223_COBALT_POSTEX_RAW",
    "title": "Cobalt Strike PostEx Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*postex_*"
      }
    },
    "description": "Raw detection of Cobalt Strike PostEx pipe.",
    "response_steps": [
      "1. SCAN: Run full forensic triage on this host.",
      "2. BLOCK: Sever network connectivity."
    ]
  },
  {
    "id": "PIPE_224_COBALT_MSAGENT",
    "title": "Cobalt Strike MSAgent Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*msagent_*"
      }
    },
    "description": "Named Pipe 'msagent_' detected. Another default Cobalt Strike pattern.",
    "response_steps": [
      "1. ISOLATE: C2 activity confirmed.",
      "2. INVESTIGATE: Look for SSH/SMB beacons linked to this."
    ]
  },
  {
    "id": "PIPE_224_COBALT_MSAGENT_RAW",
    "title": "Cobalt Strike MSAgent Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*msagent_*"
      }
    },
    "description": "Raw detection of Cobalt Strike MSAgent pipe.",
    "response_steps": [
      "1. REMEDIATE: Re-image the host.",
      "2. CREDENTIALS: Reset passwords for any user active on this box."
    ]
  },
  {
    "id": "PIPE_225_SMB_LATERAL",
    "title": "SMB Lateral Movement Pipe",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1021.002"],
    "detection": {
      "selection": {
        "pipe.name": ["*atsvc*", "*samr*", "*srvsvc*"]
      }
    },
    "description": "Access to administrative pipes (atsvc, samr, srvsvc). Often used for reconnaissance (SAMR) or execution (ATSVC/Scheduled Tasks).",
    "response_steps": [
      "1. CONTEXT: Is this expected administrative activity?",
      "2. PATTERN: Is it happening rapidly across many hosts?"
    ]
  },
  {
    "id": "PIPE_225_SMB_LATERAL_RAW",
    "title": "SMB Lateral Movement Pipe (Raw)",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1021.002"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": ["*atsvc*", "*samr*", "*srvsvc*"]
      }
    },
    "description": "Raw detection of SMB administrative pipes.",
    "response_steps": [
      "1. LOGS: check 4624 events to identify the source user/IP.",
      "2. MONITOR: Watch for subsequent process creation."
    ]
  },
  {
    "id": "PIPE_226_BITS_PIPE",
    "title": "BITS Service Pipe Abuse",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "pipe.name": "*BITSServer*"
      }
    },
    "description": "Named Pipe 'BITSServer'. May indicate BITS usage for lateral movement or persistence interaction.",
    "response_steps": [
      "1. CHECK: Is BITS being used to transfer malicious files?",
      "2. INSPECT: 'bitsadmin /list /allusers'."
    ]
  },
  {
    "id": "PIPE_226_BITS_PIPE_RAW",
    "title": "BITS Service Pipe Abuse (Raw)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*BITSServer*"
      }
    },
    "description": "Raw detection of BITS pipe usage.",
    "response_steps": [
      "1. VERIFY: Correlate with BITS client event logs."
    ]
  },
  {
    "id": "PIPE_228_WIEU_PIPE",
    "title": "WIEU Remote Exec Pipe",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1021"],
    "detection": {
      "selection": {
        "pipe.name": "*wieu_*"
      }
    },
    "description": "Suspicious pipe pattern 'wieu_'. Often associated with remote execution tools.",
    "response_steps": [
      "1. IDENTIFY: Process owner of the pipe.",
      "2. TERMINATE: If unknown, kill the process."
    ]
  },
  {
    "id": "PIPE_228_WIEU_PIPE_RAW",
    "title": "WIEU Remote Exec Pipe (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1021"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*wieu_*"
      }
    },
    "description": "Raw detection of 'wieu_' pipe.",
    "response_steps": [
      "1. INVESTIGATE: Determine the tool creating this pipe."
    ]
  },
  {
    "id": "PIPE_229_STATUS_PIPE",
    "title": "Status Pipe (CS Pattern)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*status_*"
      }
    },
    "description": "Pipe pattern 'status_'. Can be a default Cobalt Strike artifact.",
    "response_steps": [
      "1. CONTEXT: Check if this matches a CS profile.",
      "2. ISOLATE: Treat as potential C2."
    ]
  },
  {
    "id": "PIPE_229_STATUS_PIPE_RAW",
    "title": "Status Pipe (CS Pattern) (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*status_*"
      }
    },
    "description": "Raw detection of 'status_' pipe.",
    "response_steps": [
      "1. MONITOR: Look for other CS indicators (beaconing, process injection)."
    ]
  },
  {
    "id": "PIPE_230_DHELPER_PIPE",
    "title": "DHelper Pipe (Malware)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*dhelper_*"
      }
    },
    "description": "Known malicious pipe 'dhelper_'. Associated with specific malware families (e.g., Duqu/Stuxnet era or similar APTs).",
    "response_steps": [
      "1. ISOLATE: Confirmed APT indicator.",
      "2. ESCALATE: Notify security team immediately."
    ]
  },
  {
    "id": "PIPE_230_DHELPER_PIPE_RAW",
    "title": "DHelper Pipe (Malware) (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*dhelper_*"
      }
    },
    "description": "Raw detection of 'dhelper_' pipe.",
    "response_steps": [
      "1. FORENSICS: Full analysis required."
    ]
  },

  {
    "id": "MASQ_231_SVCHOST",
    "title": "Masquerading Svchost.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**svchost.exe",
          "!**Windows*System32*svchost.exe",
          "!**Windows*SysWOW64*svchost.exe",
          "!**System32*svchost.exe",
          "!**SysWOW64*svchost.exe"
        ]
      }
    },
    "description": "Svchost.exe executing from a non-standard location. Legitimate svchost.exe ONLY runs from System32 or SysWOW64.",
    "response_steps": [
      "1. KILL: This is fake. Terminate it.",
      "2. PATH: Check where it is running from (Temp, Users, etc.).",
      "3. HASH: Compare hash to legitimate svchost."
    ]
  },
  {
    "id": "MASQ_232_EXPLORER",
    "title": "Masquerading Explorer.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**explorer.exe",
          "!**Windows*explorer.exe",
          "!**Windows*SysWOW64*explorer.exe"
        ]
      }
    },
    "description": "Explorer.exe executing from a non-standard location. It should reside in C:\\Windows.",
    "response_steps": [
      "1. VERIFY: Is it running from System32 or a user folder?",
      "2. CLEAN: Remove the fake binary."
    ]
  },
  {
    "id": "MASQ_233_CSRSS",
    "title": "Masquerading Csrss.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**csrss.exe",
          "!**Windows*System32*csrss.exe",
          "!**Windows*SysWOW64*csrss.exe",
          "!**System32*csrss.exe",
          "!**SysWOW64*csrss.exe"
        ]
      }
    },
    "description": "Csrss.exe running from outside System32. This is a critical system process often spoofed by malware to hide.",
    "response_steps": [
      "1. ISOLATE: High confidence malware.",
      "2. PARENT: Who spawned this fake process?"
    ]
  },
  {
    "id": "MASQ_234_LSASS",
    "title": "Masquerading Lsass.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**lsass.exe",
          "!**Windows*System32*lsass.exe",
          "!**Windows*SysWOW64*lsass.exe",
          "!**System32*lsass.exe",
          "!**SysWOW64*lsass.exe"
        ]
      }
    },
    "description": "Lsass.exe running from outside System32. Attackers spoof LSASS to blend in or steal credentials.",
    "response_steps": [
      "1. KILL: Terminate immediatey.",
      "2. SCAN: Scan for Credential Dumpers."
    ]
  },
  {
    "id": "MASQ_235_WININIT",
    "title": "Masquerading Wininit.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**wininit.exe",
          "!**Windows*System32*wininit.exe",
          "!**Windows*SysWOW64*wininit.exe",
          "!**System32*wininit.exe",
          "!**SysWOW64*wininit.exe"
        ]
      }
    },
    "description": "Wininit.exe running from outside System32. It should only run once at boot.",
    "response_steps": [
      "1. CHECK: Is there more than one wininit.exe? (There should be only one).",
      "2. REMOVE: Delete the impostor."
    ]
  },
  {
    "id": "MASQ_236_SERVICES",
    "title": "Masquerading Services.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**services.exe",
          "!**Windows*System32*services.exe",
          "!**Windows*SysWOW64*services.exe",
          "!**System32*services.exe",
          "!**SysWOW64*services.exe"
        ]
      }
    },
    "description": "Services.exe running from outside System32.",
    "response_steps": [
      "1. ISOLATE: Fake system process detected.",
      "2. ANALYZE: Retrieve sample for RE."
    ]
  },
  {
    "id": "MASQ_237_TASKHOST",
    "title": "Masquerading Taskhost.exe",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**taskhost.exe",
          "!**Windows*System32*taskhost.exe",
          "!**Windows*SysWOW64*taskhost.exe",
          "!**System32*taskhost.exe",
          "!**SysWOW64*taskhost.exe"
        ]
      }
    },
    "description": "Taskhost.exe running from outside System32. Common for coin miners.",
    "response_steps": [
      "1. CPU: Check CPU usage. Is it mining?",
      "2. KILL: Terminate process."
    ]
  },
  {
    "id": "MASQ_238_SMSS",
    "title": "Masquerading Smss.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**smss.exe",
          "!**Windows*System32*smss.exe",
          "!**System32*smss.exe"
        ]
      }
    },
    "description": "Smss.exe running from outside System32. Session Manager should be unique and protected.",
    "response_steps": [
      "1. ISOLATE: Critical system process spoofing.",
      "2. CHECK: Only one instance (PID) usually exists (Session 0)."
    ]
  },
  {
    "id": "MASQ_239_DOUBLE_EXT",
    "title": "Double Extension Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036.007"],
    "detection": {
      "selection": {
        "process.image": [
          "*.pdf.exe",
          "*.doc.exe",
          "*.docx.exe",
          "*.xls.exe",
          "*.xlsx.exe",
          "*.ppt.exe",
          "*.pptx.exe",
          "*.txt.exe",
          "*.rtf.exe",
          "*.jpg.exe",
          "*.png.exe",
          "*.zip.exe"
        ]
      }
    },
    "description": "Execution of a file with a double extension (e.g., invoice.pdf.exe). Default Windows settings hide the last extension, tricking users into clicking.",
    "response_steps": [
      "1. USER: Did a user download this from email?",
      "2. TYPE: It's an executable, not a document.",
      "3. DELETE: Remove the file."
    ]
  },
  {
    "id": "MASQ_240_FAKE_SYSTEM_DIR",
    "title": "Execution from Fake System Directory",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": [
          "**Windows*System32 **",
          "**Windows*System32.*",
          "**Windows*SysWOW64 **",
          "**Windows*SysWOW64.*"
        ]
      }
    },
    "description": "Execution from a directory trying to look like System32 (e.g., with a trailing space). 'System32 ' != 'System32'.",
    "response_steps": [
      "1. PATH: Check the exact path character by character.",
      "2. REMOVE: Delete the fake directory."
    ]
  },

  {
    "id": "DEST_241_LOG_CLEAR_SEC",
    "title": "Security Log Cleared",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
                  "event_id": "1102"      }
    },
    "description": "The Security Event Log was cleared. This is a major Anti-Forensics indicator. Attackers do this to hide their tracks.",
    "response_steps": [
      "1. ALERT: Immediate incident response.",
      "2. RECOVER: Check if logs are forwarded to a SIEM (you can't clear remote logs).",
      "3. USER: Who cleared it? (The event 1102 itself records the user)."
    ]
  },
  {
    "id": "DEST_242_LOG_CLEAR_SYS",
    "title": "System Log Cleared",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
        "event_id": "104",
      }
    },
    "description": "The System Event Log was cleared.",
    "response_steps": [
      "1. CONTEXT: Was this maintenance?",
      "2. ALERT: If not maintenance, assume compromise."
    ]
  },
  {
    "id": "DEST_243_DEFENDER_DISABLE",
    "title": "Windows Defender Disabled",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": [
          "*Set-MpPreference*DisableRealtimeMonitoring*",
          "*DisableRealtimeMonitoring $true*",
          "*DisableRealtimeMonitoring true*",
          "*DisableRealtimeMonitoring 1*"
        ]
      }
    },
    "description": "Windows Defender Real-time Monitoring was disabled via PowerShell. Attackers do this immediately before dropping their main payload.",
    "response_steps": [
      "1. ENABLE: Re-enable Defender immediately.",
      "2. SCAN: Run a full scan.",
      "3. ISOLATE: The host is undefended and likely infected."
    ]
  },
  {
    "id": "DEST_244_DEFENDER_EXCLUSION",
    "title": "Windows Defender Exclusion Added",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*Add-MpPreference*", "*ExclusionPath*", "*ExclusionExtension*", "*ExclusionProcess*"]
      }
    },
    "description": "An exclusion was added to Windows Defender. Malware adds its own folder or extension to the exclusion list to avoid detection.",
    "response_steps": [
      "1. CHECK: What path/extension was excluded?",
      "2. INSPECT: Look in that path for malware.",
      "3. REMOVE: Remove the exclusion."
    ]
  },
  {
    "id": "DEST_245_STOP_DEFENDER",
    "title": "Stopping Security Services",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.command_line": ["* stop WinDefend*", "* stop SepMasterService*", "*sc stop WinDefend*", "*net stop WinDefend*"]
      }
    },
    "description": "Attempts to stop security services (Defender, Symantec, etc.) via command line.",
    "response_steps": [
      "1. BLOCK: These commands should be blocked by EDR/protection.",
      "2. ALERT: Active attempt to blind security."
    ]
  },
  {
    "id": "DEST_246_DELETE_BACKUP",
    "title": "Delete Backup Catalog (WBAdmin)",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*wbadmin*delete catalog*", "*wbadmin*delete systemstatebackup*"]
      }
    },
    "description": "Deletion of Windows Backup Catalog using wbadmin. Common ransomware behavior to prevent recovery.",
    "response_steps": [
      "1. ISOLATE: Ransomware precursor.",
      "2. CHECK: Are shadow copies also deleted?"
    ]
  },
  {
    "id": "DEST_247_RESIZE_SHADOW",
    "title": "Resizing Shadow Copies (Ransomware)",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*vssadmin*Resize ShadowStorage*"]
      }
    },
    "description": "Resizing Shadow Copy storage to a minimal size. This forces Windows to delete old shadow copies to make space, effectively wiping backups without using 'delete'.",
    "response_steps": [
      "1. ISOLATE: Ransomware tactic.",
      "2. PROTECT: Backup critical data immediately if not already encrypted."
    ]
  },
  {
    "id": "DEST_248_BOOT_RECOVERY",
    "title": "Disabling Boot Recovery",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*recoveryenabled No*"]
      }
    },
    "description": "Disabling Windows Recovery via BCDEdit. Prevents the user from booting into recovery mode to fix the system.",
    "response_steps": [
      "1. CHECK: Verify BCD settings.",
      "2. RESTORE: Enable recovery."
    ]
  },
  {
    "id": "DEST_249_FILE_DELETION",
    "title": "Mass File Deletion (Cmd)",
    "severity": "MEDIUM",
    "module": "IMPACT",
    "mitre": ["T1485"],
    "detection": {
      "selection": {
        "process.command_line": ["*del /f /s /q*", "*rmdir /s /q*"]
      }
    },
    "description": "Silent mass file deletion command. Could be a cleanup script or a Wiper malware.",
    "response_steps": [
      "1. TARGET: Which directory is being wiped?",
      "2. CONTEXT: Is this a temp folder (OK) or Documents (Bad)?"
    ]
  },
  {
    "id": "DEST_250_SAFE_MODE_BOOT",
    "title": "Force Safe Mode Boot (Ransomware)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.009"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*safeboot minimal*"]
      }
    },
    "description": "Forcing the machine to boot into Safe Mode. Ransomware does this because many AV/EDR solutions do not run in Safe Mode, allowing encryption to proceed unhindered.",
    "response_steps": [
      "1. ISOLATE: High risk of imminent encryption.",
      "2. REVERT: Remove the safeboot flag from BCD."
    ]
  }
];