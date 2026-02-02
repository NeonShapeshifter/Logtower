import { Rule } from '@neonshapeshifter/logtower-engine';

export const SCHEDULED_TASKS_RULES: Rule[] = [
  { 
    "id": "TSK_761_SCHTASKS_CREATE_XML", 
    "title": "Schtasks Create from XML", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": ["*/create*", "*/xml*"] } } 
  },
  { 
    "id": "TSK_762_SCHTASKS_SYSTEM_PATH", 
    "title": "Schtasks Masquerading System Path", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tn*", "*\\Microsoft\\Windows*"] } }
  },
  { 
    "id": "TSK_763_SCHTASKS_CHANGE", 
    "title": "Schtasks Modify Task", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": ["*/change*", "*/tr*"] } } 
  },
  { 
    "id": "TSK_764_SCHTASKS_RUN", 
    "title": "Schtasks Run Immediately", 
    "severity": "LOW", 
    "module": "EXECUTION", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.image": "*schtasks.exe", "process.command_line": "*/run*" } } 
  },
  { 
    "id": "TSK_765_SCHTASKS_ONLOGON", 
    "title": "Schtasks OnLogon Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onlogon*"] } } 
  },
  { 
    "id": "TSK_766_SCHTASKS_ONSTART", 
    "title": "Schtasks OnStart Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onstart*"] } } 
  },
  { 
    "id": "TSK_767_SCHTASKS_ONIDLE", 
    "title": "Schtasks OnIdle Trigger", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc onidle*"] } } 
  },
  { 
    "id": "TSK_768_SCHTASKS_MINUTE", 
    "title": "Schtasks Minute Trigger (Beacon)", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/sc minute*"] } } 
  },
  { 
    "id": "TSK_769_SCHTASKS_SYSTEM_USER", 
    "title": "Schtasks Run as SYSTEM", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/ru SYSTEM*"] } } 
  },
  { 
    "id": "TSK_770_AT_EXEC", 
    "title": "At.exe Scheduled Task", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.002"],
    "detection": { "selection": { "process.image": "*at.exe" } } 
  },
  { 
    "id": "TSK_771_PS_NEW_TASK", 
    "title": "PowerShell New-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*New-ScheduledTask*" } } 
  },
  { 
    "id": "TSK_772_PS_REGISTER_TASK", 
    "title": "PowerShell Register-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*Register-ScheduledTask*" } } 
  },
  { 
    "id": "TSK_773_PS_SET_TASK", 
    "title": "PowerShell Set-ScheduledTask", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*Set-ScheduledTask*" } } 
  },
  { 
    "id": "TSK_774_TASK_TEMP_EXEC", 
    "title": "Task Executing from Temp", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*\\Temp*"] } }
  },
  { 
    "id": "TSK_775_TASK_PUBLIC_EXEC", 
    "title": "Task Executing from Public", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*\\Users\\Public*"] } }
  },
  { 
    "id": "TSK_776_TASK_POWERSHELL", 
    "title": "Task Executing PowerShell", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*powershell*"] } } 
  },
  { 
    "id": "TSK_777_TASK_CMD", 
    "title": "Task Executing CMD", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*cmd.exe*"] } } 
  },
  { 
    "id": "TSK_778_TASK_RUNDLL", 
    "title": "Task Executing Rundll32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*rundll32*"] } } 
  },
  { 
    "id": "TSK_779_TASK_REGSVR", 
    "title": "Task Executing Regsvr32", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*regsvr32*"] } } 
  },
  { 
    "id": "TSK_780_TASK_MSHTA", 
    "title": "Task Executing Mshta", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*mshta*"] } } 
  },
  { 
    "id": "TSK_781_TASK_WSCRIPT", 
    "title": "Task Executing WScript", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*wscript*"] } } 
  },
  { 
    "id": "TSK_782_TASK_CSCRIPT", 
    "title": "Task Executing CScript", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*cscript*"] } } 
  },
  { 
    "id": "TSK_783_TASK_ENCODED", 
    "title": "Task with Encoded Command", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*-enc*"] } } 
  },
  { 
    "id": "TSK_784_TASK_HIDDEN_ATTR", 
    "title": "Task Created Hidden", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*Hidden*"] } } 
  },
  { 
    "id": "TSK_785_TASK_COMPAT", 
    "title": "Task Compatibility Mode", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*Compatibility*"] } } 
  },
  { 
    "id": "TSK_786_TASK_WAKE", 
    "title": "Task Wake To Run", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*WakeToRun*"] } } 
  },
  { 
    "id": "TSK_787_TASK_ALLOW_START", 
    "title": "Task Allow Start If On Batteries", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*New-ScheduledTaskSettingsSet*", "*AllowStartIfOnBatteries*"] } } 
  },
  { 
    "id": "TSK_788_TASK_EXEC_BYPASS", 
    "title": "Task Execution Policy Bypass", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*Bypass*"] } } 
  },
  { 
    "id": "TSK_789_TASK_WINDOW_HIDDEN", 
    "title": "Task Window Style Hidden", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*Hidden*"] } } 
  },
  { 
    "id": "TSK_790_TASK_NOPROFILE", 
    "title": "Task NoProfile", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*NoProfile*"] } } 
  },
  { 
    "id": "TSK_791_TASK_NONINTERACTIVE", 
    "title": "Task NonInteractive", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr*", "*NonInteractive*"] } } 
  },
  { 
    "id": "TSK_792_TASK_DELETE", 
    "title": "Schtasks Delete Task", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1070"],
    "detection": { "selection": { "process.command_line": ["*/delete*", "*/tn*"] } } 
  },
  { 
    "id": "TSK_793_TASK_QUERY", 
    "title": "Schtasks Query Task", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/query*" } } 
  },
  { 
    "id": "TSK_794_TASK_FOLDER_CREATE", 
    "title": "Schtasks Create Folder", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/xml*", "*/tn **"] } }
  },
  { 
    "id": "TSK_795_TASK_END", 
    "title": "Schtasks End Task", 
    "severity": "LOW", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/end*" } } 
  },
  { 
    "id": "TSK_796_TASK_SHOW_SID", 
    "title": "Schtasks Show SID", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/showsid*" } } 
  },
  { 
    "id": "TSK_797_TASK_DISABLE", 
    "title": "Schtasks Disable Task", 
    "severity": "MEDIUM", 
    "module": "IMPACT", 
    "mitre": ["T1489"],
    "detection": { "selection": { "process.command_line": "*/disable*" } } 
  },
  { 
    "id": "TSK_798_TASK_ENABLE", 
    "title": "Schtasks Enable Task", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": "*/enable*" } } 
  },
  { 
    "id": "TSK_799_TASK_PARAMS", 
    "title": "Schtasks With Parameters", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/tr * * *"] } } 
  },
  { 
    "id": "TSK_800_TASK_DELAY", 
    "title": "Schtasks Delay Modifier", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/delay*"] } } 
  },
  { 
    "id": "TSK_801_TASK_RANDOM", 
    "title": "Schtasks Random Delay", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/randomdelay*"] } } 
  },
  { 
    "id": "TSK_802_TASK_DURATION", 
    "title": "Schtasks Duration Modifier", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/du*"] } } 
  },
  { 
    "id": "TSK_803_TASK_KILL", 
    "title": "Schtasks Kill If Going On Bat", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/k*"] } } 
  },
  { 
    "id": "TSK_804_TASK_RESTART", 
    "title": "Schtasks Restart On Idle", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "process.command_line": ["*/create*", "*/ri*"] } } 
  },
  { 
    "id": "TSK_805_TASK_XML_RAW_EVENT", 
    "title": "Task Creation Raw XML Event", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Command>powershell.exe</Command>*\n" } } 
  },
  { 
    "id": "TSK_806_TASK_XML_HIDDEN_EVENT", 
    "title": "Task Creation Hidden Attribute", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Hidden>true</Hidden>*\n" } } 
  },
  { 
    "id": "TSK_807_TASK_XML_AUTHOR_EVENT", 
    "title": "Task Creation Suspicious Author", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<Author>System</Author>*\n" } } 
  },
  { 
    "id": "TSK_808_TASK_XML_LOGON_EVENT", 
    "title": "Task Creation Logon Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<LogonTrigger>*\n" } } 
  },
  { 
    "id": "TSK_809_TASK_XML_BOOT_EVENT", 
    "title": "Task Creation Boot Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<BootTrigger>*\n" } } 
  },
  { 
    "id": "TSK_810_TASK_XML_REGISTRATION_EVENT", 
    "title": "Task Creation Registration Trigger", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1053.005"],
    "detection": { "selection": { "event_id": "4698", "task.xml": "*<RegistrationTrigger>*\n" } } 
  }
];