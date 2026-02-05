import { Rule } from '@neonshapeshifter/logtower-engine';

export const ANTI_FORENSICS_RULES: Rule[] = [
  { 
    "id": "AF_611_SDELETE_EXEC", 
    "title": "SDelete Execution", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070.004"], 
    "detection": { "selection": { "process.image": "*sdelete.exe" } },
    "description": "Execution of Sysinternals SDelete. Often used by attackers to securely delete malware artifacts or data.",
    "response_steps": [
      "1. CHECK: What files were targeted?",
      "2. CONTEXT: Is this an admin secure deletion tool?"
    ]
  },
  { 
    "id": "AF_612_SDELETE_WIPE", 
    "title": "SDelete Free Space Wipe", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1485"], 
    "detection": { "selection": { "process.image": "*sdelete.exe", "process.command_line": ["*-z*", "*-c*"] } },
    "description": "SDelete used to wipe free space (-z/-c). This makes file recovery impossible.",
    "response_steps": [
      "1. ALERT: Anti-forensics activity."
    ]
  },
  { 
    "id": "AF_613_SDELETE_RECURSIVE", 
    "title": "SDelete Recursive Deletion", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1485"], 
    "detection": { "selection": { "process.image": "*sdelete.exe", "process.command_line": ["*-s*", "*-q*"] } },
    "description": "SDelete used to recursively delete folders.",
    "response_steps": [
      "1. CHECK: Folder path deleted."
    ]
  },
  { 
    "id": "AF_614_TIMESTOMP_MACE", 
    "title": "Timestomp MACE Attributes", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070.006"], 
    "detection": { "selection": { "process.command_line": ["*timestomp*", "*-m *", "*-a *", "*-c *", "*-e *"] } },
    "description": "Timestomp utility usage to modify MACE (Modified, Accessed, Created, Entry) attributes.",
    "response_steps": [
      "1. ISOLATE: Intentional timestamp manipulation."
    ]
  },
  { 
    "id": "AF_615_POWERSHELL_TIMESTOMP", 
    "title": "PowerShell Timestomping", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070.006"], 
    "detection": { "selection": { "process.command_line": ["*.CreationTime =", "*.LastWriteTime =", "*.LastAccessTime ="] } },
    "description": "Modifying file timestamps using PowerShell properties.",
    "response_steps": [
      "1. CHECK: Which file was touched?"
    ]
  },
  { 
    "id": "AF_616_ATTRIBUTE_CHANGE", 
    "title": "Attrib Hide/System", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1564.001"], 
    "detection": { "selection": { "process.image": "*attrib.exe", "process.command_line": ["*+h*", "*+s*"] } },
    "description": "Setting Hidden or System attributes on a file using attrib.exe.",
    "response_steps": [
      "1. FILE: Locate the hidden file."
    ]
  },
  { 
    "id": "AF_617_FSUTIL_USN_DELETE", 
    "title": "Fsutil Delete USN Journal", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1070.004"], 
    "detection": { "selection": { "process.image": "*fsutil.exe", "process.command_line": ["*usn*", "*deletejournal*"] } },
    "description": "Deleting the USN Journal. Hides file creation/deletion events from forensics.",
    "response_steps": [
      "1. ISOLATE: Common in ransomware/wipers."
    ]
  },
  { 
    "id": "AF_618_WEVTUTIL_CLEAR_SEC", 
    "title": "Wevtutil Clear Security Log", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1070.001"], 
    "detection": { "selection": { "process.image": "*wevtutil.exe", "process.command_line": ["*cl*", "*Security*"] } },
    "description": "Clearing the Security Event Log.",
    "response_steps": [
      "1. ISOLATE: Covering tracks."
    ]
  },
  { 
    "id": "AF_619_WEVTUTIL_CLEAR_SYS", 
    "title": "Wevtutil Clear System Log", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1070.001"], 
    "detection": { "selection": { "process.image": "*wevtutil.exe", "process.command_line": ["*cl*", "*System*"] } },
    "description": "Clearing the System Event Log.",
    "response_steps": [
      "1. ISOLATE: Covering tracks."
    ]
  },
  { 
    "id": "AF_620_WEVTUTIL_CLEAR_APP", 
    "title": "Wevtutil Clear Application Log", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070.001"], 
    "detection": { "selection": { "process.image": "*wevtutil.exe", "process.command_line": ["*cl*", "*Application*"] } },
    "description": "Clearing the Application Event Log.",
    "response_steps": [
      "1. CHECK: Often cleared after exploiting an app."
    ]
  },
  { 
    "id": "AF_621_WEVTUTIL_DISABLE", 
    "title": "Wevtutil Disable Logging", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.002"], 
    "detection": { "selection": { "process.image": "*wevtutil.exe", "process.command_line": ["*sl*", "*/e:false*"] } },
    "description": "Disabling the event logging service for a specific log.",
    "response_steps": [
      "1. CHECK: Log name disabled."
    ]
  },
  { 
    "id": "AF_622_POWERSHELL_CLEAR_LOG", 
    "title": "PowerShell Clear-EventLog", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1070.001"], 
    "detection": { "selection": { "process.command_line": ["*Clear-EventLog*"] } },
    "description": "Clearing Event Logs via PowerShell.",
    "response_steps": [
      "1. ISOLATE: Covering tracks."
    ]
  },
  { 
    "id": "AF_623_VSSADMIN_DELETE", 
    "title": "Vssadmin Delete Shadows", 
    "severity": "CRITICAL", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*vssadmin.exe", "process.command_line": ["*delete*", "*shadows*"] } },
    "description": "Deleting Shadow Copies using vssadmin. Precursor to ransomware.",
    "response_steps": [
      "1. ISOLATE: Immediate threat."
    ]
  },
  { 
    "id": "AF_624_VSSADMIN_RESIZE", 
    "title": "Vssadmin Resize ShadowStorage", 
    "severity": "HIGH", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*vssadmin.exe", "process.command_line": ["*resize*", "*shadowstorage*"] } },
    "description": "Resizing shadow storage to force deletion of old snapshots.",
    "response_steps": [
      "1. CHECK: Ransomware tactic."
    ]
  },
  { 
    "id": "AF_625_WMIC_SHADOW_DELETE", 
    "title": "WMIC ShadowCopy Delete", 
    "severity": "CRITICAL", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.command_line": ["*wmic*", "*shadowcopy*", "*delete*"] } },
    "description": "Deleting Shadow Copies using WMIC.",
    "response_steps": [
      "1. ISOLATE: Immediate threat."
    ]
  },
  { 
    "id": "AF_626_WBADMIN_DELETE_CATALOG", 
    "title": "WBAdmin Delete Catalog", 
    "severity": "CRITICAL", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*wbadmin.exe", "process.command_line": ["*delete*", "*catalog*"] } },
    "description": "Deleting Windows Backup Catalog.",
    "response_steps": [
      "1. ISOLATE: Ransomware tactic."
    ]
  },
  { 
    "id": "AF_627_WBADMIN_DELETE_BACKUP", 
    "title": "WBAdmin Delete Backup", 
    "severity": "CRITICAL", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*wbadmin.exe", "process.command_line": ["*delete*", "*backup*"] } },
    "description": "Deleting backups via wbadmin.",
    "response_steps": [
      "1. ISOLATE: Ransomware tactic."
    ]
  },
  { 
    "id": "AF_628_BCDEDIT_RECOVERY", 
    "title": "BCDEdit Disable Recovery", 
    "severity": "CRITICAL", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*bcdedit.exe", "process.command_line": ["*recoveryenabled*", "*No*"] } },
    "description": "Disabling boot recovery options.",
    "response_steps": [
      "1. ISOLATE: Ransomware tactic."
    ]
  },
  { 
    "id": "AF_629_BCDEDIT_IGNORE_FAILURES", 
    "title": "BCDEdit Ignore Failures", 
    "severity": "HIGH", 
    "module": "IMPACT", 
    "mitre": ["T1490"], 
    "detection": { "selection": { "process.image": "*bcdedit.exe", "process.command_line": ["*bootstatuspolicy*", "*ignoreallfailures*"] } },
    "description": "Setting boot policy to ignore failures.",
    "response_steps": [
      "1. CHECK: Ransomware tactic."
    ]
  },
  { 
    "id": "AF_630_CIPHER_WIPE", 
    "title": "Cipher Wipe Free Space", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1485"], 
    "detection": { "selection": { "process.image": "*cipher.exe", "process.command_line": "*/w:*" } },
    "description": "Using cipher /w to wipe free space.",
    "response_steps": [
      "1. CONTEXT: Data destruction."
    ]
  },
  { 
    "id": "AF_631_REG_DEL_MRU", 
    "title": "Registry Delete MRU (Recent Docs)", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1112"], 
    "detection": { "selection": { "process.image": "*reg.exe", "process.command_line": ["*delete*", "*RecentDocs*"] } },
    "description": "Deleting RecentDocs MRU keys.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_632_REG_DEL_RUN", 
    "title": "Registry Delete Run Key", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1112"], 
    "detection": { "selection": { "process.image": "*reg.exe", "process.command_line": ["*delete*", "*RunMRU*"] } },
    "description": "Deleting RunMRU keys.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_633_REG_DEL_TYPED_URLS", 
    "title": "Registry Delete Typed URLs", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1112"], 
    "detection": { "selection": { "process.image": "*reg.exe", "process.command_line": ["*delete*", "*TypedURLs*"] } },
    "description": "Deleting TypedURLs history.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_634_CLEAR_RECYCLE_BIN", 
    "title": "Clear Recycle Bin (Command Line)", 
    "severity": "LOW", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.command_line": ["*Clear-RecycleBin*", "*rd /s /q C:$Recycle.Bin*"] } },
    "description": "Clearing Recycle Bin via CLI.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_635_SYSMON_DRIVER_UNLOAD", 
    "title": "Fltmc Unload Sysmon", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*fltmc.exe", "process.command_line": ["*unload*", "*SysmonDrv*"] } },
    "description": "Unloading the Sysmon driver (SysmonDrv). Blinds monitoring.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_636_KILL_SYSMON", 
    "title": "Taskkill Sysmon Service", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*taskkill.exe", "process.command_line": ["*Sysmon*", "*/f*"] } },
    "description": "Killing the Sysmon service process.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_637_KILL_DEFENDER", 
    "title": "Taskkill Defender Service", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*taskkill.exe", "process.command_line": ["*WinDefend*", "*/f*"] } },
    "description": "Killing Windows Defender service.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_638_SC_STOP_SYSMON", 
    "title": "SC Stop Sysmon", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*sc.exe", "process.command_line": ["*stop*", "*Sysmon*"] } },
    "description": "Stopping Sysmon service via SC.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_639_SC_DELETE_SYSMON", 
    "title": "SC Delete Sysmon", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*sc.exe", "process.command_line": ["*delete*", "*Sysmon*"] } },
    "description": "Deleting Sysmon service.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_640_NET_STOP_SYSMON", 
    "title": "Net Stop Sysmon", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*net.exe", "process.command_line": ["*stop*", "*Sysmon*"] } },
    "description": "Stopping Sysmon via Net.exe.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_641_AUDITPOL_DISABLE", 
    "title": "Auditpol Disable Success/Failure", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.002"], 
    "detection": { "selection": { "process.image": "*auditpol.exe", "process.command_line": ["*/set*", "*/failure:disable*", "*/success:disable*"] } },
    "description": "Disabling auditing using auditpol.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_642_REG_DISABLE_AUDIT", 
    "title": "Registry Disable Auditing", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1562.002"], 
    "detection": { "selection": { "registry.target_object": "*\\Policies\\Microsoft\\Windows\\Audit*", "registry.details": "0" } },
    "description": "Disabling auditing via Registry.",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  { 
    "id": "AF_643_DELETE_PREFETCH", 
    "title": "Deletion of Prefetch Files", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.command_line": ["*del*", "*\\Windows\\Prefetch*.pf"] } },
    "description": "Deleting Prefetch files. Hinders execution history analysis.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_644_DELETE_AMCACHE", 
    "title": "Deletion of Amcache", 
    "severity": "CRITICAL", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.command_line": ["*del*", "*Amcache.hve*"] } },
    "description": "Deleting Amcache.hve.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_645_DELETE_SHIMCACHE", 
    "title": "Deletion of AppCompat Flags", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.command_line": ["*reg*", "*delete*", "*AppCompatFlags*"] } },
    "description": "Deleting ShimCache (AppCompatFlags).",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_646_POWERSHELL_HISTORY_DEL", 
    "title": "PowerShell Delete History", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1070.003"], 
    "detection": { "selection": { "process.command_line": ["*Remove-Item*", "*ConsoleHost_history.txt*"] } },
    "description": "Deleting PowerShell command history file.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_647_BASH_HISTORY_DEL", 
    "title": "WSL Delete Bash History", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1070.003"], 
    "detection": { "selection": { "process.command_line": ["*rm*", "*.bash_history*"] } },
    "description": "Deleting Bash history in WSL.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_648_ZONE_ID_STRIP", 
    "title": "Stripping Zone.Identifier (MOTW)", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.command_line": ["*Set-Content*", "*Zone.Identifier*", "*$null*"] } },
    "description": "Removing Mark-of-the-Web (Zone.Identifier) manually.",
    "response_steps": [
      "1. CHECK: Bypassing SmartScreen."
    ]
  },
  { 
    "id": "AF_649_UNBLOCK_FILE", 
    "title": "Unblock-File Usage", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1564.004"], 
    "detection": { "selection": { "process.command_line": ["*Unblock-File*", "*-Path*"] } },
    "description": "Using PowerShell Unblock-File to remove MOTW.",
    "response_steps": [
      "1. FILE: Which file was unblocked?"
    ]
  },
  { 
    "id": "AF_650_STREAMS_DELETE", 
    "title": "Sysinternals Streams Delete", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1070"], 
    "detection": { "selection": { "process.image": "*streams.exe", "process.command_line": "*-d*" } },
    "description": "Deleting Alternate Data Streams using streams.exe.",
    "response_steps": [
      "1. CHECK: Anti-forensics."
    ]
  },
  { 
    "id": "AF_651_ADS_EXECUTION", 
    "title": "Execution from ADS", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1564.004"], 
    "detection": { "selection": { "process.image": "*:*:*" } },
    "description": "Process executing from an Alternate Data Stream (file.txt:evil.exe).",
    "response_steps": [
      "1. FILE: Locate the host file."
    ]
  },
  { 
    "id": "AF_652_MAKECAB_ADS", 
    "title": "Makecab Hide in ADS", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1564.004"], 
    "detection": { "selection": { "process.command_line": ["*makecab*", "*:*"] } },
    "description": "Using makecab to hide a file in an ADS.",
    "response_steps": [
      "1. CHECK: Hiding payload."
    ]
  },
  { 
    "id": "AF_653_EXPAND_ADS", 
    "title": "Expand Hidden ADS", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1564.004"], 
    "detection": { "selection": { "process.command_line": ["*expand*", "*:*"] } },
    "description": "Using expand to extract file from ADS.",
    "response_steps": [
      "1. CHECK: Staging payload."
    ]
  },
  { 
    "id": "AF_654_ESENTUTL_ADS", 
    "title": "Esentutl Copy to ADS", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1564.004"], 
    "detection": { "selection": { "process.image": "*esentutl.exe", "process.command_line": "*/y*:*" } },
    "description": "Using esentutl to copy file to ADS.",
    "response_steps": [
      "1. CHECK: Hiding payload."
    ]
  },
  { 
    "id": "AF_655_CERTUTIL_DECODE_HIDDEN", 
    "title": "Certutil Decode Hidden File", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1140"], 
    "detection": { "selection": { "process.command_line": ["*certutil*", "*-decode*", "*hidden*"] } },
    "description": "Decoding a file hidden via attrib.",
    "response_steps": [
      "1. CHECK: Deobfuscation."
    ]
  },
  { 
    "id": "AF_656_PNPUTIL_LOAD", 
    "title": "PnpUtil Driver Load (BYOVD Prep)", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1127"], 
    "detection": { "selection": { "process.image": "*pnputil.exe", "process.command_line": ["*/add-driver*", "*.sys*"] } },
    "description": "Adding a driver using pnputil. Often used to load vulnerable drivers.",
    "response_steps": [
      "1. DRIVER: Check hash of .sys file."
    ]
  },
  { 
    "id": "AF_657_DISM_REMOVE", 
    "title": "DISM Remove Feature (Hardening)", 
    "severity": "MEDIUM", 
    "module": "IMPACT", 
    "mitre": ["T1489"], 
    "detection": { "selection": { "process.image": "*dism.exe", "process.command_line": ["*/Disable-Feature*", "*/Remove*"] } },
    "description": "Removing Windows features via DISM.",
    "response_steps": [
      "1. FEATURE: What was removed?"
    ]
  },
  { 
    "id": "AF_658_WUSA_UNINSTALL", 
    "title": "WUSA Uninstall Update", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1562.001"], 
    "detection": { "selection": { "process.image": "*wusa.exe", "process.command_line": "*/uninstall*" } },
    "description": "Uninstalling Windows Updates (KB). Attackers do this to re-open vulnerabilities.",
    "response_steps": [
      "1. KB: Which update was removed?"
    ]
  },
  { 
    "id": "AF_659_FLTMC_FILTERS", 
    "title": "Fltmc List Filters (Recon)", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1082"], 
    "detection": { "selection": { "process.image": "*fltmc.exe", "process.command_line": "*filters*" } },
    "description": "Listing filesystem minifilters. Used to identify EDR/AV agents.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  { 
    "id": "AF_660_DRIVERQUERY_LIST", 
    "title": "DriverQuery Recon", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1082"], 
    "detection": { "selection": { "process.image": "*driverquery.exe" } },
    "description": "Listing installed drivers.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  }
];