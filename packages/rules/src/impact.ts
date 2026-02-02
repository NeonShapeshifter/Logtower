import { Rule } from '@neonshapeshifter/logtower-engine';

export const IMPACT_RULES: Rule[] = [
  {
    id: 'IMPACT_001_SHADOW_COPY_DELETE',
    title: 'Shadow Copy Deletion (Ransomware Precursor)',
    severity: 'CRITICAL',
    module: 'IMPACT',
    mitre: ['T1490'],
    detection: {
      selection: {
        'process.image': ['*vssadmin.exe', '*wbadmin.exe', '*wmic.exe', '*powershell.exe'],
        'process.command_line': [
          '*delete*shadows*', 
          '*delete*catalog*', 
          '*delete*systemstatebackup*', 
          '*shadowcopy*delete*', 
          '*Resize*ShadowStorage*'
        ]
      }
    },
    description: "The attacker is deleting Windows Volume Shadow Copies (backups). This is the #1 precursor to Ransomware execution, ensuring the victim cannot restore files easily.",
    response_steps: [
      "1. ISOLATE IMMEDIATELY: Ransomware encryption will likely start within seconds/minutes.",
      "2. SHUTDOWN: If you can't isolate network, hard power-off might save some data.",
      "3. ALERT: Mobilize the Incident Response team for a mass encryption event.",
      "4. CHECK: Look for the encryption binary (often random name) running."
    ]
  },
  {
    id: 'IMPACT_002_RECOVERY_DISABLE',
    title: 'Boot Recovery Disabled (Bcdedit)',
    severity: 'CRITICAL',
    module: 'IMPACT',
    mitre: ['T1490'],
    detection: {
      selection: {
        'process.image': '*bcdedit.exe',
        'process.command_line': ['*/set* *recoveryenabled* *No*', '*/set* *bootstatuspolicy* *ignoreallfailures*']
      }
    },
    description: "Disabling Windows Automatic Repair and Recovery options using BCDEdit. This ensures that if the system crashes (or is encrypted), the user cannot easily recover.",
    response_steps: [
      "1. ISOLATE: Precursor to Ransomware or Wiper.",
      "2. RESTORE: 'bcdedit /set {default} recoveryenabled Yes'.",
      "3. HUNT: Look for other destructive commands executed in the same timeframe."
    ]
  },
  {
    id: 'IMPACT_003_LOG_CLEARING',
    title: 'Event Log Clearing (Wevtutil)',
    severity: 'HIGH',
    module: 'IMPACT',
    mitre: ['T1070.001'],
    detection: {
      selection: {
        'process.image': '*wevtutil.exe',
        'process.command_line': ['* cl *', '* clear-log *', '*Security*', '*System*', '*Application*']
      }
    },
    description: "The attacker is wiping the Windows Event Logs (Security, System, etc.) to cover their tracks after an intrusion.",
    response_steps: [
      "1. CHECK SIEM: Hopefully logs were shipped to a central server (like Logtower/Splunk). Local logs are gone.",
      "2. ALERT: Log clearing happens at the END of an attack or right before a major impact.",
      "3. INVESTIGATE: What happened immediately before the logs were cleared?"
    ]
  },
  {
    id: 'IMPACT_004_CIPHER_WIPE',
    title: 'Disk Wiping (Cipher/Format)',
    severity: 'CRITICAL',
    module: 'IMPACT',
    mitre: ['T1485'],
    detection: {
      selection: {
        'process.image': ['*cipher.exe', '*format.com'],
        'process.command_line': ['*/w:*', '*format* *:* */y*']
      }
    },
    description: "Using 'cipher.exe /w' to overwrite deleted data (making it unrecoverable) or 'format' to wipe a drive. This is destructive data loss.",
    response_steps: [
      "1. PULL PLUG: Cut power immediately to stop the wipe.",
      "2. FORENSICS: Do not boot. Image the drive to attempt data recovery (carving).",
      "3. SCOPE: Is this a 'Wiper' malware masquerading as Ransomware?"
    ]
  },
  {
    id: 'IMPACT_005_SERVICE_DESTRUCTION',
    title: 'Service Deletion / Destruction',
    severity: 'HIGH',
    module: 'IMPACT',
    mitre: ['T1489'],
    detection: {
      selection: {
        'process.image': '*sc.exe',
        'process.command_line': ['*delete*', '*config* *start=* *disabled*']
      }
    },
    description: "Deleting critical system services (like EDR agents, Backup services, or Windows Defender) or disabling them.",
    response_steps: [
      "1. RESTORE: Re-install or re-enable the service.",
      "2. IDENTIFY: Which service was targeted? If it was your EDR, you are blind.",
      "3. MONITOR: Watch for the malware payload that typically follows this defense evasion."
    ]
  },
  {
    id: 'IMPACT_006_DOMAIN_ACCOUNT_LOCKOUT',
    title: 'Mass Account Lockout (DoS)',
    severity: 'MEDIUM', // Can be high impact but usually low technical sophistication
    module: 'IMPACT',
    mitre: ['T1498.001'],
    detection: {
      selection: {
        'event_id': '4740', // User Account Locked Out
        // Detection logic would need aggregation (High count of 4740s in short time)
        'count': '>10' // Conceptual
      }
    },
    description: "Multiple user accounts are being locked out rapidly. This is likely a 'Password Spraying' attack going wrong, or a deliberate Denial of Service to disrupt operations.",
    response_steps: [
      "1. SOURCE: Identify the Caller Computer Name in event 4740.",
      "2. ISOLATE: Disconnect the source machine (it's likely infected and spraying bad passwords).",
      "3. UNLOCK: Unlock critical accounts (Service Accounts first).",
      "4. ANALYZE: Check IIS/Exchange logs if the source is external."
    ]
  },
  {
    id: 'IMPACT_007_FILE_OWNERSHIP_TAKEOVER',
    title: 'Mass File Ownership Takeover',
    severity: 'HIGH',
    module: 'IMPACT',
    mitre: ['T1222.001'],
    detection: {
      selection: {
        'process.image': ['*takeown.exe', '*icacls.exe'],
        'process.command_line': ['*/f*', '*/grant*', '*/inheritance:d*']
      }
    },
    description: "Taking ownership of large numbers of files or system directories. Ransomware does this to ensure it has permission to encrypt system files.",
    response_steps: [
      "1. ISOLATE: Precursor to encryption.",
      "2. CHECK: What folder is being modified? (e.g., C:Windows, File Shares).",
      "3. TERMINATE: Kill the process."
    ]
  },
  {
    id: 'IMPACT_008_USN_JOURNAL_DELETE',
    title: 'USN Journal Deletion',
    severity: 'HIGH',
    module: 'IMPACT',
    mitre: ['T1070.004'],
    detection: {
      selection: {
        'process.image': '*fsutil.exe',
        'process.command_line': ['*usn*', '*deletejournal*']
      }
    },
    description: "Deleting the NTFS Change Journal (USN Journal). This hinders forensic analysis of file modifications (creation, deletion, encryption).",
    response_steps: [
      "1. ALERT: Standard Ransomware behavior.",
      "2. INVESTIGATE: Assume files have already been modified/encrypted.",
      "3. RECOVER: Rely on offline backups."
    ]
  },
  {
    id: 'IMPACT_009_BITLOCKER_ENCRYPTION',
    title: 'Malicious BitLocker Encryption',
    severity: 'CRITICAL',
    module: 'IMPACT',
    mitre: ['T1486'],
    detection: {
      selection: {
        'process.image': '*manage-bde.exe',
        'process.command_line': ['*-on*', '*-lock*', '*-ForceRecovery*']
      }
    },
    description: "Attacker is using the native BitLocker tool to encrypt drives and lock the user out (Living off the Land Ransomware).",
    response_steps: [
      "1. STOP: Kill manage-bde.exe.",
      "2. KEY: Did they send the recovery key to the cloud? (Check command line args for -rp or -rk).",
      "3. RECOVER: If key is lost and encryption finished, data is unrecoverable."
    ]
  },
  {
    id: 'IMPACT_010_SYSTEM_SHUTDOWN',
    title: 'Forced System Shutdown/Reboot',
    severity: 'MEDIUM',
    module: 'IMPACT',
    mitre: ['T1529'],
    detection: {
      selection: {
        'process.image': '*shutdown.exe',
        'process.command_line': ['*/r*', '*/s*', '*/t 0*']
      }
    },
    description: "Initiating a system shutdown or reboot. Attackers do this to finalize an installation, disrupt services, or force a 'Safe Mode' boot to bypass AV.",
    response_steps: [
      "1. CANCEL: 'shutdown /a' (Abort) if caught in time.",
      "2. INVESTIGATE: Who issued the command? Is it a scheduled maintenance?",
      "3. CHECK: Look for persistence (Run keys) that will trigger upon the reboot."
    ]
  },
  {
    id: 'IMPACT_032_ESENTUTL_NTDS_CRITICAL',
    title: 'NTDS.dit Dumping via Esentutl',
    severity: 'CRITICAL',
    module: 'IMPACT',
    mitre: ['T1003.003'],
    detection: {
      selection: {
        'process.image': '*esentutl.exe',
        'process.command_line': ['*/vss*', '*ntds.dit*']
      }
    },
    description: "Detects usage of esentutl.exe to create a VSS copy of the NTDS.dit database. This is a common method to dump Active Directory credentials.",
    response_steps: [
      "1. CRITICAL: High risk of Domain Admin credential theft.",
      "2. ISOLATE: Isolate the Domain Controller immediately.",
      "3. RESET: Plan for a full KRBTGT password reset."
    ]
  },
  {
    id: 'IMPACT_041_RWINSTA_SESSION_RESET_MEDIUM',
    title: 'RDP Session Reset (Rwinsta)',
    severity: 'MEDIUM',
    module: 'IMPACT',
    mitre: ['T1529'],
    detection: {
      selection: {
        'process.image': '*rwinsta.exe',
        'process.command_line': ['*session*']
      }
    },
    description: "Detects the use of rwinsta.exe to reset a remote session. Attackers use this to kick off legitimate admins or users during an active breach.",
    response_steps: [
      "1. VERIFY: Did an admin perform this intentionally?",
      "2. CHECK: Look for unauthorized RDP logins."
    ]
  },
  {
    id: 'IMPACT_043_REG_RUNKEY_MOD_CMD',
    title: 'Registry Run Key Modification via CMD',
    severity: 'HIGH',
    module: 'PERSISTENCE',
    mitre: ['T1547.001'],
    detection: {
      selection: {
        'process.image': '*reg.exe',
        'process.command_line': ['*add*', '*\\Windows\\CurrentVersion\\Run*']
      }
    },
    description: "Detects usage of reg.exe to add entries to the Run registry key for persistence.",
    response_steps: [
      "1. INSPECT: Identify the command line and the binary being added.",
      "2. DELETE: Remove the registry key.",
      "3. FILE: Locate and delete the malware binary."
    ]
  }
];