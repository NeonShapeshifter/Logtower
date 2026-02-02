import { Rule } from '@neonshapeshifter/logtower-engine';

export const CRED_RULES: Rule[] = [
  // --- KERBEROS ATTACKS ---
  {
    id: 'CRED_001_GOLDEN_TICKET',
    title: 'Golden Ticket Usage (Forged TGT)',
    severity: 'CRITICAL',
    module: 'CRED',
    mitre: ['T1558.001'],
    detection: {
      selection: {
        'event_id': '4624',
        'logon_type': '3', // Network Logon
        // Detection nuances: Often 4624/4672 with non-existent account or mismatched SIDs, 
        // but hard to detect on logs alone without specific anomalies like blank fields or long lifetimes.
        // This is a placeholder for the "Concept".
        'user.sid': '*-500' 
      }
    },
    description: "The attacker has forged a valid Ticket Granting Ticket (TGT) using the KRBTGT password hash. This allows them to access ANY service as ANY user (including Enterprise Admins) with indefinite persistence. They own the domain.",
    response_steps: [
      "1. ISOLATE: Disconnect all Domain Controllers from the network immediately.",
      "2. RESET 1: Change the KRBTGT account password (invalidates new tickets).",
      "3. WAIT: Force replication to all DCs to ensure the change propagates.",
      "4. RESET 2: Change the KRBTGT password AGAIN (invalidates old/Golden tickets).",
      "5. REBOOT: Restart authentication services (or DCs) to clear in-memory caches.",
      "6. PRAY: Pray they didn't install a backdoor elsewhere (e.g., DSRM, skeleton key)."
    ]
  },
  {
    id: 'CRED_002_SILVER_TICKET',
    title: 'Silver Ticket Usage (Forged TGS)',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1558.001'],
    detection: {
      selection: {
        'event_id': '4624',
        'logon_type': '3',
        // Silver tickets skip the KDC (DC), so they don't leave TGT logs on DC.
        // They appear as local logons on the target server with PAC validation failures if configured.
        'authentication_package': 'Kerberos'
      }
    },
    description: "The attacker forged a Service Ticket (TGS) for a specific service (e.g., MSSQL, CIFS) on a specific server. They have the Service Account's password hash. Does not require communicating with the DC.",
    response_steps: [
      "1. IDENTIFY: Which service account is compromised? (The one associated with the target SPN).",
      "2. ROTATE: Reset the password for that specific Service Account.",
      "3. CHECK: Look for lateral movement from the compromised server.",
      "4. HUNT: Since they have the hash, check if they used it for Pass-the-Hash elsewhere."
    ]
  },
  {
    id: 'CRED_003_KERBEROASTING',
    title: 'Kerberoasting (TGS-REQ for Service Accounts)',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1558.003'],
    detection: {
      selection: {
        'event_id': '4769',
        'ticket_options': '0x40810000', // Forwardable, Renewable, Canonicalize
        'ticket_encryption': '0x17' // RC4-HMAC (Weak encryption is the tell)
      }
    },
    description: "Attacker requested a Kerberos ticket for a Service Account. They can now take this ticket offline and crack the password (brute-force). Successful cracking grants them the service account's privileges.",
    response_steps: [
      "1. PASSWORD: Reset the password for the targeted Service Account immediately.",
      "2. HARDEN: Use a complex password (>25 chars) for service accounts to make cracking impossible.",
      "3. UPGRADE: Disable RC4 encryption support in Kerberos policies (Enforce AES).",
      "4. HUNT: Check source IP. Who is requesting these tickets?"
    ]
  },
  {
    id: 'CRED_004_ASREP_ROASTING',
    title: 'AS-REP Roasting (No Pre-Auth)',
    severity: 'MEDIUM',
    module: 'CRED',
    mitre: ['T1558.004'],
    detection: {
      selection: {
        'event_id': '4768',
        'ticket_encryption': '0x17' // RC4
        // Logic requires checking if 'Pre-Auth' was required (status code) or simply successful request for such users.
      }
    },
    description: "Attack targeting users with 'Do not require Kerberos preauthentication' enabled. Attacker can request a TGT without knowing the password, then crack the response offline to retrieve the password.",
    response_steps: [
      "1. REMEDIATE: Enable 'Require Kerberos Preauthentication' for the affected user account.",
      "2. RESET: Reset the user's password immediately (assume it's cracked).",
      "3. AUDIT: Scan AD for other users with Pre-Auth disabled."
    ]
  },
  {
    id: 'CRED_005_DCSYNC',
    title: 'DCSync (Domain Replication Abuse)',
    severity: 'CRITICAL',
    module: 'CRED',
    mitre: ['T1003.006'],
    detection: {
      selection: {
        'event_id': '4662',
        'object_type': 'domainDNS', // or specific GUIDs for DS-Replication-Get-Changes
        'properties': ['*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*', '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'] // Replication rights
      }
    },
    description: "Attacker is simulating a Domain Controller to request password hashes (replication data) from a real DC. Requires 'Replicating Directory Changes' rights. They can pull KRBTGT hash.",
    response_steps: [
      "1. ISOLATE: Cut network access for the source IP performing the sync.",
      "2. VERIFY: Is the source a legitimate Domain Controller? If not, it's an attack.",
      "3. SCOPE: Assume ALL domain credentials are compromised (including KRBTGT).",
      "4. EXECUTE: Protocol 'Golden Ticket' (Reset KRBTGT twice)."
    ]
  },
  {
    id: 'CRED_006_LSASS_DUMP',
    title: 'LSASS Memory Dumping (Mimikatz/ProcDump)',
    severity: 'CRITICAL',
    module: 'CRED',
    mitre: ['T1003.001'],
    detection: {
      selection: {
        'event_id': '10', // Sysmon Process Access
        'target_image': '*lsass.exe',
        'granted_access': ['0x1F0FFF', '0x1410', '0x1010'] // Suspicious access masks
      }
    },
    description: "A process attempted to read the memory of the Local Security Authority Subsystem Service (LSASS). This is used to extract plaintext passwords, NTLM hashes, and Kerberos tickets.",
    response_steps: [
      "1. CONTAIN: Isolate the host immediately.",
      "2. ANALYZE: Identify the tool (procdump, taskmgr, mimikatz, unknown malware).",
      "3. CREDS: Reset credentials for ANY user logged into that box (including services).",
      "4. HUNT: Check for 'lsass.dmp' or similar dump files on disk."
    ]
  },
  {
    id: 'CRED_007_NTDS_THEFT',
    title: 'NTDS.dit Theft (AD Database)',
    severity: 'CRITICAL',
    module: 'CRED',
    mitre: ['T1003.003'],
    detection: {
      selection: {
        'process.image': ['*ntdsutil.exe', '*vssadmin.exe', '*diskshadow.exe'],
        'process.command_line': ['*ac i ntds*', '*create*shadow*', '*ntds.dit*']
      }
    },
    description: "Attempt to copy or access 'ntds.dit', the main Active Directory database containing all domain objects and password hashes.",
    response_steps: [
      "1. PANIC (ORDERLY): If they get this, they have every hash in the domain.",
      "2. ISOLATE: Disconnect the Domain Controller involved.",
      "3. RESET: Global password reset is required if exfiltration is confirmed.",
      "4. FORENSICS: Did the file leave the network? Check egress logs."
    ]
  },
  {
    id: 'CRED_008_SAM_THEFT',
    title: 'SAM Database Theft (Local Hashes)',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1003.002'],
    detection: {
      selection: {
        'process.command_line': ['*save HKLMSAM*', '*save HKLMSYSTEM*', '*reg* save *SAM*']
      }
    },
    description: "Attacker is dumping the local SAM registry hive to extract local user hashes (like local Administrator). Used for lateral movement via Pass-the-Hash.",
    response_steps: [
      "1. ISOLATE: Isolate the host.",
      "2. RESET: Reset the local Administrator password (LAPS is recommended).",
      "3. CHECK: Did they get the 'SYSTEM' hive too? (Required to decrypt SAM).",
      "4. HUNT: Look for lateral movement attempts using the local admin hash."
    ]
  },
  {
    id: 'CRED_009_PASS_THE_HASH',
    title: 'Pass-the-Hash (PtH)',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1550.002'],
    detection: {
      selection: {
        'event_id': '4624',
        'logon_type': '3',
        'logon_process_name': 'NtLmSsp',
        'key_length': '0' // Characteristic of PtH tools often having 0 key length in some logs, or specific NTLM anomalies
      }
    },
    description: "Attacker is authenticating to a remote server using a captured NTLM hash instead of a plaintext password. This bypasses the need to crack the hash.",
    response_steps: [
      "1. BLOCK: PtH relies on SMB/Admin shares. Restrict Workstation-to-Workstation communication.",
      "2. IDENTIFY: Which account is being used? Disable it temporarily.",
      "3. TRACE: The source IP is compromised. Investigate it.",
      "4. PREVENT: Use 'Protected Users' group or disable NTLM where possible."
    ]
  },
  {
    id: 'CRED_010_TOKEN_MANIPULATION',
    title: 'Token Manipulation / Theft',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1134'],
    detection: {
      selection: {
        'process.command_line': ['*token::elevate*', '*incognito*', '*list_tokens*'] // Signatures for common tools
      }
    },
    description: "Attacker is stealing an access token from an existing process (e.g., from a Domain Admin logged in) to impersonate that user without needing credentials.",
    response_steps: [
      "1. KILL: Terminate the malicious process holding the stolen token.",
      "2. REBOOT: Clears active tokens from memory.",
      "3. ALERT: A DA token was exposed on a lower-tier machine. Investigate why a DA was logged in there."
    ]
  },
  {
    id: 'CRED_011_BROWSER_THEFT',
    title: 'Browser Credential/Cookie Theft',
    severity: 'MEDIUM',
    module: 'CRED',
    mitre: ['T1539'],
    detection: {
      selection: {
        'process.command_line': ['*Cookies*', '*Login Data*', '*Headless*', '*--user-data-dir*']
      }
    },
    description: "Accessing web browser storage files (Chrome, Edge, Firefox) to steal saved passwords and session cookies (Session Hijacking).",
    response_steps: [
      "1. TERMINATE: Kill the stealing process.",
      "2. RESET: Reset passwords for web services accessed by that user.",
      "3. REVOKE: Invalidate active session tokens (cookies) for critical apps (M365, Okta, etc.)."
    ]
  },
  {
    id: 'CRED_012_VAULT_DUMP',
    title: 'Windows Vault / Credential Manager Dump',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1555.004'],
    detection: {
      selection: {
        'process.image': '*vaultcmd.exe',
        'process.command_line': ['*/list*', '*/enum*']
      }
    },
    description: "Enumerating or dumping credentials stored in the Windows Credential Manager (Vault). Often contains RDP saved creds, VPN passwords, or network share secrets.",
    response_steps: [
      "1. INVESTIGATE: What was stored in the Vault? (Ask user or check policy).",
      "2. ROTATE: Reset any credentials that were likely stored there.",
      "3. CLEAN: Clear the saved credentials from the compromised host."
    ]
  },
  {
    id: 'CRED_013_LAPS_ABUSE',
    title: 'LAPS Attribute Reading (Cleartext Admin)',
    severity: 'HIGH',
    module: 'CRED',
    mitre: ['T1003'],
    detection: {
      selection: {
        'event_id': '4662',
        'properties': ['*ms-Mcs-AdmPwd*'] // LAPS Password Attribute GUID
      }
    },
    description: "Attacker queried the 'ms-Mcs-AdmPwd' attribute from Active Directory. This reveals the plaintext Local Administrator password managed by LAPS.",
    response_steps: [
      "1. IDENTIFY: Who queried this? (User field in event 4662).",
      "2. VERIFY: Is that user a LAPS Admin? If not, their account is compromised.",
      "3. ROTATE: Force LAPS to expire/rotate the password immediately (Set-AdmPwdReset)."
    ]
  },
  {
    id: 'CRED_014_DCSHADOW',
    title: 'DCShadow (Rogue Domain Controller)',
    severity: 'CRITICAL',
    module: 'CRED',
    mitre: ['T1207'],
    detection: {
      selection: {
        'event_id': '4742', // Computer account changed
        'service_principal_name': '*GC/*', // SPN registration for Global Catalog
        // Very specific complex pattern usually involving ntds service registration
      }
    },
    description: "Attacker registers a rogue Domain Controller to push malicious changes (like SID History injection) via replication, then unregisters it. Bypasses SIEMs monitoring standard change events.",
    response_steps: [
      "1. PANIC: Requires Domain Admin rights to execute. Your AD is fully compromised.",
      "2. AUDIT: Review replication metadata for recent changes from unknown GUIDs.",
      "3. CLEANUP: Remove the rogue computer object and any changes pushed (e.g., SidHistory)."
    ]
  }
];