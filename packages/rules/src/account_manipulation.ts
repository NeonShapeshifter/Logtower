import { Rule } from '@neonshapeshifter/logtower-engine';

export const ACCOUNT_MANIPULATION_RULES: Rule[] = [
  { 
    "id": "ACC_811_ADMINSDHOLDER_MOD", 
    "title": "AdminSDHolder Modification", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*dsacls*", "*AdminSDHolder*"] } },
    "description": "Detects modifications to the AdminSDHolder object using dsacls. Attackers modify this object to establish persistence across all protected groups (e.g., Domain Admins) by adding their own accounts to the ACL, which SDProp then propagates automatically.",
    "response_steps": [
      "1. IDENTIFY: Who ran the command? (User and Source IP)",
      "2. ANALYZE: Review the specific ACL changes made. Who was added?",
      "3. REVERT: Remove the unauthorized entries from the AdminSDHolder ACL immediately.",
      "4. SCOPE: Force SDProp to run or wait for propagation to clean up protected groups."
    ]
  },
  { 
    "id": "ACC_812_BACKUP_OPS_ADD", 
    "title": "Add to Backup Operators", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Backup Operators*", "*/add*"] } },
    "description": "Detects addition of a user to the 'Backup Operators' group. Members of this group can read any file on the system (bypassing ACLs) and back up/restore the domain controller database (NTDS.dit), allowing for credential dumping.",
    "response_steps": [
      "1. VERIFY: Was this a scheduled IT maintenance task?",
      "2. INVESTIGATE: Identify the user added and the actor who added them.",
      "3. REVERT: Remove the user from the group if unauthorized.",
      "4. CHECK: Look for subsequent file access or 'ntdsutil' usage."
    ]
  },
  { 
    "id": "ACC_813_ACCOUNT_OPS_ADD", 
    "title": "Add to Account Operators", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Account Operators*", "*/add*"] } },
    "description": "Detects addition of a user to the 'Account Operators' group. This group can create/modify most users and groups in the domain, effectively providing a path to Domain Admin privileges.",
    "response_steps": [
      "1. VERIFY: Confirm if this is a legitimate helpdesk delegation.",
      "2. IDENTIFY: Who initiated the change?",
      "3. REVERT: Remove unauthorized members immediately.",
      "4. MONITOR: Watch for new user creations or password resets performed by the added user."
    ]
  },
  { 
    "id": "ACC_814_SERVER_OPS_ADD", 
    "title": "Add to Server Operators", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Server Operators*", "*/add*"] } },
    "description": "Detects addition of a user to the 'Server Operators' group. Members can log in interactively to servers, stop/start services, and access file shares, often leading to full server compromise.",
    "response_steps": [
      "1. VERIFY: Is this part of a server maintenance workflow?",
      "2. REVERT: Remove the user from the group if not authorized.",
      "3. SCOPE: Check if the user logged into any Domain Controllers or critical servers."
    ]
  },
  { 
    "id": "ACC_815_PRINT_OPS_ADD", 
    "title": "Add to Print Operators", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Print Operators*", "*/add*"] } },
    "description": "Detects addition of a user to the 'Print Operators' group. This group can load kernel drivers (printer drivers) on Domain Controllers, which is a common technique (e.g., PrintNightmare) to gain SYSTEM privileges.",
    "response_steps": [
      "1. VERIFY: Confirm legitimacy. This group is rarely used in modern administration.",
      "2. REVERT: Remove the user immediately.",
      "3. CHECK: Look for driver load events or spooler service activity."
    ]
  },
  { 
    "id": "ACC_816_REMOTE_DESKTOP_USERS_ADD", 
    "title": "Add to Remote Desktop Users", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Remote Desktop Users*", "*/add*"] } },
    "description": "Detects a user being added to the local 'Remote Desktop Users' group. This grants the ability to login via RDP, a common persistence mechanism for lateral movement.",
    "response_steps": [
      "1. CONTEXT: Is this a workstation or a critical server?",
      "2. VERIFY: Check ticket/approval for remote access grant.",
      "3. REVERT: Remove the user if unauthorized."
    ]
  },
  { 
    "id": "ACC_817_DNS_ADMINS_ADD", 
    "title": "Add to DnsAdmins", 
    "severity": "CRITICAL", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*DnsAdmins*", "*/add*"] } },
    "description": "Detects addition to 'DnsAdmins'. Members can force the DNS server service to load an arbitrary DLL (as SYSTEM) on the Domain Controller, leading to immediate domain compromise.",
    "response_steps": [
      "1. IMMEDIATE ACTION: This is a high-fidelity attack signal. Isolate the source.",
      "2. VERIFY: Did the DNS service restart or load a new plugin DLL?",
      "3. REVERT: Remove the user and investigate the actor."
    ]
  },
  { 
    "id": "ACC_818_SETSPN_ADD", 
    "title": "Setspn Add SPN", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*setspn.exe", "process.command_line": ["*-a*", "*-s*"] } },
    "description": "Detects the addition of a Service Principal Name (SPN) to a user account. Attackers add SPNs to accounts they control to make them 'Kerberoastable' or to facilitate other Kerberos attacks.",
    "response_steps": [
      "1. VERIFY: Is a new service actually being deployed?",
      "2. CHECK: Is the target account a standard user or a service account?",
      "3. REVERT: Remove the SPN if illegitimate."
    ]
  },
  { 
    "id": "ACC_819_SETSPN_DEL", 
    "title": "Setspn Delete SPN", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*setspn.exe", "process.command_line": "*-d*" } },
    "description": "Detects the deletion of an SPN. This can be used to hide a service or disrupt legitimate authentication (Impact).",
    "response_steps": [
      "1. VERIFY: Is this part of decommissioning a service?",
      "2. INVESTIGATE: Determine who ran the command."
    ]
  },
  { 
    "id": "ACC_820_SETSPN_LIST", 
    "title": "Setspn List SPNs", 
    "severity": "LOW", 
    "module": "DISCOVERY", 
    "mitre": ["T1087"], 
    "detection": { "selection": { "process.image": "*setspn.exe", "process.command_line": "*-l*" } },
    "description": "Detects listing of SPNs using setspn. While often legitimate, attackers use this to enumerate potential targets for Kerberoasting.",
    "response_steps": [
      "1. CONTEXT: Who is running this? Admin or random user?",
      "2. MONITOR: Watch for subsequent ticket requests (TGS-REQ)."
    ]
  },
  { 
    "id": "ACC_821_SID_HISTORY_MOD", 
    "title": "SID History Modification (DSAdd)", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1134.005"], 
    "detection": { "selection": { "process.command_line": ["*dsadd*", "*sidhistory*"] } },
    "description": "Detects attempts to inject SID History into an account. SID History is used for migration but abused by attackers to grant an account the privileges of another (e.g., Domain Admin) without adding them to the group.",
    "response_steps": [
      "1. CRITICAL: Verify if a domain migration is in progress.",
      "2. INVESTIGATE: If no migration, this is a Golden Ticket/persistence attempt.",
      "3. REVERT: Clear the SID History attribute."
    ]
  },
  { 
    "id": "ACC_822_PRIMARY_GROUP_MOD", 
    "title": "Primary Group ID Change", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/primarygroup*"] } },
    "description": "Detects changes to a user's Primary Group ID. This is an obscure persistence method used to hide group membership (e.g., setting Domain Admins as primary group hides it from some standard enumerations).",
    "response_steps": [
      "1. INVESTIGATE: Why is the primary group being changed? This is non-standard.",
      "2. REVERT: Reset to Domain Users (513) or appropriate default."
    ]
  },
  { 
    "id": "ACC_823_PWD_NOT_EXPIRE", 
    "title": "Password Does Not Expire Set", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/expires:never*"] } },
    "description": "Detects setting a user account to 'Password Never Expires'. Attackers use this to maintain long-term access to compromised credentials.",
    "response_steps": [
      "1. VERIFY: Is this a service account requiring this setting?",
      "2. POLICY: Does this violate password rotation policy?",
      "3. REVERT: Enforce expiration if unauthorized."
    ]
  },
  { 
    "id": "ACC_824_PREAUTH_DISABLE", 
    "title": "Kerberos Pre-Auth Disable", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1558.004"], 
    "detection": { "selection": { "process.command_line": ["*Set-ADAccountControl*", "*DoesNotRequirePreAuth*"] } },
    "description": "Detects disabling of Kerberos Pre-Authentication. This allows an attacker to request a TGT for the user and crack the password offline (AS-REP Roasting).",
    "response_steps": [
      "1. IMMEDIATE: Re-enable Pre-Authentication.",
      "2. ROTATE: Reset the password for the affected user immediately, assuming it is compromised.",
      "3. INVESTIGATE: Who made the change?"
    ]
  },
  { 
    "id": "ACC_825_DELEGATION_ENABLE", 
    "title": "Enable Delegation (Unconstrained)", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1558"], 
    "detection": { "selection": { "process.command_line": ["*Set-ADAccountControl*", "*TrustedForDelegation*"] } },
    "description": "Detects enabling of Unconstrained Delegation on an account. If a privileged user connects to this machine/service, their TGT is stored in memory and can be stolen by the attacker.",
    "response_steps": [
      "1. IMMEDIATE: Disable Unconstrained Delegation.",
      "2. INVESTIGATE: Check for compromised services on the target host.",
      "3. HUNT: Look for TGT extraction activity."
    ]
  },
  { 
    "id": "ACC_826_CONSTRAINED_DELEGATION", 
    "title": "Enable Constrained Delegation", 
    "severity": "HIGH", 
    "module": "CRED", 
    "mitre": ["T1558"], 
    "detection": { "selection": { "process.command_line": ["*Set-ADAccountControl*", "*TrustedToAuthForDelegation*"] } },
    "description": "Detects configuration of Constrained Delegation. While more secure than unconstrained, if configured to a target service improperly (or if Protocol Transition is enabled), it can be abused.",
    "response_steps": [
      "1. VERIFY: Validate the delegation configuration (Service and Protocol).",
      "2. AUTHORIZE: Confirm against change management."
    ]
  },
  { 
    "id": "ACC_827_DSRM_RESET", 
    "title": "DSRM Password Reset", 
    "severity": "CRITICAL", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*ntdsutil.exe", "process.command_line": ["*set dsrm password*"] } },
    "description": "Detects a reset of the Directory Services Restore Mode (DSRM) administrator password. Attackers use this to maintain a backdoor administrator account that persists even if Domain Admin passwords are reset.",
    "response_steps": [
      "1. CRITICAL: Was this authorized disaster recovery prep?",
      "2. INVESTIGATE: If unauthorized, the domain is likely fully compromised.",
      "3. ACTION: Reset the DSRM password again to a known secure value."
    ]
  },
  { 
    "id": "ACC_828_GUEST_GROUP_ADD", 
    "title": "Add to Guests Group", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Guests*", "*/add*"] } },
    "description": "Detects addition of a user to the 'Guests' group. Unusual activity, potentially used to hide accounts or facilitate anonymous access if Guest is enabled.",
    "response_steps": [
      "1. VERIFY: Is the Guest account enabled?",
      "2. CHECK: Why is a user being added here? Investigate intent."
    ]
  },
  { 
    "id": "ACC_829_HYPERV_ADMINS_ADD", 
    "title": "Add to Hyper-V Admins", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Hyper-V Administrators*", "*/add*"] } },
    "description": "Detects addition to 'Hyper-V Administrators'. Members can mount virtual disks of Domain Controllers or other sensitive VMs to access their file systems offline.",
    "response_steps": [
      "1. VERIFY: Is this a virtualization admin?",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_830_REPLICATOR_ADD", 
    "title": "Add to Replicator Group", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Replicator*", "*/add*"] } },
    "description": "Detects addition to the 'Replicator' group. This legacy group has implicit rights that can be abused for privilege escalation or persistence.",
    "response_steps": [
      "1. VERIFY: This group is rarely used. High probability of malicious intent or misconfiguration.",
      "2. REVERT: Remove the user."
    ]
  },
  { 
    "id": "ACC_831_CRYPT_OPS_ADD", 
    "title": "Add to Cryptographic Operators", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Cryptographic Operators*", "*/add*"] } },
    "description": "Detects addition to 'Cryptographic Operators'. Members can perform cryptographic operations and may be able to influence system security configuration.",
    "response_steps": [
      "1. VERIFY: Authorization check.",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_832_EVENT_LOG_READERS_ADD", 
    "title": "Add to Event Log Readers", 
    "severity": "MEDIUM", 
    "module": "COLLECTION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Event Log Readers*", "*/add*"] } },
    "description": "Detects addition to 'Event Log Readers'. This allows the user to read security logs, potentially helping an attacker study detection logic or find other user activity.",
    "response_steps": [
      "1. VERIFY: Is this a security auditor or SIEM service account?",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_833_WINRM_REMOTE_WMI_USERS_ADD", 
    "title": "Add to WinRMRemoteWMIUsers", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*WinRMRemoteWMIUsers*", "*/add*"] } },
    "description": "Detects addition to 'WinRMRemoteWMIUsers'. Allows the user to execute WMI commands remotely, a powerful method for lateral movement and execution.",
    "response_steps": [
      "1. VERIFY: Confirm legitimate need for remote WMI.",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_834_USER_COMMENT_MOD", 
    "title": "User Comment Modification", 
    "severity": "LOW", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/usercomment:*"] } },
    "description": "Detects changes to a user's comment field. Attackers sometimes store encoded configuration or state data in user comment fields.",
    "response_steps": [
      "1. INSPECT: Read the new comment. Does it look like base64 or random data?",
      "2. INVESTIGATE: Context of the change."
    ]
  },
  { 
    "id": "ACC_835_USER_PROFILE_PATH", 
    "title": "User Profile Path Modification", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/profilepath:*"] } },
    "description": "Detects changes to the user profile path. Can be used to redirect a user's profile to a malicious share.",
    "response_steps": [
      "1. INSPECT: Check the new path. Is it local or remote?",
      "2. REVERT: Restore correct profile path."
    ]
  },
  { 
    "id": "ACC_836_USER_SCRIPT_PATH", 
    "title": "User Logon Script Modification", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/scriptpath:*"] } },
    "description": "Detects changes to the user's logon script path. This is a classic persistence mechanism ensuring code execution whenever the user logs in.",
    "response_steps": [
      "1. INSPECT: Retrieve the script at the new path.",
      "2. ANALYZE: What does the script do?",
      "3. REVERT: Remove the script path."
    ]
  },
  { 
    "id": "ACC_837_USER_WORKSTATIONS", 
    "title": "User Workstations Modification", 
    "severity": "MEDIUM", 
    "module": "DEFENSE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/workstations:*"] } },
    "description": "Detects changes to the 'Logon Workstations' restriction. Attackers may clear this list to allow a compromised account to log in from anywhere.",
    "response_steps": [
      "1. VERIFY: Was a restriction removed or added?",
      "2. REVERT: Re-apply necessary login restrictions."
    ]
  },
  { 
    "id": "ACC_838_USER_PASSWORD_REQ", 
    "title": "User Password Required No", 
    "severity": "HIGH", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/passwordreq:no*"] } },
    "description": "Detects setting an account to not require a password. This creates a trivial backdoor for access.",
    "response_steps": [
      "1. IMMEDIATE: Re-enable password requirement.",
      "2. AUDIT: Check for logins to this account during the vulnerable window."
    ]
  },
  { 
    "id": "ACC_839_USER_ACTIVE_YES", 
    "title": "Activate User Account", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net user*", "*/active:yes*"] } },
    "description": "Detects the activation of a disabled user account. Attackers often re-enable dormant accounts to blend in.",
    "response_steps": [
      "1. VERIFY: Should this account be active? (e.g., employee returned).",
      "2. REVERT: Disable if unauthorized."
    ]
  },
  { 
    "id": "ACC_840_USER_UNLOCK", 
    "title": "Unlock User Account", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*Unlock-ADAccount*"] } },
    "description": "Detects an account unlock event initiated via PowerShell. Frequent unlocks might indicate an attacker trying to brute-force an account and manually resetting the lockout counter.",
    "response_steps": [
      "1. CONTEXT: Is this helpdesk activity?",
      "2. CHECK: Look for failed login attempts preceding the unlock."
    ]
  },
  { 
    "id": "ACC_841_DSMOD_GROUP", 
    "title": "DSMod Group Modification", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*dsmod.exe", "process.command_line": "*group*" } },
    "description": "Detects usage of 'dsmod group' to modify AD groups. Could be used to change membership or type.",
    "response_steps": [
      "1. INVESTIGATE: Determine specific parameters used and the target group.",
      "2. VERIFY: Authorization."
    ]
  },
  { 
    "id": "ACC_842_DSMOD_USER", 
    "title": "DSMod User Modification", 
    "severity": "MEDIUM", 
    "module": "PERSISTENCE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*dsmod.exe", "process.command_line": "*user*" } },
    "description": "Detects usage of 'dsmod user' to modify user attributes (reset password, disable, etc.).",
    "response_steps": [
      "1. INVESTIGATE: Determine specific parameters used (e.g., -pwd, -disabled).",
      "2. VERIFY: Authorization."
    ]
  },
  { 
    "id": "ACC_843_DSMOD_QUOTA", 
    "title": "DSMod Quota Modification", 
    "severity": "LOW", 
    "module": "IMPACT", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*dsmod.exe", "process.command_line": "*quota*" } },
    "description": "Detects modification of directory quotas using dsmod. Low security impact but unusual.",
    "response_steps": [
      "1. MONITOR: Check for other dsmod activity."
    ]
  },
  { 
    "id": "ACC_844_DSMOD_PARTITION", 
    "title": "DSMod Partition Modification", 
    "severity": "HIGH", 
    "module": "IMPACT", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*dsmod.exe", "process.command_line": "*partition*" } },
    "description": "Detects modification of AD partitions. Could indicate high-level directory tampering.",
    "response_steps": [
      "1. INVESTIGATE: Highly suspicious if not from a Domain Admin during maintenance.",
      "2. REVERT: Check partition integrity."
    ]
  },
  { 
    "id": "ACC_845_DSMOD_SERVER", 
    "title": "DSMod Server Modification", 
    "severity": "HIGH", 
    "module": "IMPACT", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.image": "*dsmod.exe", "process.command_line": "*server*" } },
    "description": "Detects modification of server objects in AD. Can affect replication or server availability.",
    "response_steps": [
      "1. VERIFY: Infrastructure change management.",
      "2. INVESTIGATE: Source of the command."
    ]
  },
  { 
    "id": "ACC_846_NET_ACCOUNT_FORCE", 
    "title": "Net Accounts Force Logoff", 
    "severity": "MEDIUM", 
    "module": "IMPACT", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net accounts*", "*/forcelogoff*"] } },
    "description": "Detects setting the force logoff policy. This determines if a user is disconnected when their login hours expire.",
    "response_steps": [
      "1. VERIFY: Policy change verification.",
      "2. REVERT: Reset to organizational standard."
    ]
  },
  { 
    "id": "ACC_847_NET_ACCOUNT_MINPWLEN", 
    "title": "Net Accounts Min PW Len", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net accounts*", "*/minpwlen:0*"] } },
    "description": "Detects an attempt to weaken password policies by setting minimum length to 0.",
    "response_steps": [
      "1. IMMEDIATE: Reset policy to secure standard.",
      "2. INVESTIGATE: Who attempted to weaken security?",
      "3. AUDIT: Check for short passwords created recently."
    ]
  },
  { 
    "id": "ACC_848_NET_ACCOUNT_MAXPWAGE", 
    "title": "Net Accounts Max PW Age", 
    "severity": "HIGH", 
    "module": "DEFENSE", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net accounts*", "*/maxpwage:unlimited*"] } },
    "description": "Detects an attempt to weaken password policies by setting maximum password age to unlimited.",
    "response_steps": [
      "1. IMMEDIATE: Reset policy.",
      "2. INVESTIGATE: Identify the actor."
    ]
  },
  { 
    "id": "ACC_849_LAPS_READ", 
    "title": "LAPS Password Read", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1003"], 
    "detection": { "selection": { "process.command_line": ["*Get-AdmPwdPassword*"] } },
    "description": "Detects an attempt to read the Local Administrator Password Solution (LAPS) password for a machine. This provides local admin rights to that machine.",
    "response_steps": [
      "1. VERIFY: Is the user authorized to manage that specific machine?",
      "2. MONITOR: Watch for login events on the target machine using the local admin account."
    ]
  },
  { 
    "id": "ACC_850_LAPS_RESET", 
    "title": "LAPS Password Reset", 
    "severity": "HIGH", 
    "module": "IMPACT", 
    "mitre": ["T1485"], 
    "detection": { "selection": { "process.command_line": ["*Reset-AdmPwdPassword*"] } },
    "description": "Detects an unexpected reset of a LAPS password. Could be an attacker locking out legitimate admins or covering tracks.",
    "response_steps": [
      "1. VERIFY: Authorized reset?",
      "2. INVESTIGATE: Why was the reset needed?"
    ]
  },
  { 
    "id": "ACC_851_AZURE_AD_CONNECT_SYNC", 
    "title": "Azure AD Connect Sync Account Abuse", 
    "severity": "CRITICAL", 
    "module": "CRED", 
    "mitre": ["T1003"], 
    "detection": { "selection": { "process.command_line": ["*MSOL_*", "*Sync*"] } },
    "description": "Detects suspicious usage of the Azure AD Connect Sync account (MSOL_...). This account has Replicating Directory Changes privileges and is a prime target for DCSync attacks.",
    "response_steps": [
      "1. CRITICAL: Is this activity coming from the legitimate AD Connect server?",
      "2. INVESTIGATE: If from anywhere else, it's a confirmed compromise attempt."
    ]
  },
  { 
    "id": "ACC_852_EXCHANGE_PRIVS_ADD", 
    "title": "Add to Exchange Trusted Subsystem", 
    "severity": "CRITICAL", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Exchange Trusted Subsystem*", "*/add*"] } },
    "description": "Detects addition to 'Exchange Trusted Subsystem'. Members of this group have high privileges on Exchange servers and can often escalate to Domain Admin.",
    "response_steps": [
      "1. IMMEDIATE: Verify legitimacy.",
      "2. REVERT: Remove immediately if unauthorized."
    ]
  },
  { 
    "id": "ACC_853_EXCHANGE_WINDOWS_PERM_ADD", 
    "title": "Add to Exchange Windows Permissions", 
    "severity": "CRITICAL", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Exchange Windows Permissions*", "*/add*"] } },
    "description": "Detects addition to 'Exchange Windows Permissions'. This group has WriteDacl access to the domain object, allowing for trivial privilege escalation.",
    "response_steps": [
      "1. CRITICAL: High alert. Verify immediately.",
      "2. REVERT: Remove user."
    ]
  },
  { 
    "id": "ACC_854_SCHEMA_ADMINS_ADD", 
    "title": "Add to Schema Admins", 
    "severity": "CRITICAL", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Schema Admins*", "*/add*"] } },
    "description": "Detects addition to 'Schema Admins'. This is one of the highest privilege groups, allowing modification of the AD schema.",
    "response_steps": [
      "1. CRITICAL: Schema changes are rare and tightly controlled.",
      "2. VERIFY: Confirm with Chief Architect/CISO.",
      "3. REVERT: Remove immediately."
    ]
  },
  { 
    "id": "ACC_855_ENTERPRISE_ADMINS_ADD", 
    "title": "Add to Enterprise Admins", 
    "severity": "CRITICAL", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Enterprise Admins*", "*/add*"] } },
    "description": "Detects addition to 'Enterprise Admins'. Grants full control over all domains in the forest.",
    "response_steps": [
      "1. CRITICAL: Highest alert level.",
      "2. VERIFY: Immediate authorization check.",
      "3. REVERT: Remove immediately."
    ]
  },
  { 
    "id": "ACC_856_GROUP_POLICY_CREATOR_OWNERS_ADD", 
    "title": "Add to Group Policy Creator Owners", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Group Policy Creator Owners*", "*/add*"] } },
    "description": "Detects addition to 'Group Policy Creator Owners'. Allows creation and modification of GPOs, which can be used to deploy malware to the entire fleet.",
    "response_steps": [
      "1. VERIFY: Check authorization.",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_857_INCOMING_FOREST_TRUST_ADD", 
    "title": "Add to Incoming Forest Trust Builders", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net group*", "*Incoming Forest Trust Builders*", "*/add*"] } },
    "description": "Detects addition to 'Incoming Forest Trust Builders'. Allows creation of forest trusts, potentially bridging security boundaries.",
    "response_steps": [
      "1. VERIFY: Are we setting up a new trust?",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_858_PRE_WIN2000_ADD", 
    "title": "Add to Pre-Windows 2000 Compatible Access", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Pre-Windows 2000 Compatible Access*", "*/add*"] } },
    "description": "Detects addition to 'Pre-Windows 2000 Compatible Access'. This allows the group members to read all users and groups in the domain, facilitating enumeration (BloodHound).",
    "response_steps": [
      "1. VERIFY: Is there a legacy app requirement?",
      "2. REVERT: Remove immediately to prevent recon."
    ]
  },
  { 
    "id": "ACC_859_WINDOWS_AUTH_ACCESS_ADD", 
    "title": "Add to Windows Authorization Access Group", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Windows Authorization Access Group*", "*/add*"] } },
    "description": "Detects addition to 'Windows Authorization Access Group'. Members can read the tokenGroupsGlobalAndUniversal attribute, aiding in recon.",
    "response_steps": [
      "1. VERIFY: Authorization.",
      "2. REVERT: Remove if unauthorized."
    ]
  },
  { 
    "id": "ACC_860_TERMINAL_SERVER_LICENSE_ADD", 
    "title": "Add to Terminal Server License Servers", 
    "severity": "HIGH", 
    "module": "PRIVILEGE_ESCALATION", 
    "mitre": ["T1098"], 
    "detection": { "selection": { "process.command_line": ["*net localgroup*", "*Terminal Server License Servers*", "*/add*"] } },
    "description": "Detects addition to 'Terminal Server License Servers'. Attackers can use membership here to influence licensing or potentially gain deeper access depending on patch levels.",
    "response_steps": [
      "1. VERIFY: Is this a license server?",
      "2. REVERT: Remove if unauthorized."
    ]
  }
];