import { Rule } from '@neonshapeshifter/logtower-engine';

export const WEB_RANSOMWARE_RULES: Rule[] = [
  {
    "id": "WEB_401_IIS_SPAWN_CMD",
    "title": "IIS W3WP Spawning CMD",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1505.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*w3wp.exe",
        "process.image": ["*cmd.exe", "*%COMSPEC%*"]
      }
    },
    "description": "Detects the IIS worker process (w3wp.exe) spawning a command shell. This is a classic indicator of a web shell or successful exploitation of a web vulnerability (e.g., SQL Injection, RCE).",
    "response_steps": [
      "1. ISOLATE: Take the web server offline or isolate it at the network level.",
      "2. ANALYZE: Check the command line of the spawned cmd.exe to see the attacker's intent.",
      "3. IDENTIFY: Locate the malicious file (web shell) in the web root directories.",
      "4. LOGS: Review IIS logs for unusual POST requests to the same directory."
    ]
  },
  {
    "id": "WEB_402_IIS_SPAWN_PS",
    "title": "IIS W3WP Spawning PowerShell",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1505.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*w3wp.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    },
    "description": "Detects the IIS worker process spawning PowerShell. This often indicates advanced web shell activity or 'fileless' malware execution via a web vulnerability.",
    "response_steps": [
      "1. ISOLATE: Immediate network isolation of the web server.",
      "2. ANALYZE: Inspect PowerShell Script Block Logs (4104) for the executed code.",
      "3. SEARCH: Look for newly created .aspx or .ashx files in the web application folders.",
      "4. RECOVERY: Restore the web application from a known good backup."
    ]
  },
  {
    "id": "WEB_403_TOMCAT_SPAWN",
    "title": "Tomcat Spawning Shell",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1190"],
    "detection": {
      "selection": {
        "process.parent_image": ["*tomcat*.exe", "*httpd.exe"],
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Detects Java/Tomcat or Apache processes spawning shells. This usually indicates exploitation of vulnerabilities like Log4Shell or upload of a malicious WAR file.",
    "response_steps": [
      "1. ISOLATE: Stop the Tomcat service and isolate the server.",
      "2. INSPECT: Check the 'webapps' folder for unauthorized WAR files or modified JSP files.",
      "3. LOGS: Review Tomcat/Apache access logs for large payloads or suspicious URLs."
    ]
  },
  {
    "id": "WEB_404_EXCHANGE_SPAWN",
    "title": "Exchange Spawning Shell (ProxyShell)",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1190"],
    "detection": {
      "selection": {
        "process.parent_image": "*UMWorkerProcess.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Detects Microsoft Exchange processes spawning shells. This is a high-confidence indicator of ProxyShell or ProxyLogon exploitation.",
    "response_steps": [
      "1. ISOLATE: Disconnect the Exchange server from the internet.",
      "2. PATCH: Ensure all Exchange security updates are applied.",
      "3. HUNT: Look for web shells in 'InternalProxy' and 'ExternalProxy' directories.",
      "4. AUDIT: Check for unauthorized mailbox exports or changes to Transport Rules."
    ]
  },
  {
    "id": "WEB_405_SQL_SPAWN",
    "title": "SQL Server Spawning Shell (xp_cmdshell)",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1190"],
    "detection": {
      "selection": {
        "process.parent_image": "*sqlservr.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Detects SQL Server spawning a shell. This usually indicates the abuse of 'xp_cmdshell' after a successful SQL injection or credential compromise.",
    "response_steps": [
      "1. DISABLE: Immediately disable 'xp_cmdshell' in SQL Server configuration.",
      "2. ANALYZE: Identify the SQL user account used to execute the command.",
      "3. SCOPE: Check if the SQL service account has local admin privileges (it shouldn't).",
      "4. REVERT: Change passwords for all SQL accounts."
    ]
  },
  {
    "id": "WEB_406_PHP_SPAWN",
    "title": "PHP Spawning Shell",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1190"],
    "detection": {
      "selection": {
        "process.parent_image": "*php-cgi.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Detects PHP processes spawning shells. This is often caused by PHP-based web shells or vulnerable PHP functions (system, exec, passthru).",
    "response_steps": [
      "1. ISOLATE: Isolate the web server.",
      "2. AUDIT: Review all .php files created or modified in the last 24 hours.",
      "3. HARDEN: Check php.ini for 'disable_functions' and ensure shell execution functions are restricted."
    ]
  },
  {
    "id": "WEB_407_COLDFUSION_SPAWN",
    "title": "ColdFusion Spawning Shell",
    "severity": "CRITICAL",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1190"],
    "detection": {
      "selection": {
        "process.parent_image": "*coldfusion.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    },
    "description": "Detects Adobe ColdFusion processes spawning shells, indicating potential RCE exploitation.",
    "response_steps": [
      "1. ISOLATE: Take the ColdFusion server offline.",
      "2. PATCH: Check for ColdFusion security hotfixes.",
      "3. SEARCH: Look for unauthorized .cfm or .cfml files."
    ]
  },
  {
    "id": "WEB_408_W3WP_WRITING_ASPX",
    "title": "IIS Writing ASPX File",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1505.003"],
    "detection": {
      "selection": {
        "process.image": "*w3wp.exe",
        "file.name": ["*.aspx", "*.ashx", "*.asp"]
      }
    },
    "description": "Detects the IIS worker process writing an executable web file (.aspx, etc.). This is the primary method for dropping a web shell.",
    "response_steps": [
      "1. IDENTIFY: Find the exact path of the written file.",
      "2. ANALYZE: Inspect the content of the file for malicious code.",
      "3. REVERT: Delete the file and fix the underlying vulnerability that allowed the write."
    ]
  },
  {
    "id": "WEB_409_IIS_RECON",
    "title": "IIS Process Running Recon Commands",
    "severity": "CRITICAL",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "process.parent_image": "*w3wp.exe",
        "process.image": ["*whoami.exe", "*net.exe", "*ipconfig.exe"]
      }
    },
    "description": "Detects an IIS process executing reconnaissance commands. This indicates an attacker has gained a shell and is trying to understand their environment and privileges.",
    "response_steps": [
      "1. ISOLATE: Host isolation is mandatory.",
      "2. SCOPE: Determine what information the attacker successfully gathered (check command output if available).",
      "3. HUNT: Look for subsequent lateral movement attempts."
    ]
  },
  {
    "id": "WEB_410_IIS_CERTUTIL",
    "title": "IIS Process Downloading File",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.parent_image": "*w3wp.exe",
        "process.image": ["*certutil.exe", "*bitsadmin.exe", "*curl.exe"]
      }
    },
    "description": "Detects an IIS process spawning tools used to download secondary payloads. This confirms an active breach being staged.",
    "response_steps": [
      "1. ISOLATE: Disconnect from the network.",
      "2. IDENTIFY: What was downloaded? (Check command line and proxy logs).",
      "3. RECOVER: Re-image the web server."
    ]
  },
  {
    "id": "STL_411_CHROME_LOGIN",
    "title": "Access to Chrome Login Data",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1555.003"],
    "detection": {
      "selection": {
        "file.path": "*\\User Data\\Default\\Login Data",
        "process.image": ["!*chrome.exe", "!*explorer.exe"]
      }
    },
    "description": "Detects a non-browser process accessing Chrome's stored password database. This is indicative of 'Stealer' malware (e.g., RedLine, Raccoon).",
    "response_steps": [
      "1. ISOLATE: The host is compromised by a stealer.",
      "2. RESET: Assume all passwords saved in Chrome are compromised. Reset them all (External services, VPN, Bank).",
      "3. INVESTIGATE: Identify the source process (often in Temp or Downloads)."
    ]
  },
  {
    "id": "STL_412_CHROME_COOKIES",
    "title": "Access to Chrome Cookies",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1539"],
    "detection": {
      "selection": {
        "file.path": "*\\User Data\\Default\\Cookies",
        "process.image": ["!*chrome.exe", "!*explorer.exe"]
      }
    },
    "description": "Detects unauthorized access to Chrome's cookie database. Attackers steal session cookies to bypass MFA (Session Hijacking).",
    "response_steps": [
      "1. RESET: Invalidate all active web sessions for the user.",
      "2. INVESTIGATE: Look for a malicious process running in the user context.",
      "3. MFA: Ensure FIDO2/Hardware MFA is used where possible to prevent cookie theft abuse."
    ]
  },
  {
    "id": "STL_413_EDGE_LOGIN",
    "title": "Access to Edge Login Data",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1555.003"],
    "detection": {
      "selection": {
        "file.path": "*\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        "process.image": ["!*msedge.exe", "!*explorer.exe"]
      }
    },
    "description": "Detects unauthorized access to Microsoft Edge's password database.",
    "response_steps": [
      "1. RESET: All saved passwords in Edge are compromised.",
      "2. SCAN: Run a full malware scan on the machine.",
      "3. ISOLATE: Disconnect host."
    ]
  },
  {
    "id": "STL_414_FIREFOX_COOKIES",
    "title": "Access to Firefox Cookies",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1539"],
    "detection": {
      "selection": {
        "file.name": "cookies.sqlite",
        "process.image": ["!*firefox.exe", "!*explorer.exe"]
      }
    },
    "description": "Detects unauthorized access to Firefox's cookie database (cookies.sqlite).",
    "response_steps": [
      "1. RESET: Invalidate sessions.",
      "2. INVESTIGATE: Identify process reading sqlite files in user profiles."
    ]
  },
  {
    "id": "STL_415_TELEGRAM_DATA",
    "title": "Access to Telegram Tdata",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1005"],
    "detection": {
      "selection": {
        "file.path": "*\\Telegram Desktop\\tdata*",
        "process.image": ["!*Telegram.exe"]
      }
    },
    "description": "Detects theft of Telegram session data. This allows an attacker to clone the user's Telegram session and access chats/MFA codes.",
    "response_steps": [
      "1. TERMINATE: In Telegram settings, terminate all other active sessions.",
      "2. RESET: Change Telegram account password and enable 2FA if not active.",
      "3. ISOLATE: The host has a session stealer."
    ]
  },
  {
    "id": "STL_416_DISCORD_TOKENS",
    "title": "Access to Discord LevelDB (Tokens)",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1005"],
    "detection": {
      "selection": {
        "file.path": "*\\discord\\Local Storage\\leveldb*",
        "process.image": ["!*Discord.exe"]
      }
    },
    "description": "Detects unauthorized access to Discord's token storage. Stealing Discord tokens is common for spreading malware or social engineering.",
    "response_steps": [
      "1. RESET: Change Discord password (this invalidates the current token).",
      "2. SCAN: Look for Discord-specific stealers."
    ]
  },
  {
    "id": "STL_417_OUTLOOK_PST",
    "title": "Suspicious Access to Outlook PST",
    "severity": "MEDIUM",
    "module": "COLLECTION",
    "mitre": ["T1114.001"],
    "detection": {
      "selection": {
        "file.name": ["*.pst", "*.ost"],
        "process.image": ["!*outlook.exe", "!*searchprotocolhost.exe"]
      }
    },
    "description": "Detects access to Outlook data files by non-standard processes. This indicates email exfiltration.",
    "response_steps": [
      "1. ANALYZE: What process is reading the PST file? (e.g., 7zip.exe, rclone.exe).",
      "2. PREVENT: Block the process and check for large outbound network transfers."
    ]
  },
  {
    "id": "STL_418_KEYCHAIN_ACCESS",
    "title": "Access to Windows Vault/Creds",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.004"],
    "detection": {
      "selection": {
        "file.path": "*\\AppData\\Local\\Microsoft\\Credentials*",
        "process.image": ["!*lsass.exe", "!*svchost.exe"]
      }
    },
    "description": "Detects unauthorized access to the Windows Credential Manager storage files.",
    "response_steps": [
      "1. RESET: Reset Windows account password and any saved credentials (RDP, Network shares).",
      "2. ISOLATE: Host is compromised."
    ]
  },
  {
    "id": "STL_419_SSH_KEYS",
    "title": "Access to SSH Keys",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1552.004"],
    "detection": {
      "selection": {
        "file.path": "*\\.ssh\\id_rsa*",
        "process.image": ["!*ssh.exe", "!*git.exe"]
      }
    },
    "description": "Detects a process reading private SSH keys. This allows an attacker to move laterally to Linux/Cloud infrastructure.",
    "response_steps": [
      "1. REVOKE: Immediately revoke the compromised SSH keys on all target servers.",
      "2. GENERATE: Create new keys with strong passphrases.",
      "3. INVESTIGATE: Determine which process read the key."
    ]
  },
  {
    "id": "STL_420_AWS_CREDS",
    "title": "Access to AWS Credentials",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1552.001"],
    "detection": {
      "selection": {
        "file.path": "*\\.aws\\credentials*",
        "process.image": ["!*aws.exe"]
      }
    },
    "description": "Detects theft of AWS CLI credentials. This can lead to a full Cloud infrastructure compromise.",
    "response_steps": [
      "1. REVOKE: Immediately deactivate the AWS Access Key IDs found in that file.",
      "2. AUDIT: Review AWS CloudTrail logs for unusual activity from those keys in the last hour.",
      "3. ENFORCE: Use IAM Roles and MFA for AWS CLI."
    ]
  },
  {
    "id": "RANS_421_CIPHER_WIPE",
    "title": "Cipher.exe Wiping Space",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1485"],
    "detection": {
      "selection": {
        "process.image": "*cipher.exe",
        "process.command_line": ["*/w:*"]
      }
    },
    "description": "Detects cipher.exe being used to wipe free disk space. Ransomware uses this to make file recovery impossible after encryption.",
    "response_steps": [
      "1. TERMINATE: Kill the cipher.exe process immediately.",
      "2. ALERT: This is a strong indicator that encryption has already occurred or is finishing.",
      "3. RECOVER: Start restoration from offline backups."
    ]
  },
  {
    "id": "RANS_422_FSUTIL_USN",
    "title": "Fsutil Delete USN Journal",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1070.004"],
    "detection": {
      "selection": {
        "process.image": "*fsutil.exe",
        "process.command_line": ["*usn*", "*deletejournal*"]
      }
    },
    "description": "Detects deletion of the USN Change Journal. Attackers do this to hide file activity and delete forensic evidence.",
    "response_steps": [
      "1. INVESTIGATE: Why was the journal deleted? This is not a standard admin task.",
      "2. ISOLATE: The host may be undergoing a ransomware attack."
    ]
  },
  {
    "id": "RANS_423_STOP_SQL",
    "title": "Stopping SQL Services (Ransomware)",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.command_line": ["*net stop MSSQL*", "*stop *SQL*"]
      }
    },
    "description": "Detects stopping SQL services. Ransomware stops database services to release file locks so it can encrypt the database files.",
    "response_steps": [
      "1. RESTART: Try to restart services and check for file encryption (.locked, .encrypted).",
      "2. ISOLATE: Disconnect the database server.",
      "3. AUDIT: Check for other ransomware indicators (shadow copy deletion)."
    ]
  },
  {
    "id": "RANS_424_STOP_VEEAM",
    "title": "Stopping Veeam Backup (Ransomware)",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.command_line": ["*net stop Veeam*", "*stop *Veeam*"]
      }
    },
    "description": "Detects stopping backup services. This is a critical step in a ransomware attack to prevent restoration.",
    "response_steps": [
      "1. CRITICAL: This is a high-confidence ransomware prep signal.",
      "2. ISOLATE: Isolate the backup server immediately.",
      "3. PROTECT: Ensure offline/immutable backups are secure."
    ]
  },
  {
    "id": "RANS_425_DEL_BACKUP_FILES",
    "title": "Deletion of Backup Files",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1485"],
    "detection": {
      "selection": {
        "process.command_line": ["*del *.vbk*", "*del *.bkp*", "*del *.vhd*"]
      }
    },
    "description": "Detects the deletion of common backup and virtual disk files.",
    "response_steps": [
      "1. STOP: Kill the process performing the deletion.",
      "2. ISOLATE: Isolate the host.",
      "3. RECOVER: Use immutable/offline backups."
    ]
  },
  {
    "id": "RANS_426_SHADOW_COPY_RESIZE",
    "title": "Shadow Copy Resize (Evasion)",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*vssadmin*", "*Resize ShadowStorage*"]
      }
    },
    "description": "Detects resizing the Shadow Copy storage to a very small size, effectively deleting existing shadow copies. Used by ransomware to prevent 'Previous Versions' recovery.",
    "response_steps": [
      "1. ALERT: Ransomware activity in progress.",
      "2. ISOLATE: Isolate the host.",
      "3. CHECK: Verify if files are already encrypted."
    ]
  },
  {
    "id": "RANS_427_BOOT_CONFIG_EDIT",
    "title": "BCDEdit Recovery Disable",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*recoveryenabled No*", "*ignoreallfailures*"]
      }
    },
    "description": "Detects disabling Windows recovery options. Ransomware does this to prevent the user from using 'Startup Repair' or 'Safe Mode' after the system is compromised.",
    "response_steps": [
      "1. ALERT: Attacker is preparing for a final payload or system lockdown.",
      "2. ISOLATE: Disconnect the host."
    ]
  },
  {
    "id": "RANS_428_WBADMIN_DELETE",
    "title": "WBAdmin Backup Deletion",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*wbadmin*", "*delete catalog*"]
      }
    },
    "description": "Detects deletion of the Windows Backup catalog. Used to prevent system restoration.",
    "response_steps": [
      "1. CRITICAL: High-fidelity ransomware signal.",
      "2. ISOLATE: Isolate the system immediately."
    ]
  },
  {
    "id": "RANS_429_WEVTUTIL_CLEAR",
    "title": "Wevtutil Log Clearing",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*wevtutil*", "* cl *"]
      }
    },
    "description": "Detects clearing of Windows Event Logs. Used to cover tracks and delete evidence of the breach.",
    "response_steps": [
      "1. INVESTIGATE: Identify the account that cleared the logs.",
      "2. SIEM: Check your central log management (SIEM) for the logs that were deleted locally.",
      "3. ISOLATE: Host is likely compromised."
    ]
  },
  {
    "id": "RANS_430_ICACLS_GRANT",
    "title": "Icacls Grant Everyone (Ransomware)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1222.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*icacls*", "*/grant*", "*Everyone:F*"]
      }
    },
    "description": "Detects granting full permissions to 'Everyone'. Ransomware does this to ensure it can encrypt every file on the disk regardless of original owner.",
    "response_steps": [
      "1. ALERT: Attacker is preparing for mass file modification.",
      "2. ISOLATE: Isolate the host."
    ]
  },
  {
    "id": "BYOVD_431_CAPCOM_SYS",
    "title": "Capcom Vulnerable Driver Load",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": ["Capcom.sys", "capcom.sys"]
      }
    },
    "description": "Detects the loading of the Capcom.sys driver, which contains a deliberate 'feature' that allows any user to execute code as SYSTEM. A classic BYOVD (Bring Your Own Vulnerable Driver) attack.",
    "response_steps": [
      "1. ISOLATE: Immediate isolation.",
      "2. IDENTIFY: What process loaded the driver? (often a mapper like kdmapper).",
      "3. KILL: Terminate the loader process and delete the .sys file."
    ]
  },
  {
    "id": "BYOVD_432_WINRING0_SYS",
    "title": "WinRing0 Driver Load (Miner/Exploit)",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": ["WinRing0.sys", "WinRing0x64.sys"]
      }
    },
    "description": "Detects the WinRing0 driver, often used by crypto-miners and exploits to access low-level hardware or escalate privileges.",
    "response_steps": [
      "1. ANALYZE: Check for associated mining processes (XMRig).",
      "2. DELETE: Remove the driver and the process that loaded it."
    ]
  },
  {
    "id": "BYOVD_433_GENSHIN_DRIVER",
    "title": "Mhyprot2 Driver Load (Anti-AV)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "image_load.file_name": "mhyprot2.sys"
      }
    },
    "description": "Detects the loading of mhyprot2.sys (Genshin Impact anti-cheat driver). This driver is abused by ransomware (e.g., BlackCat) to kill AV/EDR processes from kernel mode.",
    "response_steps": [
      "1. CRITICAL: Security software is being targeted.",
      "2. ISOLATE: Isolate the host immediately.",
      "3. REVERT: Check if EDR services were stopped."
    ]
  },
  {
    "id": "BYOVD_434_DRIVER_IN_TEMP",
    "title": "Driver Loaded from Temp",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_path": ["*\\AppData\\Local\\Temp*.sys", "*\\Windows\\Temp*.sys"]
      }
    },
    "description": "Detects a kernel driver being loaded from a Temp directory. Legitimate drivers should never reside in Temp; this is almost certainly a BYOVD attack.",
    "response_steps": [
      "1. ISOLATE: Disconnect host.",
      "2. ANALYZE: Extract the driver file for analysis (check for known vulnerabilities).",
      "3. RECOVER: Re-image is recommended as kernel integrity is lost."
    ]
  },
  {
    "id": "BYOVD_435_DRIVER_IN_DOWNLOADS",
    "title": "Driver Loaded from Downloads",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_path": "*\\Downloads*.sys"
      }
    },
    "description": "Detects a driver loaded directly from a user's Downloads folder.",
    "response_steps": [
      "1. ISOLATE: Disconnect host.",
      "2. INVESTIGATE: Who downloaded the file? (Check browser history)."
    ]
  },
  {
    "id": "BYOVD_436_DELL_DBUTIL",
    "title": "Dell Dbutil Vulnerable Driver",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": "dbutil_2_3.sys"
      }
    },
    "description": "Detects the vulnerable Dell dbutil_2_3.sys driver, known to be used for BYOVD attacks.",
    "response_steps": [
      "1. DELETE: Remove the driver if not legitimately needed for Dell updates.",
      "2. INVESTIGATE: Process that loaded the driver."
    ]
  },
  {
    "id": "BYOVD_437_RTCORE64",
    "title": "RTCore64 Vulnerable Driver",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": "RTCore64.sys"
      }
    },
    "description": "Detects the vulnerable RTCore64.sys (MSI Afterburner) driver, used in BYOVD attacks to read/write kernel memory.",
    "response_steps": [
      "1. DELETE: Remove driver.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "BYOVD_438_GDRV_SYS",
    "title": "GDRV (Gigabyte) Vulnerable Driver",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": "gdrv.sys"
      }
    },
    "description": "Detects the vulnerable Gigabyte gdrv.sys driver.",
    "response_steps": [
      "1. DELETE: Remove driver.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "BYOVD_439_ASUS_GLCIO",
    "title": "Asus GLCIO Vulnerable Driver",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "image_load.file_name": "Asusgio2.sys"
      }
    },
    "description": "Detects the vulnerable Asusgio2.sys driver.",
    "response_steps": [
      "1. DELETE: Remove driver.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "BYOVD_440_PROCESS_HACKER",
    "title": "KProcessHacker Driver Load",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "image_load.file_name": "kprocesshacker.sys"
      }
    },
    "description": "Detects Process Hacker's kernel driver. While the tool is legitimate, attackers use it (or its driver) to kill security processes that are normally protected.",
    "response_steps": [
      "1. VERIFY: Is an admin troubleshooting?",
      "2. CHECK: Are security processes still running?"
    ]
  },
  {
    "id": "TOOL_441_ADFIND_EXEC",
    "title": "AdFind Recon Tool",
    "severity": "HIGH",
    "module": "DISCOVERY",
    "mitre": ["T1087.002"],
    "detection": {
      "selection": {
        "process.image": "*AdFind.exe",
        "process.command_line": ["* -f *", "* -b *"]
      }
    },
    "description": "AdFind is a powerful AD query tool. Execution with discovery flags is a common precursor to domain-wide ransomware deployment.",
    "response_steps": [
      "1. ISOLATE: The host is performing reconnaissance.",
      "2. ANALYZE: What was queried? (Computers, Admins, Trusted Domains).",
      "3. HUNT: Check for other tools like SharpHound or Mimikatz."
    ]
  },
  {
    "id": "TOOL_442_RCLONE_EXEC",
    "title": "Rclone Exfiltration Tool",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1567.002"],
    "detection": {
      "selection": {
        "process.image": "*rclone.exe",
        "process.command_line": ["* copy *", "* sync *", "* config *"]
      }
    },
    "description": "Detects rclone, a tool used to sync files to cloud storage. Attackers use it to exfiltrate massive amounts of data before encryption (Double Extortion).",
    "response_steps": [
      "1. TERMINATE: Kill the rclone.exe process immediately.",
      "2. BLOCK: Block common cloud storage endpoints at the firewall.",
      "3. SCOPE: Identify which folders were targeted for exfiltration."
    ]
  },
  {
    "id": "TOOL_443_ANYDESK_PORTABLE",
    "title": "AnyDesk Portable Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1219"],
    "detection": {
      "selection": {
        "process.image": ["*AnyDesk.exe", "*\\AppData\\Local\\Temp*", "*\\Downloads*"]
      }
    },
    "description": "Detects AnyDesk running from unusual locations. Attackers use remote access tools to bypass VPN/MFA and maintain persistent access.",
    "response_steps": [
      "1. TERMINATE: Kill the process.",
      "2. VERIFY: Did the user install this? (likely social engineering).",
      "3. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "TOOL_444_TEAMVIEWER_PORTABLE",
    "title": "TeamViewer Portable Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1219"],
    "detection": {
      "selection": {
        "process.image": ["*TeamViewer.exe", "*\\AppData\\Local\\Temp*", "*\\Downloads*"]
      }
    },
    "description": "Detects TeamViewer running from Temp or Downloads.",
    "response_steps": [
      "1. TERMINATE: Kill process.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "TOOL_445_MEGASYNC_EXEC",
    "title": "MEGAcmd/MEGAclient Execution",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1567.002"],
    "detection": {
      "selection": {
        "process.image": ["*MEGAcmd.exe", "*MEGAclient.exe"]
      }
    },
    "description": "Detects MEGA sync tools, frequently used for data exfiltration due to their high speed and encryption.",
    "response_steps": [
      "1. TERMINATE: Kill process.",
      "2. BLOCK: Block mega.nz domain.",
      "3. ANALYZE: Check what files were synced."
    ]
  },
  {
    "id": "TOOL_446_ADV_IP_SCANNER",
    "title": "Advanced IP Scanner (Ransomware)",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1046"],
    "detection": {
      "selection": {
        "process.image": "*advanced_ip_scanner.exe"
      }
    },
    "description": "Detects Advanced IP Scanner. While used by admins, its presence on a workstation is a common indicator of an attacker scanning for lateral movement targets.",
    "response_steps": [
      "1. VERIFY: Authorized usage?",
      "2. MONITOR: Check for RDP/SMB connection attempts from this host to others."
    ]
  },
  {
    "id": "TOOL_447_SCREENCONNECT",
    "title": "ConnectWise ScreenConnect",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1219"],
    "detection": {
      "selection": {
        "process.image": "*ScreenConnect.ClientService.exe"
      }
    },
    "description": "Detects ScreenConnect (ConnectWise Control). Heavily abused by threat actors to maintain persistent remote access.",
    "response_steps": [
      "1. VERIFY: Is this our corporate remote support tool?",
      "2. INSPECT: Check the ScreenConnect instance URL in the config files."
    ]
  },
  {
    "id": "TOOL_448_RUSTDESK",
    "title": "RustDesk Remote Access",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1219"],
    "detection": {
      "selection": {
        "process.image": "*rustdesk.exe"
      }
    },
    "description": "Detects RustDesk, an open-source remote desktop software often used as a backup C2 channel.",
    "response_steps": [
      "1. TERMINATE: Kill process.",
      "2. ISOLATE: Host isolation."
    ]
  },
  {
    "id": "TOOL_449_SPLASHTOP_STREAMER",
    "title": "Splashtop Streamer Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1219"],
    "detection": {
      "selection": {
        "process.image": "*SRStreamer.exe"
      }
    },
    "description": "Detects Splashtop Streamer, another remote access vector.",
    "response_steps": [
      "1. VERIFY: Corporate tool?",
      "2. TERMINATE: Kill if unauthorized."
    ]
  },
  {
    "id": "TOOL_450_NGROK_CONFIG",
    "title": "Ngrok Configuration File",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.command_line": ["*ngrok*", "*config*", "*authtoken*"]
      }
    },
    "description": "Detects Ngrok configuration or execution. Ngrok is used to create secure tunnels to localhost, allowing attackers to expose internal services (like RDP) to the internet without firewall changes.",
    "response_steps": [
      "1. TERMINATE: Kill ngrok process.",
      "2. BLOCK: Block ngrok.io at the firewall.",
      "3. INVESTIGATE: What local port was being tunneled?"
    ]
  }
];