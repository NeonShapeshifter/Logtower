import { Rule } from '@neonshapeshifter/logtower-engine';

export const IDENTITY_TUNNELING_RULES: Rule[] = [
  {
    "id": "KERB_251_ROASTING_RC4",
    "title": "Kerberoasting (RC4 TGS Request)",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1558.003"],
    "detection": {
      "selection": {
        "event_id": "4769",
        "kerberos.ticket_encryption": "0x17",
        "kerberos.ticket_options": "0x40810000"
      }
    },
    "description": "A Kerberos TGS request was made using weak RC4 encryption (0x17). This is the signature of a Kerberoasting attack, where attackers request tickets for service accounts to crack their passwords offline.",
    "response_steps": [
      "1. SOURCE: Identify the user and IP requesting the ticket.",
      "2. TARGET: Which service account was targeted? Reset its password immediately.",
      "3. SCOPE: Check if multiple service tickets were requested in a short time."
    ]
  },
  {
    "id": "KERB_252_ASREP_ROASTING",
    "title": "AS-REP Roasting (No Pre-Auth)",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1558.004"],
    "detection": {
      "selection": {
        "event_id": "4768",
        "kerberos.ticket_encryption": "0x17",
        "kerberos.pre_auth_type": "0"
      }
    },
    "description": "A Kerberos TGT request was made without Pre-Authentication. This allows an attacker to receive an encrypted TGT for any user with 'Do not require Kerberos preauthentication' enabled, and crack it offline.",
    "response_steps": [
      "1. USER: Identify the vulnerable user account.",
      "2. FIX: Enable 'Require Kerberos Preauthentication' in AD for this user.",
      "3. RESET: Force a password reset for the user."
    ]
  },
  {
    "id": "KERB_253_PWD_SPRAY_FAIL",
    "title": "Password Spraying Failure (PreAuth)",
    "severity": "MEDIUM",
    "module": "CRED",
    "mitre": ["T1110.003"],
    "detection": {
      "selection": {
        "event_id": "4771",
        "kerberos.failure_code": "0x18"
      }
    },
    "description": "Kerberos Pre-Authentication failed (Bad Password). A single event is a typo, but many events for DIFFERENT users from the SAME source indicate Password Spraying.",
    "response_steps": [
      "1. SOURCE: Identify the source IP performing the spray.",
      "2. BLOCK: Block the IP at the firewall.",
      "3. MONITOR: Watch for successful logins (4624) from that IP immediately following the failures."
    ]
  },
  {
    "id": "KERB_254_PWD_SPRAY_ACCOUNT",
    "title": "Password Spraying (Unknown User)",
    "severity": "LOW",
    "module": "CRED",
    "mitre": ["T1110.003"],
    "detection": {
      "selection": {
        "event_id": "4771",
        "kerberos.failure_code": "0x6"
      }
    },
    "description": "Kerberos Pre-Authentication failed because the Username does not exist. High volume indicates user enumeration or spraying against an old user list.",
    "response_steps": [
      "1. SOURCE: Identify the attacker's IP.",
      "2. LIST: Check which usernames they are trying (are they guessing pattern-based names?)."
    ]
  },
  {
    "id": "KERB_255_GOLDEN_TICKET",
    "title": "Potential Golden Ticket Usage",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1558.001"],
    "detection": {
      "selection": {
        "event_id": "4624",
        "auth.logon_guid": "{00000000-0000-0000-0000-000000000000}",
        "user.logon_type": "3"
      }
    },
    "description": "A logon event occurred with a Logon GUID of all zeros. This is a known artifact of some Golden Ticket (Forged TGT) tools like Mimikatz when default settings are used.",
    "response_steps": [
      "1. CRITICAL: Your domain is likely fully compromised (KRBTGT hash stolen).",
      "2. EXECUTE: Initiate KRBTGT password rotation cycle (reset twice).",
      "3. ISOLATE: Identify and isolate the source machine."
    ]
  },
  {
    "id": "KERB_256_SKEW_ERROR",
    "title": "Kerberos Time Skew (Potential Attack)",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1070"],
    "detection": {
      "selection": {
        "event_id": "4771",
        "kerberos.failure_code": "0x25"
      }
    },
    "description": "Kerberos authentication failed due to time skew (>5 minutes). While often a config issue, attackers modifying system time to forge tickets or bypass time-based restrictions can trigger this.",
    "response_steps": [
      "1. CHECK: Verify NTP settings on the source.",
      "2. CONTEXT: If accompanied by other Kerberos errors, investigate for replay attacks."
    ]
  },
  {
    "id": "KERB_257_EXPIRED_TICKET",
    "title": "Kerberos Expired Ticket Usage",
    "severity": "MEDIUM",
    "module": "CRED",
    "mitre": ["T1558"],
    "detection": {
      "selection": {
        "event_id": "4769",
        "kerberos.failure_code": "0x20"
      }
    },
    "description": "A TGS request failed because the TGT was expired. Attackers trying to reuse stolen tickets (Pass-the-Ticket) often encounter this if they don't renew them.",
    "response_steps": [
      "1. USER: Which user account had the expired ticket?",
      "2. SOURCE: Is this user actually present on the source machine?"
    ]
  },
  {
    "id": "KERB_258_DELEGATION_SENSITIVE",
    "title": "Sensitive Delegation usage",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1558"],
    "detection": {
      "selection": {
        "event_id": "4769",
        "kerberos.service_name": "*krbtgt*",
        "kerberos.ticket_options": "*0x40800000*"
      }
    },
    "description": "A TGS request was made with the 'Constrained Delegation' option set. If unexpected, this could indicate an attacker abusing delegation to impersonate users.",
    "response_steps": [
      "1. SERVICE: Identify the service requesting delegation.",
      "2. TARGET: Who is being impersonated?"
    ]
  },
  {
    "id": "KERB_259_HONEYTOKEN",
    "title": "Honeytoken Account Activity",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1074"],
    "detection": {
      "selection": {
        "event_id": ["4768", "4769", "4624"],
        "user.target_name": ["*HoneyUser*", "*FakeAdmin*"]
      }
    },
    "description": "Activity detected on a Honeytoken account (a trap account that should never be used). Any activity here is a confirmed intrusion.",
    "response_steps": [
      "1. ALARM: Confirmed human adversary in the network.",
      "2. SOURCE: Identify the source IP immediately.",
      "3. ISOLATE: Isolate the source host."
    ]
  },
  {
    "id": "KERB_260_ENCRYPTION_DOWNGRADE",
    "title": "Kerberos Encryption Downgrade",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1558"],
    "detection": {
      "selection": {
        "event_id": "4768",
        "kerberos.ticket_encryption": ["0x1", "0x3"]
      }
    },
    "description": "Kerberos authentication using weak encryption (DES). Attackers downgrade encryption to crack tickets easier.",
    "response_steps": [
      "1. CHECK: Is this a legacy system (Win 2003/XP)?",
      "2. INVESTIGATE: If modern OS, this is an attack."
    ]
  },
  {
    "id": "TUN_261_PLINK_REMOTE",
    "title": "Plink Remote Port Forwarding",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.image": "*plink.exe",
        "process.command_line": "*-R *"
      }
    },
    "description": "Plink executing with '-R'. This creates a Remote Port Forward (Reverse Tunnel), allowing the attacker to access internal services (like RDP) from the outside.",
    "response_steps": [
      "1. KILL: Terminate the process.",
      "2. NETWORK: Identify the C2 server IP.",
      "3. SCOPE: What internal port was exposed?"
    ]
  },
  {
    "id": "TUN_262_PLINK_LOCAL",
    "title": "Plink Local Port Forwarding",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.image": "*plink.exe",
        "process.command_line": "*-L *"
      }
    },
    "description": "Plink executing with '-L'. This creates a Local Port Forward, allowing the attacker to tunnel traffic FROM their machine TO an internal service via the compromised host.",
    "response_steps": [
      "1. KILL: Terminate the process.",
      "2. CHECK: What internal resource is being accessed?"
    ]
  },
  {
    "id": "TUN_263_SSH_TUNNEL",
    "title": "SSH Tunneling Detected",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.image": "*ssh.exe",
        "process.command_line": ["*-R *", "*-L *", "*-D *"]
      }
    },
    "description": "Standard OpenSSH client used for tunneling (-R remote, -L local, -D dynamic SOCKS proxy).",
    "response_steps": [
      "1. ISOLATE: SSH tunnels bypass firewall rules.",
      "2. IDENTIFY: Destination of the tunnel."
    ]
  },
  {
    "id": "TUN_264_CHISEL_CLIENT",
    "title": "Chisel Tunneling Client",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.command_line": ["*chisel* client *", "*chisel* server *"]
      }
    },
    "description": "Usage of Chisel, a fast TCP/UDP tunnel over HTTP. Preferred by attackers for its speed and ability to bypass proxies.",
    "response_steps": [
      "1. ISOLATE: Confirmed tunneling tool.",
      "2. BLOCK: Block the server IP.",
      "3. HUNT: Check for the chisel binary dropped on disk."
    ]
  },
  {
    "id": "TUN_265_NGROK_EXEC",
    "title": "Ngrok Tunnel Execution",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.image": "*ngrok.exe"
      }
    },
    "description": "Execution of Ngrok. Creates a public URL pointing to a service on the local machine (e.g., exposing RDP 3389 to the internet).",
    "response_steps": [
      "1. KILL: Stop the process.",
      "2. NETWORK: Check DNS logs for ngrok.io connections.",
      "3. SCOPE: What port was being forwarded?"
    ]
  },
  {
    "id": "TUN_266_SOCAT_EXEC",
    "title": "Socat Relay Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*socat.exe"
      }
    },
    "description": "Socat execution. 'Swiss army knife' for networking, used to relay traffic between two points.",
    "response_steps": [
      "1. ARGS: Analyze arguments to understand the relay config.",
      "2. ISOLATE: Tool used for pivoting."
    ]
  },
  {
    "id": "TUN_267_FRP_TUNNEL",
    "title": "FRP Reverse Proxy",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": ["*frpc.exe", "*frps.exe"]
      }
    },
    "description": "Fast Reverse Proxy (FRP) detected. Common in modern ransomware ops for persistence and C2.",
    "response_steps": [
      "1. CONFIG: Look for frpc.ini to see the server address.",
      "2. BLOCK: Block the server IP."
    ]
  },
  {
    "id": "TUN_268_CLOUDFLARED",
    "title": "Cloudflared Tunnel Abuse",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.image": "*cloudflared.exe",
        "process.command_line": "* tunnel run *"
      }
    },
    "description": "Cloudflare Tunnel (cloudflared) usage. Valid for admins, but abused by attackers to bypass inbound firewall rules.",
    "response_steps": [
      "1. VERIFY: Is this an authorized tunnel?",
      "2. INSPECT: Check the tunnel ID and destination."
    ]
  },
  {
    "id": "TUN_269_PORTPROXY_ADD",
    "title": "Netsh PortProxy Added",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*netsh.exe",
        "process.command_line": ["*interface*", "*portproxy*", "*add*", "*v4tov4*"]
      }
    },
    "description": "Windows native 'netsh interface portproxy' used to forward traffic. Often used to pivot RDP traffic from a compromised host to another internal server.",
    "response_steps": [
      "1. LIST: 'netsh interface portproxy show all'.",
      "2. DELETE: 'netsh interface portproxy delete ...'",
      "3. TARGET: Identify the pivot target."
    ]
  },
  {
    "id": "TUN_270_LOCALHOST_CONNECT",
    "title": "Suspicious Localhost Connection",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "network.dst_ip": "127.0.0.1",
        "process.image": ["*rundll32.exe", "*regsvr32.exe", "*powershell.exe"]
      }
    },
    "description": "A system process connecting to 127.0.0.1. This often indicates a local tunnel (SOCKS proxy) listener running on the machine.",
    "response_steps": [
      "1. PORT: Which port on localhost?",
      "2. PROCESS: Identify the process listening on that port (netstat -ano)."
    ]
  },
  {
    "id": "PTH_271_LOGON_TYPE_9",
    "title": "Pass-the-Hash (Logon Type 9)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1550.002"],
    "detection": {
      "selection": {
        "event_id": "4624",
        "user.logon_type": "9",
        "raw.LogonProcessName": "seclogon"
      }
    },
    "description": "Logon Type 9 (NewCredentials) indicates usage of 'runas /netonly'. This is the specific signature of Pass-the-Hash attacks where credentials are injected for network access only.",
    "response_steps": [
      "1. SOURCE: Identify the process that initiated the logon.",
      "2. USER: Which user is being impersonated?"
    ]
  },
  {
    "id": "PTH_272_SEKURLSA_PTH",
    "title": "Mimikatz Sekurlsa::pth",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1550.002"],
    "detection": {
      "selection": {
        "process.command_line": "*sekurlsa::pth*"
      }
    },
    "description": "Mimikatz command to perform Pass-the-Hash. Injects an NTLM hash into memory to create a new logon session.",
    "response_steps": [
      "1. ISOLATE: Mimikatz execution confirmed.",
      "2. RESET: The target account's hash is compromised. Reset password."
    ]
  },
  {
    "id": "PTH_273_OVERPASS_RC4",
    "title": "OverPass-the-Hash (RC4 Downgrade)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1550.002"],
    "detection": {
      "selection": {
        "event_id": "4768",
        "kerberos.ticket_encryption": "0x17",
        "network.src_ip": ["!::1", "!127.0.0.1"]
      }
    },
    "description": "An RC4 encrypted TGT request from a remote machine. Modern Windows uses AES. Forcing RC4 suggests an attacker using an NTLM hash to request a TGT (OverPass-the-Hash).",
    "response_steps": [
      "1. VERIFY: Is the source a legacy Windows 2003/XP machine?",
      "2. INVESTIGATE: If a modern machine, it's an attack."
    ]
  },
  {
    "id": "PTH_274_WMI_PTH",
    "title": "WMI Pass-the-Hash (Impacket)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1550.002"],
    "detection": {
      "selection": {
        "process.parent_image": "*wmiprvse.exe",
        "process.command_line": "*cmd.exe /Q /c * \\127.0.0.1/*"
      }
    },
    "description": "Impacket wmiexec.py using Pass-the-Hash. It executes commands via WMI and redirects output to the local admin share.",
    "response_steps": [
      "1. SOURCE: Identify the lateral movement source.",
      "2. ISOLATE: The source machine has admin credentials for this target."
    ]
  },
  {
    "id": "PTH_275_MIMIKATZ_CMD",
    "title": "Mimikatz Command Line",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "process.command_line": ["*privilege::debug*", "*lsadump::*", "*kerberos::list*"]
      }
    },
    "description": "Common Mimikatz commands detected in command line arguments.",
    "response_steps": [
      "1. ISOLATE: Credential dumping tool.",
      "2. INVESTIGATE: Assume all creds in memory are stolen."
    ]
  },
  {
    "id": "PTH_276_RUBEUS_EXEC",
    "title": "Rubeus Execution",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1550"],
    "detection": {
      "selection": {
        "process.command_line": ["*Rubeus.exe*", "* asktgt *", "* monitor *", "* kerberoast *"]
      }
    },
    "description": "Execution of Rubeus, a C# toolset for raw Kerberos interaction and abuses.",
    "response_steps": [
      "1. ISOLATE: Advanced Kerberos attack tool.",
      "2. CHECK: Did they export tickets (base64 blobs)?"
    ]
  },
  {
    "id": "PTH_277_KEBEO_EXEC",
    "title": "Kekeo Execution",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1550"],
    "detection": {
      "selection": {
        "process.command_line": ["*kekeo.exe*", "* tgt::*"]
      }
    },
    "description": "Execution of Kekeo, another tool by the creator of Mimikatz for Kerberos manipulation.",
    "response_steps": [
      "1. ISOLATE: Kerberos attack tool."
    ]
  },
  {
    "id": "PTH_278_SAFETYKATZ",
    "title": "SafetyKatz Execution",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "process.command_line": "*SafetyKatz*"
      }
    },
    "description": "SafetyKatz is a modified version of Mimikatz that dumps LSASS memory via MiniDumpWriteDump to avoid detection.",
    "response_steps": [
      "1. ISOLATE: Credential dumping."
    ]
  },
  {
    "id": "PTH_279_RUNAS_NETONLY",
    "title": "RunAs NetOnly (Potential PTH)",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1134"],
    "detection": {
      "selection": {
        "process.command_line": "*/netonly*"
      }
    },
    "description": "Usage of 'runas /netonly'. While valid for admins, it's the mechanism used by tools like Mimikatz to inject credentials without logging on locally.",
    "response_steps": [
      "1. CONTEXT: Admin workflow or malicious?"
    ]
  },
  {
    "id": "PTH_280_FRESH_CREDS",
    "title": "Network Logon with New Credentials",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1550"],
    "detection": {
      "selection": {
        "event_id": "4624",
        "user.logon_type": "3",
        "auth.auth_package": "NTLM",
        "auth.workstation": "WORKSTATION"
      }
    },
    "description": "Network logon (Type 3) using NTLM where the workstation name is generic ('WORKSTATION'). Tools like Impacket often use this default.",
    "response_steps": [
      "1. SOURCE: Check source IP.",
      "2. PATTERN: Is it scanning multiple hosts?"
    ]
  },
  {
    "id": "ZERO_281_ANON_PWD_CHANGE",
    "title": "Zerologon (Anonymous Password Change)",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "event_id": "4742",
        "user.name": "ANONYMOUS LOGON"
      }
    },
    "description": "Event 4742 showing 'ANONYMOUS LOGON' changing a computer account password. This is the smoking gun for Zerologon (CVE-2020-1472).",
    "response_steps": [
      "1. EMERGENCY: The domain is compromised. The DC password was reset to empty.",
      "2. RESTORE: You must restore the DC machine account password.",
      "3. PATCH: Apply CVE-2020-1472 patch immediately."
    ]
  },
  {
    "id": "ZERO_282_NETLOGON_AUTH_FAIL",
    "title": "Netlogon Auth Failure (Zerologon)",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1068"],
    "detection": {
      "selection": {
        "event_id": "5805",
        "raw.Error": "*C0000225*"
      }
    },
    "description": "Netlogon authentication failure with specific error. High volume of these indicates a Zerologon brute-force attempt.",
    "response_steps": [
      "1. SOURCE: Identify and block source IP.",
      "2. PATCH: Ensure DCs are patched."
    ]
  },
  {
    "id": "ZERO_283_DCSYNC",
    "title": "DCSync Attack (DS-Replication)",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.006"],
    "detection": {
      "selection": {
        "event_id": "4662",
        "raw.Properties": ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"]
      }
    },
    "description": "Access to 'DS-Replication-Get-Changes' extended rights. This indicates a DCSync attack where an attacker simulates a DC to pull password hashes.",
    "response_steps": [
      "1. USER: Identify the user account performing DCSync.",
      "2. ISOLATE: If not a DC machine account or AADConnect, it's an attack.",
      "3. RESET: Reset KRBTGT."
    ]
  },
  {
    "id": "ZERO_284_MACHINE_ACC_USAGE",
    "title": "Suspicious Machine Account Usage",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1078"],
    "detection": {
      "selection": {
        "event_id": "4624",
        "user.name": "*$",
        "network.src_ip": ["!::1", "!127.0.0.1"]
      }
    },
    "description": "A machine account (ending in $) logged in from a DIFFERENT IP than expected. Machine accounts should authenticate from their own IP.",
    "response_steps": [
      "1. SPOOFING: Potential Silver Ticket or machine account theft.",
      "2. INVESTIGATE: Correlate IP with hostname."
    ]
  },
  {
    "id": "ZERO_285_SAM_DUMP",
    "title": "SAM Database Access",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.002"],
    "detection": {
      "selection": {
        "event_id": "4656",
        "raw.ObjectName": "*\\SAM"
      }
    },
    "description": "Handle requested for the SAM database file. Indicates an attempt to dump local password hashes.",
    "response_steps": [
      "1. PROCESS: Who requested the handle?",
      "2. ISOLATE: Credential theft."
    ]
  },
  {
    "id": "ZERO_286_LSASS_CLONE",
    "title": "LSASS Clone Created",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003.001"],
    "detection": {
      "selection": {
        "process.image": "*lsass.exe",
        "process.command_line": "*clone*"
      }
    },
    "description": "LSASS process cloning detected. Some tools clone the process to dump memory from the clone safely without crashing the system.",
    "response_steps": [
      "1. ISOLATE: Advanced dumping technique.",
      "2. RESET: Reset creds."
    ]
  },
  {
    "id": "ZERO_287_PRINTNIGHTMARE",
    "title": "PrintNightmare Suspicious File",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "image_load.file_path": "*\\spool\\drivers*"
      }
    },
    "description": "Suspicious DLL load from spool drivers directory. Signature of PrintNightmare exploitation.",
    "response_steps": [
      "1. ISOLATE: Potential SYSTEM compromise via Print Spooler.",
      "2. DISABLE: Disable Print Spooler service."
    ]
  },
  {
    "id": "ZERO_288_PETITPOTAM",
    "title": "PetitPotam EFS Abuse",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1187"],
    "detection": {
      "selection": {
        "event_id": "5145",
        "raw.ShareName": "*\\IPC$",
        "raw.RelativeTargetName": "lsarpc"
      }
    },
    "description": "Suspicious access to lsarpc pipe on IPC$. Could be PetitPotam coercing authentication.",
    "response_steps": [
      "1. PATCH: Ensure EFS updates are applied.",
      "2. MONITOR: Watch for machine account authentication triggered by this."
    ]
  },
  {
    "id": "NET_289_PS_BEACON",
    "title": "PowerShell Beacon to Web Port",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071.001"],
    "detection": {
      "selection": {
        "process.image": ["*powershell.exe", "*pwsh.exe"],
        "network.dst_port": ["80", "443", "8080"]
      }
    },
    "description": "PowerShell making persistent connections to web ports. Typical C2 beacon behavior.",
    "response_steps": [
      "1. FREQUENCY: Check connection interval (Beaconing?).",
      "2. URL: Check the URL accessed (Proxy logs)."
    ]
  },
  {
    "id": "NET_290_CMD_BEACON",
    "title": "CMD Beacon to Web Port",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071.001"],
    "detection": {
      "selection": {
        "process.image": "*cmd.exe",
        "network.dst_port": ["80", "443"]
      }
    },
    "description": "Command Prompt making web connections. Very suspicious, cmd.exe is not a browser.",
    "response_steps": [
      "1. PARENT: What spawned cmd?",
      "2. ISOLATE: Likely reverse shell."
    ]
  },
  {
    "id": "NET_291_RUNDLL_BEACON",
    "title": "Rundll32 Beacon to Web Port",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071.001"],
    "detection": {
      "selection": {
        "process.image": "*rundll32.exe",
        "network.dst_port": ["80", "443"]
      }
    },
    "description": "Rundll32 making web connections. Often Cobalt Strike or other DLL-based malware.",
    "response_steps": [
      "1. COMMAND: Check which DLL is loaded.",
      "2. ISOLATE: High confidence threat."
    ]
  },
  {
    "id": "NET_292_REGSVR_BEACON",
    "title": "Regsvr32 Beacon to Web Port",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071.001"],
    "detection": {
      "selection": {
        "process.image": "*regsvr32.exe",
        "network.dst_port": ["80", "443"]
      }
    },
    "description": "Regsvr32 making web connections (Squiblydoo).",
    "response_steps": [
      "1. COMMAND: Check for .sct file in arguments.",
      "2. BLOCK: C2 communication."
    ]
  },
  {
    "id": "NET_293_TOR_BEACON",
    "title": "Connection to TOR Ports",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090.003"],
    "detection": {
      "selection": {
        "network.dst_port": ["9001", "9050", "9150"]
      }
    },
    "description": "Connection to known TOR ports. Malware often uses TOR for anonymity.",
    "response_steps": [
      "1. CHECK: Is TOR usage authorized?",
      "2. ISOLATE: Likely C2 or dark web access."
    ]
  },
  {
    "id": "NET_294_JAVA_BEACON",
    "title": "Java Suspicious Outbound",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*java.exe",
        "network.dst_port": ["!80", "!443", "!8080"]
      }
    },
    "description": "Java process connecting to non-web ports. Could be Log4Shell callback.",
    "response_steps": [
      "1. IP: Check destination reputation.",
      "2. SERVER: Check Java application logs."
    ]
  },
  {
    "id": "NET_295_UNKNOWN_BIN_BEACON",
    "title": "Unknown Binary in Temp Beaconing",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": ["*\\AppData\\Local\\Temp*", "*\\Users\\Public*"],
        "network.dst_port": ["80", "443"]
      }
    },
    "description": "Binary running from Temp/Public making web connections. Classic malware behavior.",
    "response_steps": [
      "1. SAMPLE: Retrieve binary.",
      "2. ISOLATE: High probability of malware."
    ]
  },
  {
    "id": "NET_296_NON_STD_PORT",
    "title": "Common Tool Non-Standard Port",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1041"],
    "detection": {
      "selection": {
        "process.image": ["*powershell.exe", "*cmd.exe"],
        "network.dst_port": ["!80", "!443", "!53", "!8080"]
      }
    },
    "description": "Powershell/CMD connecting to weird ports (e.g., 4444).",
    "response_steps": [
      "1. PORT: 4444? Metasploit.",
      "2. ISOLATE: C2 connection."
    ]
  },
  {
    "id": "NET_297_MSHTA_NET",
    "title": "Mshta Network Connection",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1218.005"],
    "detection": {
      "selection": {
        "process.image": "*mshta.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "Mshta.exe making network connection. Likely executing remote HTA.",
    "response_steps": [
      "1. URL: Identify source.",
      "2. ISOLATE: Malware execution."
    ]
  },
  {
    "id": "NET_298_CERTUTIL_NET",
    "title": "Certutil Network Connection",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": {
      "selection": {
        "process.image": "*certutil.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "Certutil making network connection. Used for downloading artifacts.",
    "response_steps": [
      "1. COMMAND: Check arguments.",
      "2. BLOCK: Domain blocked?"
    ]
  },
  {
    "id": "NET_299_HH_NET",
    "title": "HH.exe Network Connection",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1218.001"],
    "detection": {
      "selection": {
        "process.image": "*hh.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "Help Host (hh.exe) making network connection. Malicious CHM file.",
    "response_steps": [
      "1. FILE: Identify CHM file.",
      "2. ISOLATE: Execution confirmed."
    ]
  },
  {
    "id": "NET_300_REGASM_NET",
    "title": "RegAsm Network Connection",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1218.009"],
    "detection": {
      "selection": {
        "process.image": "*regasm.exe",
        "network.dst_ip": "*"
      }
    },
    "description": "RegAsm making network connection. Sign of code injection/execution.",
    "response_steps": [
      "1. ISOLATE: C2 beacon."
    ]
  }
];