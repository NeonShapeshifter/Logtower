import { Rule } from '@neonshapeshifter/logtower-engine';

export const NETWORK_DEFENSE_RULES: Rule[] = [
  {
    "id": "PRX_451_PSIPHON",
    "title": "Psiphon Censorship Bypass Tool",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": ["*psiphon3.exe", "*psiphon-tunnel-core.exe"]
      }
    },
    "description": "Psiphon execution detected. This tool is used to bypass censorship and firewalls, creating an encrypted tunnel out of the network.",
    "response_steps": [
      "1. POLICY: Is this software allowed?",
      "2. NETWORK: Check traffic volume to Psiphon nodes."
    ]
  },
  {
    "id": "PRX_452_TOR_BROWSER",
    "title": "Tor Browser/Service Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090.003"],
    "detection": {
      "selection": {
        "process.image": ["*tor.exe", "*firefox.exe"],
        "process.command_line": ["*Tor Browser*", "*--class \"Tor Browser\"*"]
      }
    },
    "description": "Tor Browser execution detected. Connects to the Tor network, hiding traffic and destination.",
    "response_steps": [
      "1. ISOLATE: Potential data exfiltration or dark web access.",
      "2. CHECK: User intent."
    ]
  },
  {
    "id": "PRX_453_ULTRASURF",
    "title": "Ultrasurf Proxy Tool",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": ["*u*.exe", "*ut*.exe"],
        "process.command_line": ["*ultrasurf*", "*u.exe*"]
      }
    },
    "description": "Ultrasurf execution detected. A proxy tool used to bypass firewalls.",
    "response_steps": [
      "1. ISOLATE: Unauthorized proxy usage."
    ]
  },
  {
    "id": "PRX_454_PROTONVPN",
    "title": "ProtonVPN Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*ProtonVPN.exe"
      }
    },
    "description": "ProtonVPN client execution.",
    "response_steps": [
      "1. POLICY: Unauthorized VPN?"
    ]
  },
  {
    "id": "PRX_455_OPENVPN_PORTABLE",
    "title": "OpenVPN Portable Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*openvpn.exe",
        "process.command_line": ["*--config*", "*.ovpn*"]
      }
    },
    "description": "OpenVPN execution with a config file. Could be a legitimate VPN or a malicious tunnel.",
    "response_steps": [
      "1. CONFIG: Check the .ovpn file for destination."
    ]
  },
  {
    "id": "PRX_456_WIREGUARD",
    "title": "WireGuard Tunnel Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*wireguard.exe"
      }
    },
    "description": "WireGuard VPN client execution.",
    "response_steps": [
      "1. POLICY: Unauthorized VPN?"
    ]
  },
  {
    "id": "PRX_457_SOFTETHER",
    "title": "SoftEther VPN Client",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": ["*vpnclient.exe", "*vpncmd.exe"]
      }
    },
    "description": "SoftEther VPN client execution. Powerful multi-protocol VPN.",
    "response_steps": [
      "1. ISOLATE: Check for unauthorized tunneling."
    ]
  },
  {
    "id": "PRX_458_SHADOWSOCKS",
    "title": "Shadowsocks Proxy Client",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*shadowsocks*.exe"
      }
    },
    "description": "Shadowsocks client execution. SOCKS5 proxy designed to bypass censorship.",
    "response_steps": [
      "1. ISOLATE: Unauthorized proxy."
    ]
  },
  {
    "id": "PRX_459_WINDSCRIBE",
    "title": "Windscribe VPN",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*Windscribe.exe"
      }
    },
    "description": "Windscribe VPN client execution.",
    "response_steps": [
      "1. POLICY: Unauthorized VPN?"
    ]
  },
  {
    "id": "PRX_460_HOTSPOT_SHIELD",
    "title": "Hotspot Shield VPN",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": {
      "selection": {
        "process.image": "*HSSCP.exe"
      }
    },
    "description": "Hotspot Shield VPN client execution.",
    "response_steps": [
      "1. POLICY: Unauthorized VPN?"
    ]
  },
  {
    "id": "IMP_461_ATEXEC",
    "title": "Impacket Atexec",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1053.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*cmd.exe /C * > * 2>&1*", "*schtasks.exe /create * /tn *"]
      }
    },
    "description": "Detection of Impacket's atexec.py behavior (Scheduled Task creation + output redirection).",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: Lateral movement confirmed."
    ]
  },
  {
    "id": "IMP_462_SMBEXEC",
    "title": "Impacket Smbexec",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.command_line": ["*execute.bat*", "*%COMSPEC% /Q /c echo* ^> \\127.0.0.1C$*"]
      }
    },
    "description": "Detection of Impacket's smbexec.py. Executes commands via a service that runs a batch file.",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: Lateral movement confirmed."
    ]
  },
  {
    "id": "IMP_463_WMIEXEC",
    "title": "Impacket Wmiexec Output",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.command_line": ["*cmd.exe /Q /c * \\127.0.0.1ADMIN$*", "* 2>&1"]
      }
    },
    "description": "Detection of Impacket's wmiexec.py output redirection pattern.",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: Lateral movement confirmed."
    ]
  },
  {
    "id": "IMP_464_DCOMEXEC",
    "title": "Impacket Dcomexec",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1021.003"],
    "detection": {
      "selection": {
        "process.command_line": ["*cmd.exe /Q /c * > \\127.0.0.1ADMIN$*"]
      }
    },
    "description": "Detection of Impacket's dcomexec.py behavior.",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: Lateral movement confirmed."
    ]
  },
  {
    "id": "IMP_465_CRACKMAPEXEC",
    "title": "CrackMapExec/NetExec Activity",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1021.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*cmd.exe /c echo * > *ADMIN$*"]
      }
    },
    "description": "Detection of CrackMapExec (CME) or NetExec command execution.",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: Mass spreading tool."
    ]
  },
  {
    "id": "IMP_466_EVIL_WINRM",
    "title": "Evil-WinRM Execution",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1021.006"],
    "detection": {
      "selection": {
        "process.command_line": "*Invoke-Expression*Evil-WinRM*"
      }
    },
    "description": "Detection of Evil-WinRM script execution.",
    "response_steps": [
      "1. SOURCE: Identify attacker IP.",
      "2. ISOLATE: WinRM access compromise."
    ]
  },
  {
    "id": "IMP_467_REMCOM",
    "title": "RemCom (Open Source PsExec)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.image": "*RemCom.exe"
      }
    },
    "description": "RemCom execution detected. PsExec alternative.",
    "response_steps": [
      "1. CONTEXT: Admin or attacker?"
    ]
  },
  {
    "id": "IMP_468_PAEXEC",
    "title": "PAExec Execution",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.image": "*PAExec.exe"
      }
    },
    "description": "PAExec execution detected. PsExec alternative.",
    "response_steps": [
      "1. CONTEXT: Admin or attacker?"
    ]
  },
  {
    "id": "IMP_469_WINEXE",
    "title": "Winexe Execution",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.image": "*winexe.exe",
        "process.command_line": "*--runas*"
      }
    },
    "description": "Winexe execution detected. Linux-to-Windows lateral movement tool.",
    "response_steps": [
      "1. SOURCE: Attacker is likely on a Linux host."
    ]
  },
  {
    "id": "IMP_470_MIMIKATZ_REMOTE",
    "title": "Mimikatz Remote Execution",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "process.command_line": ["*mimikatz*", "*sekurlsa*", "*lsadump*"]
      }
    },
    "description": "Mimikatz detected in command line arguments.",
    "response_steps": [
      "1. ISOLATE: Credential theft."
    ]
  },
  {
    "id": "STG_471_7ZIP_PASSWORD",
    "title": "7-Zip Password Protected Archive",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1560.001"],
    "detection": {
      "selection": {
        "process.image": "*7z*.exe",
        "process.command_line": ["* -p*", "* -v*m"]
      }
    },
    "description": "Creating a password protected 7zip archive. Often used to encrypt stolen data before exfiltration.",
    "response_steps": [
      "1. FILE: Identify the archive created.",
      "2. CONTENTS: What data is inside?"
    ]
  },
  {
    "id": "STG_472_RAR_CLI",
    "title": "Rar.exe Command Line Staging",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1560.001"],
    "detection": {
      "selection": {
        "process.image": "*rar.exe",
        "process.command_line": ["* a *", "* -hp*"]
      }
    },
    "description": "Rar.exe creating an archive with encryption (-hp).",
    "response_steps": [
      "1. CHECK: Data staging for exfil."
    ]
  },
  {
    "id": "STG_473_WINRAR_CLI",
    "title": "WinRAR Staging",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1560.001"],
    "detection": {
      "selection": {
        "process.image": "*WinRAR.exe",
        "process.command_line": ["* a *", "* -p*"]
      }
    },
    "description": "WinRAR.exe creating an encrypted archive.",
    "response_steps": [
      "1. CHECK: Data staging."
    ]
  },
  {
    "id": "STG_474_PS_COMPRESS",
    "title": "PowerShell Compress-Archive",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1560"],
    "detection": {
      "selection": {
        "process.command_line": ["*Compress-Archive*", "* -DestinationPath *"]
      }
    },
    "description": "PowerShell compressing files. Can be legitimate or staging.",
    "response_steps": [
      "1. SOURCE: What files are being zipped?"
    ]
  },
  {
    "id": "STG_475_MAKECAB",
    "title": "Makecab Staging",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1560"],
    "detection": {
      "selection": {
        "process.image": "*makecab.exe",
        "process.command_line": "*.cab"
      }
    },
    "description": "Using makecab.exe to compress files.",
    "response_steps": [
      "1. CHECK: Data staging."
    ]
  },
  {
    "id": "STG_476_COMPACT",
    "title": "Compact.exe Compression",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1560"],
    "detection": {
      "selection": {
        "process.image": "*compact.exe",
        "process.command_line": "*/c*"
      }
    },
    "description": "Using compact.exe to compress files.",
    "response_steps": [
      "1. CHECK: Data staging."
    ]
  },
  {
    "id": "STG_477_TAR",
    "title": "Tar.exe Staging",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1560.001"],
    "detection": {
      "selection": {
        "process.image": "*tar.exe",
        "process.command_line": ["* -c *", "* -f *"]
      }
    },
    "description": "Using native tar.exe to archive files.",
    "response_steps": [
      "1. CHECK: Data staging."
    ]
  },
  {
    "id": "STG_478_ROBOCOPY_TEMP",
    "title": "Robocopy to Temp",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1567"],
    "detection": {
      "selection": {
        "process.image": "*robocopy.exe",
        "process.command_line": ["*Temp*", "*Downloads*"]
      }
    },
    "description": "Robocopy moving files to a temporary directory. Staging for exfiltration.",
    "response_steps": [
      "1. CHECK: What data is being moved?"
    ]
  },
  {
    "id": "STG_479_COPY_ADMIN_SHARE",
    "title": "Copy to Admin Share",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy * *ADMIN$*", "*copy * *C$*"]
      }
    },
    "description": "Copying files to admin shares (ADMIN$, C$). Lateral movement artifact.",
    "response_steps": [
      "1. FILE: What file was copied (payload)?"
    ]
  },
  {
    "id": "STG_480_LARGE_FILE_TEMP",
    "title": "Suspicious Archive in Temp",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1560"],
    "detection": {
      "selection": {
        "file.name": ["*.zip", "*.rar", "*.7z", "*.tar.gz"],
        "file.path": ["*AppDataLocalTemp*", "*WindowsTemp*"]
      }
    },
    "description": "Creation of archive files in Temp folders.",
    "response_steps": [
      "1. CHECK: Exfiltration staging."
    ]
  },
  {
    "id": "SIG_481_WHOAMI_ALL",
    "title": "Whoami /All (Recon)",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1033"],
    "detection": {
      "selection": {
        "process.image": "*whoami.exe",
        "process.command_line": "*/all*"
      }
    },
    "description": "Execution of 'whoami /all'. Enumerates user groups and privileges.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_482_NET_USER_DOMAIN",
    "title": "Net User Domain Recon",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1087.002"],
    "detection": {
      "selection": {
        "process.image": "*net.exe",
        "process.command_line": ["*user*", "*/domain*"]
      }
    },
    "description": "Enumerating domain users.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_483_NET_GROUP_ADMINS",
    "title": "Net Group Domain Admins Recon",
    "severity": "HIGH",
    "module": "DISCOVERY",
    "mitre": ["T1087.002"],
    "detection": {
      "selection": {
        "process.image": "*net.exe",
        "process.command_line": ["*group*", "*domain admins*"]
      }
    },
    "description": "Enumerating Domain Admins group members.",
    "response_steps": [
      "1. CONTEXT: Targeted recon."
    ]
  },
  {
    "id": "SIG_484_NLTEST_TRUSTS",
    "title": "Nltest Domain Trusts",
    "severity": "HIGH",
    "module": "DISCOVERY",
    "mitre": ["T1482"],
    "detection": {
      "selection": {
        "process.image": "*nltest.exe",
        "process.command_line": ["*/domain_trusts*", "*/parentdomain*"]
      }
    },
    "description": "Enumerating domain trusts with nltest.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_485_NLTEST_DCLIST",
    "title": "Nltest DC List",
    "severity": "HIGH",
    "module": "DISCOVERY",
    "mitre": ["T1482"],
    "detection": {
      "selection": {
        "process.image": "*nltest.exe",
        "process.command_line": "*/dclist*"
      }
    },
    "description": "Enumerating Domain Controllers.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_486_SYSTEMINFO",
    "title": "Systeminfo Execution",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1082"],
    "detection": {
      "selection": {
        "process.image": "*systeminfo.exe"
      }
    },
    "description": "System information discovery.",
    "response_steps": [
      "1. CONTEXT: Patch level checking?"
    ]
  },
  {
    "id": "SIG_487_IPCONFIG_ALL",
    "title": "Ipconfig All (Recon)",
    "severity": "INFO",
    "module": "DISCOVERY",
    "mitre": ["T1016"],
    "detection": {
      "selection": {
        "process.image": "*ipconfig.exe",
        "process.command_line": "*/all*"
      }
    },
    "description": "Network configuration discovery.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_488_QUSER",
    "title": "Quser Session Discovery",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1033"],
    "detection": {
      "selection": {
        "process.image": "*quser.exe"
      }
    },
    "description": "Enumerating logged on users.",
    "response_steps": [
      "1. CONTEXT: Lateral movement prep."
    ]
  },
  {
    "id": "SIG_489_QWINSTA",
    "title": "Qwinsta Session Discovery",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1033"],
    "detection": {
      "selection": {
        "process.image": "*qwinsta.exe"
      }
    },
    "description": "Enumerating RDP sessions.",
    "response_steps": [
      "1. CONTEXT: Lateral movement prep."
    ]
  },
  {
    "id": "SIG_490_NETSTAT_ANO",
    "title": "Netstat Port Discovery",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1049"],
    "detection": {
      "selection": {
        "process.image": "*netstat.exe",
        "process.command_line": ["*-ano*", "*-anb*"]
      }
    },
    "description": "Enumerating active connections.",
    "response_steps": [
      "1. CONTEXT: Recon."
    ]
  },
  {
    "id": "SIG_491_KLIST_PURGE",
    "title": "Klist Purge Tickets",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1550"],
    "detection": {
      "selection": {
        "process.image": "*klist.exe",
        "process.command_line": "*purge*"
      }
    },
    "description": "Purging Kerberos tickets. Used before injecting new tickets (PTT) or cleaning up.",
    "response_steps": [
      "1. CHECK: Ticket manipulation?"
    ]
  },
  {
    "id": "SIG_492_TASKKILL_IM",
    "title": "Taskkill Security Tool",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.image": "*taskkill.exe",
        "process.command_line": ["*/im *", "*/f *"]
      }
    },
    "description": "Forcefully killing a process by name.",
    "response_steps": [
      "1. TARGET: What process was killed?"
    ]
  },
  {
    "id": "SIG_493_FLTMC_UNLOAD",
    "title": "Fltmc Unload Driver",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.image": "*fltmc.exe",
        "process.command_line": "*unload*"
      }
    },
    "description": "Unloading a filesystem filter driver (e.g., EDR/AV).",
    "response_steps": [
      "1. ISOLATE: Defense evasion."
    ]
  },
  {
    "id": "SIG_494_AUDITPOL_CLEAR",
    "title": "Auditpol Clear Policy",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.002"],
    "detection": {
      "selection": {
        "process.image": "*auditpol.exe",
        "process.command_line": ["*/clear*", "*/remove*"]
      }
    },
    "description": "Clearing audit policies.",
    "response_steps": [
      "1. ISOLATE: Disabling logging."
    ]
  },
  {
    "id": "SIG_495_SC_STOP",
    "title": "SC Stop Service",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.image": "*sc.exe",
        "process.command_line": "*stop*"
      }
    },
    "description": "Stopping a service via SC.",
    "response_steps": [
      "1. TARGET: What service?"
    ]
  },
  {
    "id": "SIG_496_NET_STOP",
    "title": "Net Stop Service",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.image": "*net.exe",
        "process.command_line": "*stop*"
      }
    },
    "description": "Stopping a service via Net.",
    "response_steps": [
      "1. TARGET: What service?"
    ]
  },
  {
    "id": "SIG_497_REG_DELETE",
    "title": "Reg Delete Key",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1112"],
    "detection": {
      "selection": {
        "process.image": "*reg.exe",
        "process.command_line": "*delete*"
      }
    },
    "description": "Deleting a registry key.",
    "response_steps": [
      "1. TARGET: What key?"
    ]
  },
  {
    "id": "SIG_498_CMDKEY_LIST",
    "title": "Cmdkey List Credentials",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003"],
    "detection": {
      "selection": {
        "process.image": "*cmdkey.exe",
        "process.command_line": "*/list*"
      }
    },
    "description": "Listing stored credentials.",
    "response_steps": [
      "1. CHECK: Credential dumping."
    ]
  },
  {
    "id": "SIG_499_VAULTCMD_LIST",
    "title": "Vaultcmd List Credentials",
    "severity": "HIGH",
    "module": "CRED",
    "mitre": ["T1003.004"],
    "detection": {
      "selection": {
        "process.image": "*vaultcmd.exe",
        "process.command_line": "*/list*"
      }
    },
    "description": "Listing Vault credentials.",
    "response_steps": [
      "1. CHECK: Credential dumping."
    ]
  },
  {
    "id": "SIG_500_WEVTUTIL_CL_AGAIN",
    "title": "Wevtutil Clear Log (Repeated)",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
        "process.image": "*wevtutil.exe",
        "process.command_line": ["*cl *", "*clear-log*"]
      }
    },
    "description": "Clearing logs.",
    "response_steps": [
      "1. ISOLATE: Anti-forensics."
    ]
  }
];
