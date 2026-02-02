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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  }
];
