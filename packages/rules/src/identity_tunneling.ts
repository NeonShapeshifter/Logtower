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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  }
];
