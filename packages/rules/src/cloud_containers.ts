import { Rule } from '@neonshapeshifter/logtower-engine';

export const CLOUD_CONTAINER_RULES: Rule[] = [
  {
    "id": "CONT_501_DOCKER_PRIV",
    "title": "Docker Privileged Container",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1611"],
    "detection": {
      "selection": {
        "process.image": "*docker.exe",
        "process.command_line": ["*run*", "*--privileged*"]
      }
    }
  },
  {
    "id": "CONT_502_DOCKER_MOUNT_ROOT",
    "title": "Docker Mounting Host Root",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1611"],
    "detection": {
      "selection": {
        "process.image": "*docker.exe",
        "process.command_line": ["*-v C::*", "*-v /:*"]
      }
    }
  },
  {
    "id": "CONT_503_KUBECTL_EXEC",
    "title": "Kubectl Exec (Shell in Container)",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1609"],
    "detection": {
      "selection": {
        "process.image": "*kubectl.exe",
        "process.command_line": ["*exec*", "*-it*", "*/bin/sh*", "*/bin/bash*"]
      }
    }
  },
  {
    "id": "CONT_504_WSL_HOST_ACCESS",
    "title": "WSL Accessing Host Files",
    "severity": "HIGH",
    "module": "COLLECTION",
    "mitre": ["T1202"],
    "detection": {
      "selection": {
        "process.image": "*wsl.exe",
        "process.command_line": ["*cp /mnt/c/*", "*cat /mnt/c/*"]
      }
    }
  },
  {
    "id": "CONT_505_DOCKER_SOCK",
    "title": "Docker Socket Exposure",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1611"],
    "detection": {
      "selection": {
        "process.command_line": ["*-v /var/run/docker.sock:*", "*//./pipe/docker_engine*"]
      }
    }
  },
  {
    "id": "BROW_506_CHROME_DEBUG",
    "title": "Chrome Remote Debugging",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.image": "*chrome.exe",
        "process.command_line": "*--remote-debugging-port=*"
      }
    }
  },
  {
    "id": "BROW_507_EDGE_DEBUG",
    "title": "Edge Remote Debugging",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.image": "*msedge.exe",
        "process.command_line": "*--remote-debugging-port=*"
      }
    }
  },
  {
    "id": "BROW_508_MALICIOUS_EXT",
    "title": "Browser Loading Unpacked Extension",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1176"],
    "detection": {
      "selection": {
        "process.image": ["*chrome.exe", "*msedge.exe"],
        "process.command_line": "*--load-extension=*"
      }
    }
  },
  {
    "id": "BROW_509_HEADLESS_MODE",
    "title": "Browser Headless Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1185"],
    "detection": {
      "selection": {
        "process.image": ["*chrome.exe", "*msedge.exe", "*firefox.exe"],
        "process.command_line": ["*--headless*", "*-headless*"]
      }
    }
  },
  {
    "id": "BROW_510_DISABLING_SECURITY",
    "title": "Browser Disabling Web Security",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*--disable-web-security*", "*--allow-file-access-from-files*"]
      }
    }
  },
  {
    "id": "USB_511_EXEC_REMOVABLE",
    "title": "Execution from Removable Drive",
    "severity": "MEDIUM",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1091"],
    "detection": {
      "selection": {
        "process.image": ["D:*.exe", "E:*.exe", "F:*.exe", "G:*.exe"],
        "//process.image_path": ["!*\\Device\\HarddiskVolume*"] 
      }
    }
  },
  {
    "id": "USB_512_USB_SPREADER",
    "title": "USB Worm Behavior (Copy to Root)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1091"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy *.exe *: *", "*copy *.lnk *: *"]
      }
    }
  },
  {
    "id": "USB_513_MOUNTPOINTS2",
    "title": "Registry MountPoints2 Abuse",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2*",
        "registry.details": "*shell*\\command*"
      }
    }
  },
  {
    "id": "USB_514_IMAGELOAD_USB",
    "title": "DLL Loaded from USB",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1574.002"],
    "detection": {
      "selection": {
        "image_load.file_path": ["D:*.dll", "E:*.dll", "F:*.dll"]
      }
    }
  },
  {
    "id": "USB_515_EXFIL_TO_USB",
    "title": "Potential Exfiltration to USB",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1052.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*copy * D:*", "*xcopy * E:*", "*robocopy * F:*"]
      }
    }
  },
  {
    "id": "RDP_516_REG_ENABLE",
    "title": "RDP Enabled via Registry",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Control\\Terminal Server\\fDenyTSConnections",
        "registry.details": "0"
      }
    }
  },
  {
    "id": "RDP_517_ALLOW_FIREWALL",
    "title": "RDP Allowed in Firewall",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.004"],
    "detection": {
      "selection": {
        "process.command_line": ["*netsh*advfirewall*set rule*Remote Desktop*enable*", "*action=allow*protocol=TCP*localport=3389*"]
      }
    }
  },
  {
    "id": "RDP_518_REVERSE_RDP",
    "title": "Reverse RDP Tunneling (Plink/Ssh)",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": {
      "selection": {
        "process.command_line": ["*:3389:127.0.0.1:3389*", "*:3389:localhost:3389*"]
      }
    }
  },
  {
    "id": "RDP_519_SHADOW_SESSION",
    "title": "RDP Shadow Session (Spying)",
    "severity": "CRITICAL",
    "module": "COLLECTION",
    "mitre": ["T1113"],
    "detection": {
      "selection": {
        "process.command_line": ["*mstsc*", "*/shadow:*", "*/control*"]
      }
    }
  },
  {
    "id": "RDP_520_STICKY_KEYS_RDP",
    "title": "Sticky Keys Over RDP",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.008"],
    "detection": {
      "selection": {
        "process.parent_image": "*winlogon.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"],
        "process.command_line": "*sethc*"
      }
    }
  },
  {
    "id": "INST_521_MSI_URL",
    "title": "MSI Install from URL",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.image": "*msiexec.exe",
        "process.command_line": ["*http:*", "*https:*"]
      }
    }
  },
  {
    "id": "INST_522_MSI_QUIET_SYSTEM",
    "title": "MSI Quiet Install as System",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.image": "*msiexec.exe",
        "process.command_line": ["*/q*", "*/qn*"],
        "user.name": "SYSTEM"
      }
    }
  },
  {
    "id": "INST_523_MSI_TEMP",
    "title": "MSI Executing from Temp",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1218.007"],
    "detection": {
      "selection": {
        "process.image": "*msiexec.exe",
        "process.command_line": ["*\\AppData\\Local\\Temp*", "*\\Windows\\Temp*"]
      }
    }
  },
  {
    "id": "INST_524_RUNONCE_INSTALLER",
    "title": "RunOnceEx Registry Abuse",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1547.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx*"
      }
    }
  },
  {
    "id": "INST_525_ALWAYS_INSTALL_ELEVATED",
    "title": "AlwaysInstallElevated Policy",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1548.002"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\AlwaysInstallElevated",
        "registry.details": "1"
      }
    }
  },
  {
    "id": "AZ_526_AZ_CLI_LOGIN",
    "title": "Azure CLI Login Attempt",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1589"],
    "detection": {
      "selection": {
        "process.image": ["*az.exe", "*az.cmd"],
        "process.command_line": "*login*"
      }
    }
  },
  {
    "id": "AZ_527_AZ_VM_RUN_COMMAND",
    "title": "Azure VM Run Command",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.command_line": ["*az vm run-command*"]
      }
    }
  },
  {
    "id": "AZ_528_WAAGENT_ABUSE",
    "title": "Windows Azure Agent Suspicious Child",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.parent_image": "*WaAppAgent.exe",
        "process.image": ["*powershell.exe", "*cmd.exe"]
      }
    }
  },
  {
    "id": "AZ_529_METADATA_SERVICE",
    "title": "Azure Metadata Service Access",
    "severity": "CRITICAL",
    "module": "CRED",
    "mitre": ["T1552"],
    "detection": {
      "selection": {
        "process.command_line": ["*169.254.169.254*", "*metadata.json*"]
      }
    }
  },
  {
    "id": "OFF_530_OUTLOOK_VBA_ENABLE",
    "title": "Outlook VBA Security Disabled",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "registry.target_object": "*\\Security\\Level",
        "registry.details": "1"
      }
    }
  },
  {
    "id": "WMI_531_WIN32_PROCESS_CREATE",
    "title": "WMI Win32_Process Create",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmic*", "*process call create*"]
      }
    }
  },
  {
    "id": "WMI_532_SHADOWCOPY_DEL",
    "title": "WMIC Delete ShadowCopy",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmic*", "*shadowcopy*", "*delete*"]
      }
    }
  },
  {
    "id": "WMI_533_OS_RECON",
    "title": "WMIC OS Reconnaissance",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmic*", "*os get*"]
      }
    }
  },
  {
    "id": "WMI_534_USER_RECON",
    "title": "WMIC User Account Recon",
    "severity": "LOW",
    "module": "DISCOVERY",
    "mitre": ["T1087"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmic*", "*useraccount list*"]
      }
    }
  },
  {
    "id": "WMI_535_STARTUP_LIST",
    "title": "WMIC Startup List Recon",
    "severity": "MEDIUM",
    "module": "DISCOVERY",
    "mitre": ["T1083"],
    "detection": {
      "selection": {
        "process.command_line": ["*wmic*", "*startup list*"]
      }
    }
  },
  {
    "id": "MISC_536_WERFAULT_SUSP",
    "title": "WerFault Suspicious Parent",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": "*WerFault.exe",
        "process.parent_image": ["!*svchost.exe", "!*wermgr.exe"]
      }
    }
  },
  {
    "id": "MISC_537_CONHOST_CHILD",
    "title": "Conhost.exe Suspicious Parent",
    "severity": "MEDIUM",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.image": "*conhost.exe",
        "process.parent_image": ["!*cmd.exe", "!*powershell.exe", "!*csrss.exe", "!*svchost.exe"]
      }
    }
  },
  {
    "id": "MISC_538_TASKMGR_PARENT",
    "title": "Taskmgr Spawning Unknown",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.parent_image": "*taskmgr.exe",
        "process.image": ["!*taskmgr.exe", "!*mmc.exe", "!*resmon.exe"]
      }
    }
  },
  {
    "id": "MISC_539_DLLHOST_NET",
    "title": "DllHost.exe Network Connection",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*dllhost.exe",
        "network.dst_ip": "*"
      }
    }
  },
  {
    "id": "MISC_540_NOTEPAD_NET",
    "title": "Notepad.exe Network Connection",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1071"],
    "detection": {
      "selection": {
        "process.image": "*notepad.exe",
        "network.dst_ip": "*"
      }
    }
  },
  {
    "id": "SHIM_541_SDBINST",
    "title": "Sdbinst.exe Shim Installation",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.011"],
    "detection": {
      "selection": {
        "process.image": "*sdbinst.exe"
      }
    }
  },
  {
    "id": "SHIM_542_CUSTOM_SHIM",
    "title": "Custom Shim Database File",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.011"],
    "detection": {
      "selection": {
        "file.name": "*.sdb",
        "process.image": "*sdbinst.exe"
      }
    }
  },
  {
    "id": "DRV_543_DRIVER_SIGN_OFF",
    "title": "Disabling Driver Signature Enforcement",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*nointegritychecks ON*", "*testsigning ON*"]
      }
    }
  },
  {
    "id": "EVT_544_EVENT_SERVICE_STOP",
    "title": "Stopping EventLog Service",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*net stop eventlog*", "*sc stop eventlog*"]
      }
    }
  },
  {
    "id": "PRT_545_PRINTER_DRIVER_ADD",
    "title": "Suspicious Printer Driver Add",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1547"],
    "detection": {
      "selection": {
        "process.command_line": ["*rundll32*", "*printui.dll*", "*PrintUIEntry*"]
      }
    }
  },
  {
    "id": "WMI_546_MOFCOMP",
    "title": "Mofcomp.exe MOF Compilation",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "process.image": "*mofcomp.exe"
      }
    }
  },
  {
    "id": "COM_547_MMC_SPAWN",
    "title": "MMC Spawning Shell",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059"],
    "detection": {
      "selection": {
        "process.parent_image": "*mmc.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    }
  },
  {
    "id": "COM_548_SERVICES_SPAWN_CMD",
    "title": "Services.exe Spawning CMD",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1543.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*services.exe",
        "process.image": ["*cmd.exe", "*%COMSPEC%*"]
      }
    }
  },
  {
    "id": "COM_549_WINLOGON_SPAWN",
    "title": "Winlogon Spawning Shell (Non-Userinit)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1547.004"],
    "detection": {
      "selection": {
        "process.parent_image": "*winlogon.exe",
        "process.image": ["*cmd.exe", "*powershell.exe"]
      }
    }
  },
  {
    "id": "HUNT_550_ETW_TRACE_STOP",
    "title": "Stopping ETW Trace Session",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.002"],
    "detection": {
      "selection": {
        "process.command_line": ["*logman*", "*stop*", "*trace*"]
      }
    }
  }
];
