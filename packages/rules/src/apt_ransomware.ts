import { Rule } from '@neonshapeshifter/logtower-engine';

export const APT_RANSOMWARE_RULES: Rule[] = [
  {
    "id": "WMI_201_CMD_CONSUMER",
    "title": "WMI CommandLine Consumer Created",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.destination": "*CommandLineEventConsumer*"
      }
    }
  },
  {
    "id": "WMI_201_CMD_CONSUMER_RAW",
    "title": "WMI CommandLine Consumer Created (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Type": "*CommandLineEventConsumer*"
      }
    }
  },
  {
    "id": "WMI_202_SCRIPT_CONSUMER",
    "title": "WMI ActiveScript Consumer Created",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.destination": "*ActiveScriptEventConsumer*"
      }
    }
  },
  {
    "id": "WMI_202_SCRIPT_CONSUMER_RAW",
    "title": "WMI ActiveScript Consumer Created (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Type": "*ActiveScriptEventConsumer*"
      }
    }
  },
  {
    "id": "WMI_203_BINDING",
    "title": "WMI Filter to Consumer Binding",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.operation": "*FilterToConsumerBinding*"
      }
    }
  },
  {
    "id": "WMI_203_BINDING_RAW",
    "title": "WMI Filter to Consumer Binding (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "21",
        "raw.Consumer": "*",
        "raw.Filter": "*"
      }
    }
  },
  {
    "id": "WMI_204_POWERSHELL_CONSUMER",
    "title": "WMI Consumer Executing PowerShell",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.command_line": ["*powershell*", "*pwsh*"]
      }
    }
  },
  {
    "id": "WMI_204_POWERSHELL_CONSUMER_RAW",
    "title": "WMI Consumer Executing PowerShell (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Destination": ["*powershell*", "*pwsh*"]
      }
    }
  },
  {
    "id": "WMI_205_CMD_CONSUMER_EXEC",
    "title": "WMI Consumer Executing CMD",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.command_line": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    }
  },
  {
    "id": "WMI_205_CMD_CONSUMER_EXEC_RAW",
    "title": "WMI Consumer Executing CMD (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.Destination": ["*cmd.exe*", "*%COMSPEC%*"]
      }
    }
  },
  {
    "id": "WMI_206_VBS_CONSUMER",
    "title": "WMI Consumer Executing VBS/JS",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.script_text": ["*vbscript*", "*JScript*"]
      }
    }
  },
  {
    "id": "WMI_206_VBS_CONSUMER_RAW",
    "title": "WMI Consumer Executing VBS/JS (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "20",
        "raw.ScriptText": ["*vbscript*", "*JScript*", "*jscript*"]
      }
    }
  },
  {
    "id": "WMI_207_SCRCONS_SPAWN",
    "title": "Scrcons.exe Spawning Process",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "process.parent_image": "*scrcons.exe",
        "process.image": ["*cmd.exe", "*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    "id": "WMI_208_WMI_PRVSE_SPAWN",
    "title": "Wmiprvse.exe Spawning PowerShell",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.parent_image": "*wmiprvse.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    "id": "WMI_209_KRYPTON_WMI",
    "title": "Krypton/Empire WMI Persistence",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "wmi.name": "*Updater*",
        "wmi.query": "*SELECT * FROM __InstanceModificationEvent*"
      }
    }
  },
  {
    "id": "WMI_209_KRYPTON_WMI_RAW",
    "title": "Krypton/Empire WMI Persistence (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1546.003"],
    "detection": {
      "selection": {
        "event_id": "19",
        "raw.Name": "*Updater*",
        "raw.Query": "*SELECT * FROM __InstanceModificationEvent*"
      }
    }
  },
  {
    "id": "WMI_210_IMPACKET_WMI",
    "title": "Impacket WMI Exec",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1047"],
    "detection": {
      "selection": {
        "process.parent_image": "*wmiprvse.exe",
        "process.command_line": ["*cmd.exe /Q /c *", "*cmd.exe /c *"]
      }
    }
  },

  {
    "id": "ACC_211_USER_CREATED",
    "title": "Local User Account Created",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720"
      }
    }
  },
  {
    "id": "ACC_212_ADMIN_GROUP_ADD",
    "title": "User Added to Local Administrators",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4732", "4728"],
        "group.name": ["*Administrators*", "*Administradores*"]
      }
    }
  },
  {
    "id": "ACC_212_ADMIN_GROUP_ADD_RAW",
    "title": "User Added to Local Administrators (Raw)",
    "severity": "HIGH",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4732", "4728"],
        "raw.GroupName": ["*Administrators*", "*Administradores*", "*Domain Admins*", "*Admins*", "*Administradores del dominio*"]
      }
    }
  },
  {
    "id": "ACC_213_USER_ENABLED",
    "title": "User Account Enabled",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4722"
      }
    }
  },
  {
    "id": "ACC_214_PWD_RESET",
    "title": "Password Reset Attempt",
    "severity": "MEDIUM",
    "module": "CRED",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4724",
      }
    }
  },
  {
    "id": "ACC_215_USER_DELETED",
    "title": "User Account Deleted",
    "severity": "LOW",
    "module": "DEFENSE",
    "mitre": ["T1070"],
    "detection": {
      "selection": {
        "event_id": "4726",
      }
    }
  },
  {
    "id": "ACC_216_GUEST_ENABLED",
    "title": "Guest Account Enabled",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1078"],
    "detection": {
      "selection": {
        "event_id": "4722",
        "user.target_name": ["*Guest*", "*Invitado*"]
      }
    }
  },
  {
    "id": "ACC_216_GUEST_ENABLED_RAW",
    "title": "Guest Account Enabled (Raw)",
    "severity": "HIGH",
    "module": "INITIAL_ACCESS",
    "mitre": ["T1078"],
    "detection": {
      "selection": {
        "event_id": "4722",
        "raw.TargetUserName": ["*Guest*", "*Invitado*"]
      }
    }
  },
  {
    "id": "ACC_217_SUPPORT_USER",
    "title": "Suspicious 'Support' User Created",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "user.target_name": ["*Support*", "*HelpDesk*", "*Admin*", "*Kiosk*"]
      }
    }
  },
  {
    "id": "ACC_217_SUPPORT_USER_RAW",
    "title": "Suspicious 'Support' User Created (Raw)",
    "severity": "HIGH",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "raw.TargetUserName": ["*Support*", "*HelpDesk*", "*Admin*", "*Kiosk*"]
      }
    }
  },
  {
    "id": "ACC_218_HIDDEN_USER",
    "title": "Hidden/Suspicious User Created ($)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "user.target_name": "*$*"
      }
    }
  },
  {
    "id": "ACC_218_HIDDEN_USER_RAW",
    "title": "Hidden/Suspicious User Created ($) (Raw)",
    "severity": "CRITICAL",
    "module": "PERSISTENCE",
    "mitre": ["T1136.001"],
    "detection": {
      "selection": {
        "event_id": "4720",
        "raw.TargetUserName": "*$*"
      }
    }
  },
  {
    "id": "ACC_219_SEC_GROUP_MOD",
    "title": "Security-Enabled Group Modification",
    "severity": "MEDIUM",
    "module": "PERSISTENCE",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": ["4735", "4737"],
      }
    }
  },
  {
    "id": "ACC_220_DOMAIN_ADMIN_ADD",
    "title": "Added to Domain Admins",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4728",
        "group.name": "*Domain Admins*"
      }
    }
  },
  {
    "id": "ACC_220_DOMAIN_ADMIN_ADD_RAW",
    "title": "Added to Domain Admins (Raw)",
    "severity": "CRITICAL",
    "module": "PRIVILEGE_ESCALATION",
    "mitre": ["T1098"],
    "detection": {
      "selection": {
        "event_id": "4728",
        "raw.GroupName": "*Domain Admins*"
      }
    }
  },

  {
    "id": "PIPE_221_PSEXEC",
    "title": "PsExec Named Pipe",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": ["*PSEXESVC*", "*PaExec*"]
      }
    }
  },
  {
    "id": "PIPE_221_PSEXEC_RAW",
    "title": "PsExec Named Pipe (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": ["*PSEXESVC*", "*PaExec*"]
      }
    }
  },
  {
    "id": "PIPE_222_COBALT_MOJO",
    "title": "Cobalt Strike Mojo Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*mojo.5688.8052.*"
      }
    }
  },
  {
    "id": "PIPE_222_COBALT_MOJO_RAW",
    "title": "Cobalt Strike Mojo Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*mojo.5688.8052.*"
      }
    }
  },
  {
    "id": "PIPE_223_COBALT_POSTEX",
    "title": "Cobalt Strike PostEx Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*postex_*"
      }
    }
  },
  {
    "id": "PIPE_223_COBALT_POSTEX_RAW",
    "title": "Cobalt Strike PostEx Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*postex_*"
      }
    }
  },
  {
    "id": "PIPE_224_COBALT_MSAGENT",
    "title": "Cobalt Strike MSAgent Pipe",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*msagent_*"
      }
    }
  },
  {
    "id": "PIPE_224_COBALT_MSAGENT_RAW",
    "title": "Cobalt Strike MSAgent Pipe (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*msagent_*"
      }
    }
  },
  {
    "id": "PIPE_225_SMB_LATERAL",
    "title": "SMB Lateral Movement Pipe",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1021.002"],
    "detection": {
      "selection": {
        "pipe.name": ["*atsvc*", "*samr*", "*srvsvc*"]
      }
    }
  },
  {
    "id": "PIPE_225_SMB_LATERAL_RAW",
    "title": "SMB Lateral Movement Pipe (Raw)",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1021.002"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": ["*atsvc*", "*samr*", "*srvsvc*"]
      }
    }
  },
  {
    "id": "PIPE_226_BITS_PIPE",
    "title": "BITS Service Pipe Abuse",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "pipe.name": "*BITSServer*"
      }
    }
  },
  {
    "id": "PIPE_226_BITS_PIPE_RAW",
    "title": "BITS Service Pipe Abuse (Raw)",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1197"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*BITSServer*"
      }
    }
  },
  {
    "id": "PIPE_228_WIEU_PIPE",
    "title": "WIEU Remote Exec Pipe",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1021"],
    "detection": {
      "selection": {
        "pipe.name": "*wieu_*"
      }
    }
  },
  {
    "id": "PIPE_228_WIEU_PIPE_RAW",
    "title": "WIEU Remote Exec Pipe (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1021"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*wieu_*"
      }
    }
  },
  {
    "id": "PIPE_229_STATUS_PIPE",
    "title": "Status Pipe (CS Pattern)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*status_*"
      }
    }
  },
  {
    "id": "PIPE_229_STATUS_PIPE_RAW",
    "title": "Status Pipe (CS Pattern) (Raw)",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*status_*"
      }
    }
  },
  {
    "id": "PIPE_230_DHELPER_PIPE",
    "title": "DHelper Pipe (Malware)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "pipe.name": "*dhelper_*"
      }
    }
  },
  {
    "id": "PIPE_230_DHELPER_PIPE_RAW",
    "title": "DHelper Pipe (Malware) (Raw)",
    "severity": "CRITICAL",
    "module": "LATERAL",
    "mitre": ["T1570"],
    "detection": {
      "selection": {
        "event_id": ["17", "18"],
        "raw.PipeName": "*dhelper_*"
      }
    }
  },

  {
    "id": "MASQ_231_SVCHOST",
    "title": "Masquerading Svchost.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**svchost.exe",
          "!**Windows*System32*svchost.exe",
          "!**Windows*SysWOW64*svchost.exe",
          "!**System32*svchost.exe",
          "!**SysWOW64*svchost.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_232_EXPLORER",
    "title": "Masquerading Explorer.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**explorer.exe",
          "!**Windows*explorer.exe",
          "!**Windows*SysWOW64*explorer.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_233_CSRSS",
    "title": "Masquerading Csrss.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**csrss.exe",
          "!**Windows*System32*csrss.exe",
          "!**Windows*SysWOW64*csrss.exe",
          "!**System32*csrss.exe",
          "!**SysWOW64*csrss.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_234_LSASS",
    "title": "Masquerading Lsass.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**lsass.exe",
          "!**Windows*System32*lsass.exe",
          "!**Windows*SysWOW64*lsass.exe",
          "!**System32*lsass.exe",
          "!**SysWOW64*lsass.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_235_WININIT",
    "title": "Masquerading Wininit.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**wininit.exe",
          "!**Windows*System32*wininit.exe",
          "!**Windows*SysWOW64*wininit.exe",
          "!**System32*wininit.exe",
          "!**SysWOW64*wininit.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_236_SERVICES",
    "title": "Masquerading Services.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**services.exe",
          "!**Windows*System32*services.exe",
          "!**Windows*SysWOW64*services.exe",
          "!**System32*services.exe",
          "!**SysWOW64*services.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_237_TASKHOST",
    "title": "Masquerading Taskhost.exe",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**taskhost.exe",
          "!**Windows*System32*taskhost.exe",
          "!**Windows*SysWOW64*taskhost.exe",
          "!**System32*taskhost.exe",
          "!**SysWOW64*taskhost.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_238_SMSS",
    "title": "Masquerading Smss.exe",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1036.005"],
    "detection": {
      "selection": {
        "process.image": [
          "**smss.exe",
          "!**Windows*System32*smss.exe",
          "!**System32*smss.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_239_DOUBLE_EXT",
    "title": "Double Extension Execution",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036.007"],
    "detection": {
      "selection": {
        "process.image": [
          "*.pdf.exe",
          "*.doc.exe",
          "*.docx.exe",
          "*.xls.exe",
          "*.xlsx.exe",
          "*.ppt.exe",
          "*.pptx.exe",
          "*.txt.exe",
          "*.rtf.exe",
          "*.jpg.exe",
          "*.png.exe",
          "*.zip.exe"
        ]
      }
    }
  },
  {
    "id": "MASQ_240_FAKE_SYSTEM_DIR",
    "title": "Execution from Fake System Directory",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1036"],
    "detection": {
      "selection": {
        "process.image": [
          "**Windows*System32 **",
          "**Windows*System32.*",
          "**Windows*SysWOW64 **",
          "**Windows*SysWOW64.*"
        ]
      }
    }
  },

  {
    "id": "DEST_241_LOG_CLEAR_SEC",
    "title": "Security Log Cleared",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
                  "event_id": "1102"      }
    }
  },
  {
    "id": "DEST_242_LOG_CLEAR_SYS",
    "title": "System Log Cleared",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1070.001"],
    "detection": {
      "selection": {
        "event_id": "104",
      }
    }
  },
  {
    "id": "DEST_243_DEFENDER_DISABLE",
    "title": "Windows Defender Disabled",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": [
          "*Set-MpPreference*DisableRealtimeMonitoring*",
          "*DisableRealtimeMonitoring $true*",
          "*DisableRealtimeMonitoring true*",
          "*DisableRealtimeMonitoring 1*"
        ]
      }
    }
  },
  {
    "id": "DEST_244_DEFENDER_EXCLUSION",
    "title": "Windows Defender Exclusion Added",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.001"],
    "detection": {
      "selection": {
        "process.command_line": ["*Add-MpPreference*", "*ExclusionPath*", "*ExclusionExtension*", "*ExclusionProcess*"]
      }
    }
  },
  {
    "id": "DEST_245_STOP_DEFENDER",
    "title": "Stopping Security Services",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1489"],
    "detection": {
      "selection": {
        "process.command_line": ["* stop WinDefend*", "* stop SepMasterService*", "*sc stop WinDefend*", "*net stop WinDefend*"]
      }
    }
  },
  {
    "id": "DEST_246_DELETE_BACKUP",
    "title": "Delete Backup Catalog (WBAdmin)",
    "severity": "CRITICAL",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*wbadmin*delete catalog*", "*wbadmin*delete systemstatebackup*"]
      }
    }
  },
  {
    "id": "DEST_247_RESIZE_SHADOW",
    "title": "Resizing Shadow Copies (Ransomware)",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*vssadmin*Resize ShadowStorage*"]
      }
    }
  },
  {
    "id": "DEST_248_BOOT_RECOVERY",
    "title": "Disabling Boot Recovery",
    "severity": "HIGH",
    "module": "IMPACT",
    "mitre": ["T1490"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*recoveryenabled No*"]
      }
    }
  },
  {
    "id": "DEST_249_FILE_DELETION",
    "title": "Mass File Deletion (Cmd)",
    "severity": "MEDIUM",
    "module": "IMPACT",
    "mitre": ["T1485"],
    "detection": {
      "selection": {
        "process.command_line": ["*del /f /s /q*", "*rmdir /s /q*"]
      }
    }
  },
  {
    "id": "DEST_250_SAFE_MODE_BOOT",
    "title": "Force Safe Mode Boot (Ransomware)",
    "severity": "HIGH",
    "module": "DEFENSE",
    "mitre": ["T1562.009"],
    "detection": {
      "selection": {
        "process.command_line": ["*bcdedit*", "*safeboot minimal*"]
      }
    }
  }
];
