import { Rule } from '@neonshapeshifter/logtower-engine';

export const PROCESS_SPAWN_RULES: Rule[] = [
  {
    id: "PROC_136_WORD_CMD",
    title: "Word Spawning CMD",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*winword.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_137_WORD_PS",
    title: "Word Spawning PowerShell",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*winword.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_138_EXCEL_CMD",
    title: "Excel Spawning CMD",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*excel.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_139_EXCEL_PS",
    title: "Excel Spawning PowerShell",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*excel.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_140_PPT_CMD",
    title: "PowerPoint Spawning CMD",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*powerpnt.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_141_PPT_PS",
    title: "PowerPoint Spawning PowerShell",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*powerpnt.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_142_OUTLOOK_CMD",
    title: "Outlook Spawning CMD",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*outlook.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_143_OUTLOOK_PS",
    title: "Outlook Spawning PowerShell",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*outlook.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_144_CHROME_CMD",
    title: "Chrome Spawning CMD",
    severity: "HIGH",
    module: "INITIAL_ACCESS",
    mitre: ["T1189", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*chrome.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_145_CHROME_PS",
    title: "Chrome Spawning PowerShell",
    severity: "HIGH",
    module: "INITIAL_ACCESS",
    mitre: ["T1189", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*chrome.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_146_EDGE_CMD",
    title: "Edge Spawning CMD",
    severity: "HIGH",
    module: "INITIAL_ACCESS",
    mitre: ["T1189", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*msedge.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_147_EDGE_PS",
    title: "Edge Spawning PowerShell",
    severity: "HIGH",
    module: "INITIAL_ACCESS",
    mitre: ["T1189", "T1059.001"],
    detection: {
      selection: {
        "process.parent_image": "*msedge.exe",
        "process.image": ["*powershell.exe", "*pwsh.exe"]
      }
    }
  },
  {
    id: "PROC_148_FIREFOX_CMD",
    title: "Firefox Spawning CMD",
    severity: "HIGH",
    module: "INITIAL_ACCESS",
    mitre: ["T1189", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": "*firefox.exe",
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_149_ACROBAT_CMD",
    title: "Acrobat Spawning CMD",
    severity: "CRITICAL",
    module: "INITIAL_ACCESS",
    mitre: ["T1204.002", "T1059.003"],
    detection: {
      selection: {
        "process.parent_image": ["*acrord32.exe", "*acrobat.exe"],
        "process.image": "*cmd.exe"
      }
    }
  },
  {
    id: "PROC_150_JAVA_CMD",
    title: "Java Spawning CMD",
    severity: "HIGH",
    module: "PERSISTENCE",
    mitre: ["T1505.003"],
    detection: {
      selection: {
        "process.parent_image": "*java.exe",
        "process.image": "*cmd.exe"
      }
    }
  }
];
