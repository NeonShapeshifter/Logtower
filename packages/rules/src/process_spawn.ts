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
    },
    description: "Detects Microsoft Word spawning Command Prompt. This is a classic indicator of a malicious macro (VBA) or exploit execution.",
    response_steps: [
      "1. ISOLATE: Disconnect the machine.",
      "2. FILE: Identify the document opened (check recent files or command line).",
      "3. PARENT: Check if it was opened from Outlook (Phishing) or Browser (Download)."
    ]
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
    },
    description: "Detects Microsoft Word spawning PowerShell. This usually indicates a macro executing a download cradle or payload directly.",
    response_steps: [
      "1. ISOLATE: Highly likely phishing payload execution.",
      "2. DECODE: Check the PowerShell arguments for encoded commands.",
      "3. BLOCK: Block the domain the script tried to contact."
    ]
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
    },
    description: "Detects Microsoft Excel spawning Command Prompt. Indicates a malicious macro (XLSM) or exploit (e.g., CSV Injection).",
    response_steps: [
      "1. ISOLATE: Machine is likely compromised.",
      "2. DOCUMENT: Retrieve the malicious spreadsheet.",
      "3. PAYLOAD: What command did cmd.exe run?"
    ]
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
    },
    description: "Detects Microsoft Excel spawning PowerShell. Common technique for banking trojans (Emotet, Dridex) delivered via spam.",
    response_steps: [
      "1. ISOLATE: Stop potential lateral movement or ransomware deployment.",
      "2. ANALYZE: Check the PowerShell command line."
    ]
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
    },
    description: "Detects PowerPoint spawning Command Prompt. Often triggered by malicious actions or embedded OLE objects.",
    response_steps: [
      "1. ISOLATE: Confirmed malicious activity.",
      "2. SOURCE: Did the user run a slideshow recently?"
    ]
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
    },
    description: "Detects PowerPoint spawning PowerShell. Similar to Word/Excel macros but less common (and thus often missed by users).",
    response_steps: [
      "1. ISOLATE: Immediate containment.",
      "2. REVIEW: Check what script was executed."
    ]
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
    },
    description: "Detects Outlook spawning Command Prompt. This implies an exploit in the preview pane or the user double-clicking a malicious attachment/link that executes code.",
    response_steps: [
      "1. ISOLATE: Likely a successful phishing attack.",
      "2. EMAIL: Identify the phishing email and purge it from other mailboxes."
    ]
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
    },
    description: "Detects Outlook spawning PowerShell. Very high confidence indicator of compromise via email.",
    response_steps: [
      "1. ISOLATE: The endpoint is compromised.",
      "2. SEARCH: Look for the email subject/sender in logs."
    ]
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
    },
    description: "Detects Google Chrome spawning Command Prompt. Could be a browser exploit, a malicious extension, or a user running a downloaded executable directly.",
    response_steps: [
      "1. HISTORY: Check browser history at the time of the event.",
      "2. EXTENSIONS: Review installed extensions for malicious ones.",
      "3. DOWNLOADS: What did the user download recently?"
    ]
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
    },
    description: "Detects Google Chrome spawning PowerShell. Highly suspicious behavior often linked to drive-by downloads or social engineering.",
    response_steps: [
      "1. ISOLATE: High risk of C2 infection.",
      "2. PAYLOAD: Analyze the PowerShell command."
    ]
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
    },
    description: "Detects Microsoft Edge spawning Command Prompt. Similar risks to Chrome (Exploits, Extensions, Malware downloads).",
    response_steps: [
      "1. HISTORY: Check Edge history.",
      "2. SMARTSCREEN: Did the user bypass SmartScreen warning?"
    ]
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
    },
    description: "Detects Microsoft Edge spawning PowerShell. Likely a browser-based attack vector.",
    response_steps: [
      "1. ISOLATE: Machine is likely compromised.",
      "2. INVESTIGATE: Look for 'Invoke-Expression' or downloads in the PS command."
    ]
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
    },
    description: "Detects Firefox spawning Command Prompt.",
    response_steps: [
      "1. HISTORY: Check browsing history.",
      "2. PROFILE: Check Firefox profile for malicious addons."
    ]
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
    },
    description: "Detects Adobe Reader spawning Command Prompt. Indicates a malicious PDF with embedded Javascript or exploit code.",
    response_steps: [
      "1. FILE: Identify the PDF opened.",
      "2. ISOLATE: PDF exploits are often used in targeted attacks (APT)."
    ]
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
    },
    description: "Detects Java spawning Command Prompt. This is a classic signature of a Web Shell (JSP) or deserialization exploit (e.g., Log4Shell) on a server.",
    response_steps: [
      "1. CONTEXT: Is this a web server (Tomcat, JBoss)?",
      "2. WEB LOGS: Check web access logs for the time of execution.",
      "3. ISOLATE: If it's a server, assume the application is fully compromised."
    ]
  }
];