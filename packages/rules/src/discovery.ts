import { Rule } from '@neonshapeshifter/logtower-engine';

export const DISCOVERY_RULES: Rule[] = [
  {
    id: 'DISCOVERY_001_WHOAMI',
    title: 'System Owner/User Discovery (Whoami)',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1033'],
    detection: {
      selection: {
        'process.image': '*whoami.exe'
      }
    },
    description: "Execution of whoami.exe to identify the current user context. While common for admins, it is often the first command run by attackers after exploitation.",
    response_steps: [
      "1. CONTEXT: Check the parent process. Was it spawned by a shell (cmd/powershell) or an exploit source (IIS, SQL)?",
      "2. TIMELINE: What happened immediately before? (File write, service creation?)",
      "3. USER: Is this a service account running whoami? (Highly suspicious)."
    ]
  },
  {
    id: 'DISCOVERY_002_NET',
    title: 'Net Account Discovery',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1087.001', 'T1069.001'],
    detection: {
      selection: {
        'process.image': ['*net.exe', '*net1.exe'],
        'process.command_line': ['* user*', '* group*', '* localgroup*']
      }
    },
    description: "Usage of 'net user' or 'net localgroup' to enumerate accounts and groups. Attackers use this to find admins or other high-value targets.",
    response_steps: [
      "1. SCOPE: Is this a one-off command or part of a script?",
      "2. ARGUMENTS: Did they list 'Domain Admins' or specific high-priv groups?",
      "3. PARENT: Check parent process for signs of automation (malware)."
    ]
  },
  {
    id: 'DISCOVERY_003_SYSTEMINFO',
    title: 'System Information Discovery (Systeminfo)',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1082'],
    detection: {
      selection: {
        'process.image': '*systeminfo.exe'
      }
    },
    description: "Execution of systeminfo.exe to gather detailed OS/Hardware information. Attackers use this to check patch levels (hotfixes) for privilege escalation vulnerabilities.",
    response_steps: [
      "1. INTENT: Is this an admin inventorying the system?",
      "2. NEXT STEPS: Look for searches for 'KB...' vulnerabilities post-execution.",
      "3. NETWORK: Did the output get piped or sent to a remote host?"
    ]
  },
  {
    id: 'DISCOVERY_004_TASKLIST',
    title: 'Process Discovery (Tasklist)',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1057'],
    detection: {
      selection: {
        'process.image': '*tasklist.exe'
      }
    },
    description: "Execution of tasklist.exe to list running processes. Attackers check this to identify security tools (AV/EDR) or vulnerable applications.",
    response_steps: [
      "1. CONTEXT: Often run with /svc to see services hosting processes.",
      "2. CORRELATION: Look for subsequent 'taskkill' or attempts to stop discovered services."
    ]
  },
  {
    id: 'DISCOVERY_005_IPCONFIG',
    title: 'System Network Configuration Discovery (Ipconfig)',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1016'],
    detection: {
      selection: {
        'process.image': '*ipconfig.exe'
      }
    },
    description: "Execution of ipconfig.exe to view network configuration. Attackers use it to identify subnets, gateways, and DNS servers for pivoting.",
    response_steps: [
      "1. NORMALCY: Extremely common, but suspicious in rapid succession with other discovery tools.",
      "2. CHECK: Often followed by 'arp -a' or 'route print'."
    ]
  },
  {
    id: 'DISCOVERY_006_NLTEST',
    title: 'Domain Trust Discovery (Nltest)',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1482'],
    detection: {
      selection: {
        'process.image': '*nltest.exe',
        'process.command_line': ['*/dclist:*', '*/domain_trusts*', '*/dsgetdc:*']
      }
    },
    description: "Execution of nltest.exe to enumerate domain controllers and trusts. Used to map the AD infrastructure for lateral movement.",
    response_steps: [
      "1. CRITICALITY: Rare for normal users. Common for admins and attackers.",
      "2. TARGET: Which domain was queried?",
      "3. FOLLOW-UP: Watch for LDAP queries or connection attempts to the identified DCs."
    ]
  },
  {
    id: 'DISCOVERY_007_NETSTAT',
    title: 'System Network Connections Discovery (Netstat)',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1049'],
    detection: {
      selection: {
        'process.image': '*netstat.exe',
        'process.command_line': ['*-a*']
      }
    },
    description: "Execution of netstat.exe to view active connections and listening ports. Attackers use it to find available services or check if their C2 port is open.",
    response_steps: [
      "1. ARGS: '-ano' is classic for mapping PID to Ports.",
      "2. PARENT: If run by a web server process (w3wp.exe), it's likely a webshell."
    ]
  },
  {
    id: 'DISCOVERY_008_QUSER',
    title: 'System Owner/User Discovery (Quser)',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1033'],
    detection: {
      selection: {
        'process.image': ['*quser.exe', '*query.exe'],
        'process.command_line': ['*user*']
      }
    },
    description: "Execution of quser.exe or 'query user' to see logged-on users. Attackers use this to identify if admins are active on the box (to avoid detection).",
    response_steps: [
      "1. TIMING: Often run before lateral movement attempts.",
      "2. SOURCE: Check if run remotely via WinRM/WMI."
    ]
  },
  {
    id: 'DISCOVERY_009_ARP',
    title: 'System Network Configuration Discovery (Arp)',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1016'],
    detection: {
      selection: {
        'process.image': '*arp.exe',
        'process.command_line': ['*-a*']
      }
    },
    description: "Execution of 'arp -a' to view the ARP cache. Maps IP addresses to MAC addresses, revealing adjacent hosts on the local subnet.",
    response_steps: [
      "1. RECON: Used to find targets for lateral movement without active scanning (nmap).",
      "2. MONITOR: Watch for connections to the IPs listed in the ARP cache."
    ]
  },
  {
    id: 'DISCOVERY_010_ROUTE',
    title: 'System Network Connections Discovery (Route)',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1049'],
    detection: {
      selection: {
        'process.image': '*route.exe',
        'process.command_line': ['* print*']
      }
    },
    description: "Execution of 'route print' to view the routing table. Attackers use this to identify other networks/subnets accessible from the compromised host.",
    response_steps: [
      "1. PIVOT: Look for traffic destined for internal subnets found in the route table.",
      "2. PARENT: Check what spawned this command."
    ]
  },
  {
    id: 'DISCOVERY_011_DSQUERY_AD_ENUM',
    title: 'Dsquery AD Enumeration',
    severity: 'MEDIUM',
    module: 'DISCOVERY',
    mitre: ['T1087.002'],
    detection: {
      selection: {
        'process.image': '*dsquery.exe',
        'process.command_line': ['*user*', '*group*', '*computer*', '*subnet*']
      }
    },
    description: "Execution of dsquery.exe to search Active Directory. Powerful tool for enumerating users, groups, and computers matching specific criteria.",
    response_steps: [
      "1. QUERY: Analyze the filter used. Did they search for 'admin' or 'service' accounts?",
      "2. VOLUME: Large queries suggest mass enumeration.",
      "3. SOURCE: Is this a developer or admin machine?"
    ]
  },
  {
    id: 'DISCOVERY_012_CSVDE_EXPORT_AD_HIGH',
    title: 'Csvde AD Export',
    severity: 'HIGH',
    module: 'DISCOVERY',
    mitre: ['T1087.002'],
    detection: {
      selection: {
        'process.image': '*csvde.exe',
        'process.command_line': ['*-f*', '*-r*']
      }
    },
    description: "Execution of csvde.exe to export Active Directory data to a file. Often used to dump the entire directory structure for offline analysis.",
    response_steps: [
      "1. EXPORT: Identify the output file (-f filename.csv).",
      "2. CONTENTS: Check if the file contains sensitive info (users, groups).",
      "3. BLOCK: Restrict usage to Domain Admins."
    ]
  },
  {
    id: 'DISCOVERY_013_GPRESULT_POLICY_RECON_LOW',
    title: 'Gpresult Policy Recon',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1615'],
    detection: {
      selection: {
        'process.image': '*gpresult.exe',
        'process.command_line': ['*/z*', '*/h*']
      }
    },
    description: "Execution of gpresult.exe to dump Group Policy settings. Attackers use this to identify security controls, audit settings, and admin groups pushed via GPO.",
    response_steps: [
      "1. OUTPUT: Did they save the report to a file?",
      "2. ANALYSIS: They might be looking for 'SeDebugPrivilege' or local admin assignments."
    ]
  },
  {
    id: 'DISCOVERY_014_NET_SHARE_DISCOVERY_MEDIUM',
    title: 'Net Share Discovery',
    severity: 'MEDIUM',
    module: 'DISCOVERY',
    mitre: ['T1135'],
    detection: {
      selection: {
        'process.image': ['*net.exe', '*net1.exe'],
        'process.command_line': ['*view*', '*share*']
      }
    },
    description: "Usage of 'net view' or 'net share' to list network shares. Key step in identifying file servers and potential locations for lateral movement.",
    response_steps: [
      "1. TARGET: 'net view \\target' indicates interest in a specific host.",
      "2. DOMAIN: 'net view /domain' lists all computers in the domain.",
      "3. MONITOR: Watch for SMB connections to the discovered shares."
    ]
  },
  {
    id: 'DISCOVERY_015_NBTSTAT_RECON_LOW',
    title: 'Nbtstat Reconnaissance',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1016'],
    detection: {
      selection: {
        'process.image': '*nbtstat.exe',
        'process.command_line': ['*-n*', '*-c*']
      }
    },
    description: "Execution of nbtstat.exe to query NetBIOS names. Used to resolve IP addresses to hostnames and identify the type of service running.",
    response_steps: [
      "1. LEGACY: NetBIOS is older but still present. Usage is rare for modern admin tasks.",
      "2. CONTEXT: Often used when DNS is not reliable or to find workgroups."
    ]
  },
  {
    id: 'DISCOVERY_016_DRIVERQUERY_ENUM_LOW',
    title: 'Driverquery Driver Enumeration',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1082'],
    detection: {
      selection: {
        'process.image': '*driverquery.exe',
        'process.command_line': ['*/v*', '*/si*']
      }
    },
    description: "Execution of driverquery.exe to list installed drivers. Attackers use this to find vulnerable drivers (BYOVD) to exploit for kernel access.",
    response_steps: [
      "1. VULN CHECK: Cross-reference installed drivers with known vulnerable ones (e.g., Capcom, Genshin Impact anti-cheat).",
      "2. MONITOR: Watch for 'sc create' or driver loading events."
    ]
  },
  {
    id: 'DISCOVERY_018_TREE_FILESYSTEM_MAP_INFO',
    title: 'Tree Filesystem Mapping',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1083'],
    detection: {
      selection: {
        'process.image': '*tree.exe',
        'process.command_line': ['*/f*', '*/a*']
      }
    },
    description: "Execution of tree.exe to map directory structures. Attackers use this to quickly find interesting files (confidential docs, source code) in a new environment.",
    response_steps: [
      "1. OUTPUT: Did they redirect output to a file? (e.g., tree /f > file_list.txt).",
      "2. PATH: Which directory was mapped? (C:\\Users, Network Shares?)."
    ]
  },
  {
    id: 'DISCOVERY_019_CMD_SET_ENV_INFO',
    title: 'Cmd Environment Variable Discovery',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1082'],
    detection: {
      selection: {
        'process.image': '*cmd.exe',
        'process.command_line': ['* set']
      }
    },
    description: "Execution of 'set' command in cmd to view environment variables. Reveals paths, usernames, domains, and sometimes leaked keys in env vars.",
    response_steps: [
      "1. REVIEW: Check if any sensitive keys are stored in environment variables on this host.",
      "2. PARENT: Common reconnaissance step for automated scripts."
    ]
  },
  {
    id: 'DISCOVERY_020_DOSKEY_HISTORY_MACROS_LOW',
    title: 'Doskey History/Macros',
    severity: 'LOW',
    module: 'DISCOVERY',
    mitre: ['T1059.003'],
    detection: {
      selection: {
        'process.image': '*doskey.exe',
        'process.command_line': ['*/history*', '*/macros*']
      }
    },
    description: "Usage of doskey /history to view previously executed commands in the current session. Attackers look for typed passwords or interesting commands.",
    response_steps: [
      "1. HISTORY: If you see this, the attacker is looking back at what YOU or the user just typed.",
      "2. ALERT: Indicates interactive session control."
    ]
  }
];