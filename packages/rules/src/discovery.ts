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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  },
  // Batch 10: Discovery Expansion
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
    }
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
    }
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
    }
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
    }
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
    }
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
    }
  },
  {
    id: 'DISCOVERY_018_TREE_FILESYSTEM_MAP_INFO',
    title: 'Tree Filesystem Mapping',
    severity: 'INFO',
    module: 'DISCOVERY',
    mitre: ['T1083'],
    detection: {
      selection: {
        'process.image': '*tree.exe', // tree.com usually but exe wildcard is safer
        'process.command_line': ['*/f*', '*/a*']
      }
    }
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
    }
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
    }
  }
];
