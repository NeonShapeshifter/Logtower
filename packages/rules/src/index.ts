import { LOLBAS_RULES } from './lolbas.js';
import { LATERAL_RULES } from './lateral.js';
import { DEFENSE_RULES } from './defense.js';
import { CRED_RULES } from './cred.js';
import { DISCOVERY_RULES } from './discovery.js';
import { IMPACT_RULES } from './impact.js';
import { PERSISTENCE_RULES } from './persistence.js';
import { POWERSHELL_RULES } from './powershell.js';
import { PROCESS_SPAWN_RULES } from './process_spawn.js';
import { ADVANCED_RULES } from './advanced.js';
import { APT_RANSOMWARE_RULES } from './apt_ransomware.js';
import { IDENTITY_TUNNELING_RULES } from './identity_tunneling.js';
import { ANOMALY_RULES } from './anomalies.js';
import { SIGMA_COMPLIANCE_RULES } from './sigma_compliance.js';
import { WEB_RANSOMWARE_RULES } from './web_ransomware.js';
import { NETWORK_DEFENSE_RULES } from './network_defense.js';
import { CLOUD_CONTAINER_RULES } from './cloud_containers.js';
import { BITS_PERSISTENCE_RULES } from './bits_persistence.js';
import { POWERSHELL_DEEP_RULES } from './powershell_deep.js';
import { ANTI_FORENSICS_RULES } from './anti_forensics.js';
import { SHELLS_RULES } from './shells.js';
import { SCHEDULED_TASKS_RULES } from './scheduled_tasks.js';
import { ACCOUNT_MANIPULATION_RULES } from './account_manipulation.js';
import { ADVANCED_WINDOWS_RULES } from './advanced_windows.js';
import { TOOL_SIGNATURES_RULES } from './tool_signatures.js';

const ALL_RULES = [
  ...LOLBAS_RULES,
  ...LATERAL_RULES,
  ...DEFENSE_RULES,
  ...CRED_RULES,
  ...DISCOVERY_RULES,
  ...IMPACT_RULES,
  ...PERSISTENCE_RULES,
  ...POWERSHELL_RULES,
  ...PROCESS_SPAWN_RULES,
  ...ADVANCED_RULES,
  ...APT_RANSOMWARE_RULES,
  ...IDENTITY_TUNNELING_RULES,
  ...ANOMALY_RULES,
  ...SIGMA_COMPLIANCE_RULES,
  ...WEB_RANSOMWARE_RULES,
  ...NETWORK_DEFENSE_RULES,
  ...CLOUD_CONTAINER_RULES,
  ...BITS_PERSISTENCE_RULES,
  ...POWERSHELL_DEEP_RULES,
  ...ANTI_FORENSICS_RULES,
  ...SHELLS_RULES,
  ...SCHEDULED_TASKS_RULES,
  ...ACCOUNT_MANIPULATION_RULES,
  ...ADVANCED_WINDOWS_RULES,
  ...TOOL_SIGNATURES_RULES
];

export const RULESETS = {
  lolbas: LOLBAS_RULES,
  lateral: LATERAL_RULES,
  defense: DEFENSE_RULES,
  cred: CRED_RULES,
  discovery: DISCOVERY_RULES,
  impact: IMPACT_RULES,
  persistence: PERSISTENCE_RULES,
  powershell: POWERSHELL_RULES,
  process_spawn: PROCESS_SPAWN_RULES,
  advanced: ADVANCED_RULES,
  apt: APT_RANSOMWARE_RULES,
  identity: IDENTITY_TUNNELING_RULES,
  anomalies: ANOMALY_RULES,
  sigma_compliance: SIGMA_COMPLIANCE_RULES,
  web_ransomware: WEB_RANSOMWARE_RULES,
  network_defense: NETWORK_DEFENSE_RULES,
  cloud_containers: CLOUD_CONTAINER_RULES,
  bits_persistence: BITS_PERSISTENCE_RULES,
  powershell_deep: POWERSHELL_DEEP_RULES,
  anti_forensics: ANTI_FORENSICS_RULES,
  shells: SHELLS_RULES,
  scheduled_tasks: SCHEDULED_TASKS_RULES,
  account_manipulation: ACCOUNT_MANIPULATION_RULES,
  advanced_windows: ADVANCED_WINDOWS_RULES,
  tool_signatures: TOOL_SIGNATURES_RULES,
  all: ALL_RULES
};

export const BASE_RULES = RULESETS.lolbas;
