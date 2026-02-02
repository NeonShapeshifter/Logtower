import { LogtowerEvent } from '@neonshapeshifter/logtower-core';

export type RuleSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type RuleModule = 
  | 'LOLBAS' 
  | 'LATERAL' 
  | 'INTEL' 
  | 'DISCOVERY' 
  | 'DEFENSE' 
  | 'CRED' 
  | 'IMPACT' 
  | 'PERSISTENCE'
  | 'EXECUTION'
  | 'INITIAL_ACCESS'
  | 'COMMAND_AND_CONTROL'
  | 'PRIVILEGE_ESCALATION'
  | 'COLLECTION'
  | 'EXFILTRATION'
  | 'INTERNAL'
  | 'ANOMALY';
export type RuleStatus = 'experimental' | 'test' | 'stable';

export interface Rule {
  id: string;
  title: string;
  severity: RuleSeverity;
  module: RuleModule;
  mitre?: string[];

  // Extended info (optional - for Pokedex/Playbook integration)
  description?: string;
  response_steps?: string[];
  references?: string[];
  falsepositives?: string[];
  author?: string;
  date?: string;
  status?: RuleStatus;
  tags?: string[];

  // Simplified Sigma-like condition
  detection: {
    selection: Record<string, string | string[]>; // field -> value(s) (OR logic inside array)
    condition?: string; // Default is "all fields in selection must match"
  };
}
