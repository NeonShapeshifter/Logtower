import { LogtowerEvent, Finding, FindingSchema } from '@neonshapeshifter/logtower-core';
import { Rule } from './types.js';
import { matchRule } from './matcher.js';
import { ThreatIntel } from './intel.js';
import { v4 as uuidv4 } from 'uuid';

export class DetectionEngine {
  private rules: Rule[] = [];
  private findingsMap: Map<string, Finding> = new Map();
  private logonState: Map<string, number[]> = new Map();
  private badIps: Set<string> = new Set();

  constructor(rules: Rule[], badIps: string[] = []) {
    this.rules = rules;
    this.badIps = new Set(badIps);
  }

  public processEvent(event: LogtowerEvent): Finding | null {
    let newFinding: Finding | null = null;
    
    // 1. Stateless Rules
    for (const rule of this.rules) {
      if (matchRule(event, rule)) {
        const f = this.addFinding(event, rule);
        if (!newFinding) newFinding = f;
      }
    }

    // 2. Stateful Logic: Logon Burst (Lateral Movement)
    if (event.event_id === 4624 && event.user?.name && !event.user.name.endsWith('$')) {
      const user = event.user.name;
      const ts = new Date(event.timestamp.replace(' ', 'T')).getTime(); // rough parsing
      
      if (!this.logonState.has(user)) {
        this.logonState.set(user, []);
      }
      
      const timestamps = this.logonState.get(user)!;
      timestamps.push(ts);
      
      // Filter timestamps older than 60s
      const windowStart = ts - 60000;
      const recent = timestamps.filter(t => t > windowStart);
      this.logonState.set(user, recent);
      
      if (recent.length >= 3) {
        // Trigger Virtual Rule
        const lateralRule: Rule = {
            id: 'LATERAL_001_BURST',
            title: `Logon Burst (${recent.length} in 60s)`,
            severity: 'HIGH',
            module: 'LATERAL',
            mitre: ['T1078'],
            detection: { selection: {} }
        };
        const f = this.addFinding(event, lateralRule);
        if (!newFinding) newFinding = f;
      }
    }
    
    return newFinding;
  }

  private addFinding(event: LogtowerEvent, rule: Rule): Finding {
    const key = `${rule.id}|${event.host}`;
    
    // Check Intel (pre-calculated by CLI/Ingestor)
    const ipMatch = (event as any)._intel;
    let intelData = undefined;
    
    if (ipMatch) {
        intelData = {
            match: true,
            source: ipMatch.source,
            description: ipMatch.description,
            value: ipMatch.value
        };
        // Escalate severity if Intel matches
        // But we don't want to mutate the Rule object globally, just local finding
    }

    if (this.findingsMap.has(key)) {
      const existing = this.findingsMap.get(key)!;
      existing.evidence.push({
        event_ts: event.timestamp,
        summary: this.summarizeEvent(event, rule),
        raw_event: event.raw // Store RAW
      });
      if (existing.evidence.length > 10) existing.evidence.shift();
      return existing;
      
    } else {
      const newF: Finding = {
        id: uuidv4(),
        rule_id: rule.id,
        severity: ipMatch ? 'CRITICAL' : rule.severity, // Escalate on Intel match
        title: ipMatch ? `${rule.title} [INTEL]` : rule.title,
        description: `Detected ${rule.title} on ${event.host}`,
        host: event.host,
        timestamp: event.timestamp,
        score: rule.severity === 'CRITICAL' ? 100 : rule.severity === 'HIGH' ? 75 : 50,
        evidence: [{
          event_ts: event.timestamp,
          summary: this.summarizeEvent(event, rule),
          raw_event: event.raw // Store RAW
        }],
        mitre: rule.mitre,
        process: event.process,
        user: event.user,
        registry: event.registry,
        service: event.service,
        task: event.task,
        image_load: event.image_load,
        wmi: event.wmi,
        pipe: event.pipe,
        kerberos: event.kerberos,
        bits: event.bits,
        ad_change: event.ad_change,
        intel: intelData
      };
      this.findingsMap.set(key, newF);
      return newF;
    }
  }

  public getFindings(): Finding[] {
    return Array.from(this.findingsMap.values());
  }

  public addExternalFindings(findings: Finding[]) {
      findings.forEach(f => this.findingsMap.set(f.id, f));
  }

  private summarizeEvent(event: LogtowerEvent, rule: Rule): string {
    if (event.process?.command_line) return event.process.command_line;
    return `Event ID ${event.event_id}`;
  }
}

export * from './types.js';
export * from './intel.js';export * from './tracker.js';
