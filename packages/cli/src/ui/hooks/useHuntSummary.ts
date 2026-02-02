import { useMemo } from 'react';
import { Finding, sortFindings } from '@neonshapeshifter/logtower-core';

export const useHuntSummary = (findings: Finding[]) => {
  return useMemo(() => {
    // 1. Stats
    const stats: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { 
        if (stats[f.severity] !== undefined) stats[f.severity]++; 
    });

    // 2. Top 5 Severity
    // sortFindings already sorts by Severity then Recency.
    // We just take unique titles to avoid duplicates in summary if desired?
    // The requirement implies Top 5 findings (which might be grouped by rule_id in engine, but here 'findings' are unique alerts).
    // If 'findings' are individual alerts, just taking top 5 is fine.
    const sortedBySev = sortFindings(findings);
    const topSeverity = sortedBySev.slice(0, 5);

    // 3. Top 5 Count (Evidence Volume)
    const sortedByCount = [...findings].sort((a, b) => b.evidence.length - a.evidence.length);
    const topCount = sortedByCount.slice(0, 5);

    return { stats, topSeverity, topCount };
  }, [findings]);
};
