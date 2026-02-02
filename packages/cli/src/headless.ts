import { DetectionEngine, ThreatIntel } from '@neonshapeshifter/logtower-engine';
import { RULESETS } from '@neonshapeshifter/logtower-rules';
import { Finding, sortFindings, filterFindings, getSampleEvidence, normalizeEvent } from '@neonshapeshifter/logtower-core';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolve parser binary: prefer bundled binary, fallback to monorepo dev path
function resolveParserBinary(): string {
    // Production: bundled binary in package bin/ directory
    const bundledBin = path.join(__dirname, '../bin/logtower-parser');
    if (fs.existsSync(bundledBin)) {
        return bundledBin;
    }

    // Development: monorepo structure
    const REPO_ROOT = path.resolve(__dirname, '../../..');
    const devBin = path.join(REPO_ROOT, 'packages/parser-rust/target/release/logtower-parser');
    if (fs.existsSync(devBin)) {
        return devBin;
    }

    // Debug build fallback
    const debugBin = path.join(REPO_ROOT, 'packages/parser-rust/target/debug/logtower-parser');
    if (fs.existsSync(debugBin)) {
        return debugBin;
    }

    throw new Error(
        'Logtower Parser Binary not found.\n\n' +
        'If you are running from source (Development Mode):\n' +
        '  You need to compile the Rust parser manually.\n' +
        '  Run the following command in the project root:\n' +
        '    cd packages/parser-rust && cargo build --release\n\n' +
        'If you are running the installed CLI:\n' +
        '  The binary should have been bundled. Please reinstall the package.\n' +
        '  Missing path: ' + bundledBin
    );
}

export const runHeadless = async (
    filePath: string,
    filterMode: 'IMPORTANT' | 'ALL' = 'IMPORTANT',
    rulesetName: string = 'lolbas',
    outputJson: boolean = false,
    summaryMode: boolean = false,
    hours?: number,
    limit?: number,
    intelPath?: string
) => {
    // Select Ruleset
    let rules = RULESETS.lolbas;
    if (rulesetName === 'all') {
        rules = RULESETS.all;
    } else if (RULESETS[rulesetName as keyof typeof RULESETS]) {
        rules = RULESETS[rulesetName as keyof typeof RULESETS];
    } else {
        console.error(`Error: Unknown ruleset '${rulesetName}'. Available: ${Object.keys(RULESETS).join(', ')}, all`);
        process.exit(1);
    }

    if (!fs.existsSync(filePath)) {
        if (outputJson) console.log(JSON.stringify({ error: "File not found" }));
        else console.error(`Error: File not found: ${filePath}`);
        process.exit(1);
    }

    // Only support EVTX here
    if (!filePath.toLowerCase().endsWith('.evtx')) {
         console.error("Error: runHeadless only supports .evtx files. For JSONL use the CLI directly.");
         process.exit(1);
    }

    // Load Intel Feeds if provided
    const intel = new ThreatIntel();
    let intelStats = { ips: 0, tor: 0, hashes: 0, domains: 0 };
    if (intelPath && fs.existsSync(intelPath)) {
        intelStats = intel.loadFromDirectory(intelPath);
    }

    const engine = new DetectionEngine(rules);

    let rustParser: string;
    try {
        rustParser = resolveParserBinary();
    } catch (err: any) {
        if (outputJson) console.log(JSON.stringify({ error: err.message }));
        else console.error(`Error: ${err.message}`);
        process.exit(1);
    }

    // Guardrails
    const cutoffTime = hours ? Date.now() - (hours * 3600000) : 0;
    const limitCount = limit || Infinity;

    if (!outputJson) {
        console.log(`\nStarting Headless Hunt on: ${filePath}`);
        console.log(`Ruleset: ${rulesetName} (${rules.length} rules)`);
        console.log(`Filter Mode: ${filterMode}`);
        if (hours) console.log(`Time Filter: Last ${hours} hours`);
        if (limit) console.log(`Event Limit: ${limit}`);
        if (intel.isLoaded()) {
            console.log(`Intel Feeds: ${intelStats.ips} C2 IPs | ${intelStats.tor} Tor | ${intelStats.hashes} Hashes | ${intelStats.domains} Domains`);
        }
        console.log("");
    }

    let processedCount = 0;
    let intelHits = 0;

    const proc = spawn(rustParser, [filePath]);

    proc.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        for (const line of lines) {
            if (processedCount >= limitCount) {
                proc.kill();
                break;
            }

            if (!line.trim()) continue;
            try {
                const rawJson = JSON.parse(line);
                const event = normalizeEvent(rawJson);
                if (event) {
                    // Time Check
                    if (cutoffTime > 0) {
                        const eventTs = new Date(event.timestamp).getTime();
                        if (eventTs < cutoffTime) continue;
                    }

                    // Check Intel on the event
                    if (intel.isLoaded()) {
                        const intelMatch = intel.checkEvent(event);
                        if (intelMatch) {
                            intelHits++;
                            // Attach intel to event for potential later use
                            (event as any)._intel = intelMatch;
                        }
                    }

                    engine.processEvent(event);
                    processedCount++;
                }
            } catch {}
        }
    });

    proc.stderr.on('data', () => {});

    proc.on('close', () => {
        finish();
    });

    async function finish() {
        const findings = engine.getFindings();

        // Enrich findings with Intel
        if (intel.isLoaded()) {
            for (const finding of findings) {
                // Check IPs in finding
                const srcIp = finding.evidence[0]?.raw_event?.IpAddress ||
                              finding.evidence[0]?.raw_event?.SourceIp;
                const dstIp = finding.evidence[0]?.raw_event?.DestinationIp;

                let match = intel.checkIp(srcIp) || intel.checkIp(dstIp);

                // Check domains in command line
                if (!match && finding.process?.command_line) {
                    const urlPattern = /https?:\/\/([^\s/]+)/gi;
                    let urlMatch;
                    while ((urlMatch = urlPattern.exec(finding.process.command_line)) !== null) {
                        match = intel.checkDomain(urlMatch[1]);
                        if (match) break;
                    }
                }

                // Attach intel to finding
                if (match) {
                    (finding as any).intel = {
                        match: true,
                        source: match.source,
                        description: match.description,
                        value: match.value
                    };
                }
            }

            // Auto-detect connectivity for online enrichment
            const isOnline = await intel.detectConnectivity();
            if (isOnline && !outputJson) {
                console.log(`\x1b[32m[ONLINE] Connected to URLhaus API for URL verification\x1b[0m\n`);
            }
        }

        const visibleFindings = sortFindings(filterFindings(findings, filterMode));

        if (summaryMode) {
            const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
            findings.forEach((f: Finding) => { if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++; });

            const topSeverity = visibleFindings.slice(0, 5);
            const topCount = [...visibleFindings].sort((a, b) => b.evidence.length - a.evidence.length).slice(0, 5);

            if (outputJson) {
                console.log(JSON.stringify({
                    processed: processedCount,
                    intel_hits: intelHits,
                    totals: severityCounts,
                    top_severity: topSeverity.map(f => ({ ...f, evidence: [] })),
                    top_count: topCount.map(f => ({ ...f, evidence: [] }))
                }, null, 2));
                return;
            }

            console.log(`\n=== Execution Summary ===`);
            console.log(`Processed Events: ${processedCount}`);
            console.log(`Total Findings: ${findings.length}`);
            if (intel.isLoaded()) console.log(`Intel Hits: ${intelHits}`);
            console.log(`\n[Severity Breakdown]`);
            Object.entries(severityCounts).forEach(([k, v]) => {
                if (v > 0) console.log(`  ${k}: ${v}`);
            });
            console.log(`\n[Top 5 by Severity]`);
            topSeverity.forEach(f => {
                const intelTag = (f as any).intel ? ' [INTEL]' : '';
                console.log(`  [${f.severity}] ${f.title}${intelTag} (${f.evidence.length})`);
            });
            return;
        }

        if (outputJson) {
            console.log(JSON.stringify(findings, null, 2));
            return;
        }

        const hiddenCount = findings.length - visibleFindings.length;

        console.log(`\n=== Detection Report ===`);
        console.log(`Processed: ${processedCount}`);
        console.log(`Total Findings: ${findings.length}`);
        if (intel.isLoaded()) console.log(`Intel Hits: ${intelHits}`);
        console.log(`Visible: ${visibleFindings.length}\n`);

        visibleFindings.forEach((f: Finding) => {
            const hasIntel = (f as any).intel;
            const color = f.severity === 'CRITICAL' ? '\x1b[31m' :
                          f.severity === 'HIGH' ? '\x1b[35m' :
                          f.severity === 'MEDIUM' ? '\x1b[33m' :
                          '\x1b[36m';
            const reset = '\x1b[0m';
            const intelTag = hasIntel ? ` \x1b[41m[INTEL: ${hasIntel.description}]\x1b[0m` : '';

            console.log(`${color}[${f.severity}] ${f.rule_id} ${f.title}${intelTag} (Count: ${f.evidence.length})${reset}`);
            console.log(`  Evidence: ${getSampleEvidence(f)}`);
            if (hasIntel) {
                console.log(`  \x1b[31mIntel: ${hasIntel.source} - ${hasIntel.value}\x1b[0m`);
            }
        });

        if (hiddenCount > 0) {
            console.log(`\n\x1b[33m(${hiddenCount} findings hidden by '${filterMode}' filter)\x1b[0m`);
        }

        console.log(`\nStatus: COMPLETE`);
    }
};
