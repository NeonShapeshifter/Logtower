import fs from 'fs';
import path from 'path';

export type IntelMatch = {
    type: 'IP' | 'HASH' | 'DOMAIN' | 'URL';
    value: string;
    source: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH';
};

export type UrlCheckResult = {
    found: boolean;
    threat?: string;
    tags?: string[];
    source?: string;
};

export class ThreatIntel {
    private botnetIps = new Set<string>();
    private torExits = new Set<string>();
    private malwareHashes = new Set<string>();
    private malwareDomains = new Set<string>();
    private loaded = false;
    private isOnline: boolean | null = null;

    /**
     * Load feeds from a directory containing:
     * - botnet_ips.txt (one IP per line)
     * - tor_exits.txt (one IP per line)
     * - malware_hashes.txt (one SHA256 per line)
     * - malware_domains.txt (hostfile format: 127.0.0.1 domain.com)
     */
    public loadFromDirectory(feedsPath: string): { ips: number; tor: number; hashes: number; domains: number } {
        const stats = { ips: 0, tor: 0, hashes: 0, domains: 0 };

        // Load Botnet IPs
        const botnetFile = path.join(feedsPath, 'botnet_ips.txt');
        if (fs.existsSync(botnetFile)) {
            const lines = fs.readFileSync(botnetFile, 'utf-8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    this.botnetIps.add(trimmed);
                    stats.ips++;
                }
            }
        }

        // Load Tor Exit Nodes
        const torFile = path.join(feedsPath, 'tor_exits.txt');
        if (fs.existsSync(torFile)) {
            const lines = fs.readFileSync(torFile, 'utf-8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    this.torExits.add(trimmed);
                    stats.tor++;
                }
            }
        }

        // Load Malware Hashes
        const hashFile = path.join(feedsPath, 'malware_hashes.txt');
        if (fs.existsSync(hashFile)) {
            const lines = fs.readFileSync(hashFile, 'utf-8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim().toLowerCase();
                if (trimmed && !trimmed.startsWith('#') && /^[a-f0-9]{64}$/.test(trimmed)) {
                    this.malwareHashes.add(trimmed);
                    stats.hashes++;
                }
            }
        }

        // Load Malware Domains (hostfile format: 127.0.0.1 domain.com)
        const domainFile = path.join(feedsPath, 'malware_domains.txt');
        if (fs.existsSync(domainFile)) {
            const lines = fs.readFileSync(domainFile, 'utf-8').split('\n');
            for (const line of lines) {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    // Parse hostfile format: "127.0.0.1 domain.com" or just "domain.com"
                    const parts = trimmed.split(/\s+/);
                    const domain = parts.length > 1 ? parts[1] : parts[0];
                    if (domain && !domain.startsWith('127.') && !domain.startsWith('0.')) {
                        this.malwareDomains.add(domain.toLowerCase());
                        stats.domains++;
                    }
                }
            }
        }

        this.loaded = true;
        return stats;
    }

    public isLoaded(): boolean {
        return this.loaded;
    }

    public getStats(): { ips: number; tor: number; hashes: number; domains: number } {
        return {
            ips: this.botnetIps.size,
            tor: this.torExits.size,
            hashes: this.malwareHashes.size,
            domains: this.malwareDomains.size
        };
    }

    /**
     * Check if an IP is in threat feeds (botnet C2 or Tor exit)
     */
    public checkIp(ip?: string | null): IntelMatch | null {
        if (!ip) return null;

        if (this.botnetIps.has(ip)) {
            return {
                type: 'IP',
                value: ip,
                source: 'Feodo Tracker (abuse.ch)',
                description: 'Botnet C2 Server',
                severity: 'CRITICAL'
            };
        }

        if (this.torExits.has(ip)) {
            return {
                type: 'IP',
                value: ip,
                source: 'Tor Project',
                description: 'Tor Exit Node',
                severity: 'HIGH'
            };
        }

        return null;
    }

    /**
     * Check if a hash is known malware
     */
    public checkHash(hash?: string | null): IntelMatch | null {
        if (!hash) return null;

        const normalized = hash.toLowerCase().trim();

        if (this.malwareHashes.has(normalized)) {
            return {
                type: 'HASH',
                value: normalized,
                source: 'MalwareBazaar (abuse.ch)',
                description: 'Known Malware Sample',
                severity: 'CRITICAL'
            };
        }

        return null;
    }

    /**
     * Check if a domain is known malicious
     */
    public checkDomain(domain?: string | null): IntelMatch | null {
        if (!domain) return null;

        const normalized = domain.toLowerCase().trim();

        if (this.malwareDomains.has(normalized)) {
            return {
                type: 'DOMAIN',
                value: normalized,
                source: 'URLhaus (abuse.ch)',
                description: 'Malware Distribution Site',
                severity: 'CRITICAL'
            };
        }

        return null;
    }

    /**
     * Extract domain from URL and check
     */
    public checkUrl(url?: string | null): IntelMatch | null {
        if (!url) return null;

        try {
            const parsed = new URL(url);
            return this.checkDomain(parsed.hostname);
        } catch {
            // If URL parsing fails, try as domain
            return this.checkDomain(url);
        }
    }

    /**
     * Check all IOCs from an event
     */
    public checkEvent(event: {
        network?: { src_ip?: string | null; dst_ip?: string | null };
        process?: { command_line?: string | null };
        dns?: { query_name?: string | null };
    }): IntelMatch | null {
        // Check IPs
        const srcMatch = this.checkIp(event.network?.src_ip);
        if (srcMatch) return srcMatch;

        const dstMatch = this.checkIp(event.network?.dst_ip);
        if (dstMatch) return dstMatch;

        // Check DNS queries
        const dnsMatch = this.checkDomain(event.dns?.query_name);
        if (dnsMatch) return dnsMatch;

        // Check for URLs/domains in command line (basic extraction)
        const cmdLine = event.process?.command_line;
        if (cmdLine) {
            // Extract potential URLs/domains from command line
            const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
            let match;
            while ((match = ipPattern.exec(cmdLine)) !== null) {
                const domainMatch = this.checkDomain(match[0]);
                if (domainMatch) return domainMatch;
            }
        }

        return null;
    }

    /**
     * Auto-detect internet connectivity
     */
    public async detectConnectivity(): Promise<boolean> {
        if (this.isOnline !== null) return this.isOnline;

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3000);

            const response = await fetch('https://urlhaus-api.abuse.ch/v1/', {
                method: 'HEAD',
                signal: controller.signal
            });

            clearTimeout(timeout);
            this.isOnline = response.ok;
            return this.isOnline;
        } catch {
            this.isOnline = false;
            return false;
        }
    }

    /**
     * Get online status (cached after first check)
     */
    public getOnlineStatus(): boolean | null {
        return this.isOnline;
    }

    /**
     * Online mode: Query URLhaus API for a specific URL
     */
    public async checkUrlOnline(url: string): Promise<UrlCheckResult | null> {
        try {
            const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `url=${encodeURIComponent(url)}`
            });

            if (!response.ok) return null;

            const data = await response.json() as { query_status: string; threat?: string; tags?: string[] };

            if (data.query_status === 'ok') {
                return {
                    found: true,
                    threat: data.threat || 'Malware Distribution',
                    tags: data.tags || [],
                    source: 'URLhaus (abuse.ch)'
                };
            }

            return { found: false };
        } catch {
            return null;
        }
    }

    /**
     * Online mode: Query URLhaus API for a specific host/domain
     */
    public async checkHostOnline(host: string): Promise<UrlCheckResult | null> {
        try {
            const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `host=${encodeURIComponent(host)}`
            });

            if (!response.ok) return null;

            const data = await response.json() as { query_status: string; url_count?: number; blacklists?: { spamhaus_dbl?: string } };

            if (data.query_status === 'ok' && data.url_count && data.url_count > 0) {
                return {
                    found: true,
                    threat: `${data.url_count} malicious URLs known`,
                    tags: data.blacklists?.spamhaus_dbl ? ['spamhaus'] : [],
                    source: 'URLhaus (abuse.ch)'
                };
            }

            return { found: false };
        } catch {
            return null;
        }
    }

    /**
     * For URLs - offline mode returns guidance for manual check
     */
    public getUrlCheckGuidance(url: string): string {
        let domain = url;
        try {
            const parsed = new URL(url);
            domain = parsed.hostname;
        } catch {
            // Use as-is
        }

        return `Verify at: https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`;
    }
}
