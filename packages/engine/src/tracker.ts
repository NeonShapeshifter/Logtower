import { LogtowerEvent, Finding } from '@neonshapeshifter/logtower-core';

export interface GraphNode {
  id: string; // IP or Hostname
  type: 'IP' | 'HOST';
  isPatientZero?: boolean;
  findings?: Finding[];
  maxSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface GraphEdge {
  from: string;
  to: string;
  user: string;
  method: string; // RDP, SMB, WMI, NETWORK
  timestamp: string;
  count: number;
}

const SEVERITY_WEIGHT = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
};

export class LateralTracker {
  private nodes: Map<string, GraphNode> = new Map();
  private edges: Map<string, GraphEdge> = new Map();

  public processEvent(event: LogtowerEvent) {
    // 1. Inbound Logons (4624) on Destination
    if (event.event_id === 4624) {
        // Ignore SYSTEM/Machine accounts for cleaner graph
        if (event.user?.name?.endsWith('$') || event.user?.name === 'SYSTEM') return;

        const dest = event.host;
        const srcIp = event.network?.src_ip;
        const srcHost = event.auth?.workstation;
        const user = event.user?.name || 'unknown';
        const logonType = event.auth?.logon_type;

        // Filter local logons (Source loopback)
        if (srcIp === '127.0.0.1' || srcIp === '::1') return;

        // We prefer Source Hostname, fallback to IP
        let source = srcHost;
        if (!source || source === '-') source = srcIp;
        
        if (source && dest && source !== dest) {
            this.addConnection(source, dest, user, `LOGON_${logonType}`, event.timestamp);
        }
    }

    // 2. Outbound Network Connections (Sysmon 3) from Source
    if (event.event_id === 3) {
        const src = event.host;
        const destIp = event.network?.dst_ip;
        const image = event.process?.image;
        const port = event.network?.dst_port;

        // Filter noisy ports (optional)
        if (destIp && src) {
             const method = `NET:${port} (${image?.split('\\').pop()})`;
             this.addConnection(src, destIp, event.user?.name || '?', method, event.timestamp);
        }
    }

    // 3. Logon Failure (4625)
    if (event.event_id === 4625) {
        const dest = event.host;
        const srcIp = event.network?.src_ip;
        const user = event.user?.name || 'unknown';
        const failureCode = event.auth?.failure_code || 'Unknown';

        // Ignore local loopback
        if (srcIp === '127.0.0.1' || srcIp === '::1' || !srcIp) return;

        // For 4625, we often only have IP, rarely WorkstationName reliably in all versions
        // We use srcIp as source
        
        if (srcIp && dest) {
            this.addConnection(srcIp, dest, user, `FAILED_LOGON (${failureCode})`, event.timestamp);
        }
    }
  }

  public enrichWithFindings(findings: Finding[]) {
      findings.forEach(f => {
          // Try to find the node by Hostname or IP
          const node = this.nodes.get(f.host);
          
          // Fallback: Check if we have a node matching src_ip if host is unknown?
          // Usually detection happens on 'host', so mapping by f.host is safest.
          
          if (node) {
              if (!node.findings) node.findings = [];
              node.findings.push(f);

              // Update Max Severity
              const currentWeight = node.maxSeverity ? SEVERITY_WEIGHT[node.maxSeverity] : -1;
              const newWeight = SEVERITY_WEIGHT[f.severity];
              if (newWeight > currentWeight) {
                  node.maxSeverity = f.severity;
              }
          }
      });
  }

  private addConnection(from: string, to: string, user: string, method: string, ts: string) {
      const key = `${from}->${to}|${method}|${user}`;
      
      this.ensureNode(from);
      this.ensureNode(to);

      if (this.edges.has(key)) {
          const edge = this.edges.get(key)!;
          edge.count++;
          // Keep first timestamp or last? Tracking first occurrence usually indicates start of movement
      } else {
          this.edges.set(key, {
              from,
              to,
              user,
              method,
              timestamp: ts,
              count: 1
          });
      }
  }

  private ensureNode(id: string) {
      if (!this.nodes.has(id)) {
          const type = /^\d{1,3}\./.test(id) ? 'IP' : 'HOST';
          this.nodes.set(id, { id, type });
      }
  }

  public getGraph() {
      // Logic to determine Patient Zero (simplistic: node with OutDegree > 0 and InDegree == 0)
      const inDegree = new Map<string, number>();
      const timestamps: number[] = [];

      this.edges.forEach(e => {
          inDegree.set(e.to, (inDegree.get(e.to) || 0) + 1);
          if (e.timestamp) timestamps.push(new Date(e.timestamp).getTime());
      });

      const nodes = Array.from(this.nodes.values()).map(n => ({
          ...n,
          isPatientZero: (inDegree.get(n.id) || 0) === 0 && this.edges.size > 0 // Only patient zero if edges exist
      }));

      // Calculate Time Window
      let timeWindow = 'N/A';
      if (timestamps.length > 0) {
          const min = new Date(Math.min(...timestamps));
          const max = new Date(Math.max(...timestamps));
          // Format duration
          const diffMs = max.getTime() - min.getTime();
          const diffMins = Math.round(diffMs / 60000);
          timeWindow = `${diffMins} mins (${min.toISOString().split('T')[1]?.split('.')[0]} - ${max.toISOString().split('T')[1]?.split('.')[0]})`;
      }

      return {
          nodes,
          edges: Array.from(this.edges.values()),
          stats: {
              hosts: nodes.filter(n => n.type === 'HOST').length,
              ips: nodes.filter(n => n.type === 'IP').length,
              connections: this.edges.size,
              uniqueUsers: new Set(Array.from(this.edges.values()).map(e => e.user)).size,
              timeWindow
          }
      };
  }
}
