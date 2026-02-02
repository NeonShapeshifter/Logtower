import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import { GraphNode, GraphEdge } from '@neonshapeshifter/logtower-engine';

type LateralViewProps = {
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    stats: {
        hosts: number;
        ips: number;
        connections: number;
        uniqueUsers: number;
        timeWindow: string;
    };
  };
  onBack: () => void;
};

export const LateralView = ({ graph, onBack }: LateralViewProps) => {
  const [viewMode, setViewMode] = useState<'TREE' | 'TABLE'>('TREE');

  useInput((input, key) => {
    if (key.escape || input === 'q') {
      onBack();
    }
    if (key.tab || input === 'v') {
      setViewMode(prev => prev === 'TREE' ? 'TABLE' : 'TREE');
    }
  });

  // --- TREE VIEW LOGIC ---
  const renderTree = () => {
    if (graph.nodes.length === 0) return <Text color="yellow">No lateral movement detected.</Text>;

    const elements: React.ReactNode[] = [];
    const visited = new Set<string>();

    const buildTreeElements = (nodeId: string, prefix: string, isLast: boolean) => {
        if (visited.has(nodeId)) {
            elements.push(
                <Text key={`${nodeId}-cycle`}>
                    {prefix}{isLast ? '└── ' : '├── '}<Text color="dim">[Cyclic] {nodeId}</Text>
                </Text>
            );
            return;
        }
        visited.add(nodeId);

        const node = graph.nodes.find(n => n.id === nodeId);
        const nodeLabel = node?.type === 'IP' ? `[IP: ${nodeId}]` : `[HOST: ${nodeId}]`;
        const marker = node?.isPatientZero ? ' (PATIENT ZERO)' : '';
        
        // Threat Analysis - Sort by severity first
        const findings = node?.findings || [];
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
        const sortedFindings = [...findings].sort((a, b) => severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder]);
        const uniqueThreats = Array.from(new Set(sortedFindings.map(f => f.title))).slice(0, 2); 
        const threatCount = findings.length;
        const threatLabel = threatCount > 0 ? ` [!] [${uniqueThreats.join(', ')}${threatCount > 2 ? '...' : ''}]` : '';
        
        const nodeColor = node?.maxSeverity === 'CRITICAL' ? 'red' : 
                          node?.maxSeverity === 'HIGH' ? 'magenta' : 
                          node?.maxSeverity === 'MEDIUM' ? 'yellow' : 
                          node?.isPatientZero ? 'cyan' : 'white';

        elements.push(
            <Text key={nodeId}>
                {prefix}{isLast ? '└── ' : '├── '}<Text color={nodeColor} bold>{nodeLabel}{marker}</Text><Text color="red">{threatLabel}</Text>
            </Text>
        );

        const outgoing = graph.edges.filter(e => e.from === nodeId);
        outgoing.forEach((edge, i) => {
            const isLastEdge = i === outgoing.length - 1;
            const newPrefix = prefix + (isLast ? '    ' : '│   ');
            
            const isFailed = edge.method.startsWith('FAILED');
            const linkColor = isFailed ? 'red' : 'green';
            const arrow = isFailed ? '-x-' : '-->';

            elements.push(
                <Text key={`${nodeId}-${edge.to}-${i}`} dimColor>
                    {newPrefix}│
                </Text>
            );
            elements.push(
                <Text key={`${nodeId}-${edge.to}-${i}-link`}>
                    {newPrefix}├── --[ <Text color={linkColor}>{edge.method}</Text> | {edge.user} ]--{'>'}
                </Text>
            );
            buildTreeElements(edge.to, newPrefix, isLastEdge);
        });
    };

    const patients = graph.nodes.filter(n => n.isPatientZero);
    const starters = patients.length > 0 ? patients : [graph.nodes[0]];

    starters.forEach((startNode, i) => {
        buildTreeElements(startNode.id, '', i === starters.length - 1);
        elements.push(<Text key={`spacer-${i}`}> </Text>); 
    });

    return (
      <Box flexDirection="column">
        {elements}
      </Box>
    );
  };

  // --- TABLE VIEW LOGIC ---
  const renderTable = () => {
      // Group by Source + User
      const summary = new Map<string, { source: string, user: string, targets: Set<string>, methods: Set<string> }>();

      graph.edges.forEach(edge => {
          const key = `${edge.from}|${edge.user}`;
          if (!summary.has(key)) {
              summary.set(key, { source: edge.from, user: edge.user, targets: new Set(), methods: new Set() });
          }
          const entry = summary.get(key)!;
          entry.targets.add(edge.to);
          entry.methods.add(edge.method);
      });

      const rows = Array.from(summary.values());

      return (
          <Box flexDirection="column">
              <Box borderStyle="single" borderColor="cyan" paddingX={1}>
                  <Box width={20}><Text bold color="cyan">USER</Text></Box>
                  <Box width={25}><Text bold color="cyan">SOURCE</Text></Box>
                  <Box width={30}><Text bold color="cyan">TARGETS</Text></Box>
                  <Box width={20}><Text bold color="cyan">PROTOCOLS</Text></Box>
              </Box>
              {rows.map((row, i) => (
                  <Box key={i} borderStyle="single" borderColor="grey" paddingX={1}>
                      <Box width={20}><Text wrap="truncate-end">{row.user}</Text></Box>
                      <Box width={25}><Text wrap="truncate-end">{row.source}</Text></Box>
                      <Box width={30}><Text wrap="truncate-end">{Array.from(row.targets).join(', ')}</Text></Box>
                      <Box width={20}><Text wrap="truncate-end">{Array.from(row.methods).join(', ')}</Text></Box>
                  </Box>
              ))}
              {rows.length === 0 && <Text>No movements to display.</Text>}
          </Box>
      );
  };

  return (
    <Box flexDirection="column" padding={1}>
        <Box borderStyle="double" borderColor="magenta" paddingX={1} marginBottom={1} flexDirection="column" alignItems="center">
            <Text bold>LATERAL MOVEMENT SCOUT</Text>
            <Box marginTop={0} justifyContent="space-between" width={80}>
                 <Text>Hosts: {graph.stats.hosts} | IPs: {graph.stats.ips}</Text>
                 <Text>Edges: {graph.stats.connections}</Text>
                 <Text>Users: {graph.stats.uniqueUsers}</Text>
                 <Text>Window: {graph.stats.timeWindow}</Text>
            </Box>
        </Box>
        
        <Box marginBottom={1}>
            <Text>Current View: </Text>
            <Text bold color={viewMode === 'TREE' ? 'green' : 'white'} backgroundColor={viewMode === 'TREE' ? 'green' : undefined}> [ TREE GRAPH ] </Text>
            <Text> </Text>
            <Text bold color={viewMode === 'TABLE' ? 'green' : 'white'} backgroundColor={viewMode === 'TABLE' ? 'green' : undefined}> [ SUMMARY TABLE ] </Text>
        </Box>

        <Box borderStyle="round" borderColor="white" padding={1}>
            {viewMode === 'TREE' ? renderTree() : renderTable()}
        </Box>

        <Box marginTop={1}>
            <Text dimColor>TAB: Switch View | q: Quit</Text>
        </Box>
    </Box>
  );
};