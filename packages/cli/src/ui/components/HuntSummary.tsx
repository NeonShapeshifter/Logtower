import React from 'react';
import { Box, Text } from 'ink';
import { Finding } from '@neonshapeshifter/logtower-core';

type HuntSummaryProps = {
  stats: Record<string, number>;
  topSeverity: Finding[];
  topCount: Finding[];
};

export const HuntSummary = ({ stats, topSeverity, topCount }: HuntSummaryProps) => {
  return (
    <Box flexDirection="column" paddingLeft={1}>
        {/* Stats Row */}
        <Box marginBottom={1}>
            <Text>
                CRIT:<Text color="red" bold>{stats.CRITICAL}</Text> | 
                HIGH:<Text color="magenta" bold>{stats.HIGH}</Text> | 
                MED:<Text color="yellow" bold>{stats.MEDIUM}</Text> | 
                LOW:<Text color="cyan" bold>{stats.LOW}</Text>
            </Text>
        </Box>

        {/* Top Lists */}
        <Box flexDirection="row">
            {/* Severity Column */}
            <Box flexDirection="column" width="50%" paddingRight={1}>
                <Text underline bold>Top 5 Severity</Text>
                {topSeverity.length === 0 ? <Text dimColor>None</Text> : 
                 topSeverity.map((f, i) => (
                    <Box key={f.id} flexDirection="row">
                         <Text bold color={f.severity === 'CRITICAL' ? 'red' : f.severity === 'HIGH' ? 'magenta' : 'yellow'}>
                             [{f.severity.substring(0,1)}] 
                         </Text>
                         <Text wrap="truncate-end"> {f.title}</Text>
                    </Box>
                 ))
                }
            </Box>

            {/* Count Column */}
            <Box flexDirection="column" width="50%">
                <Text underline bold>Top 5 Volume</Text>
                {topCount.length === 0 ? <Text dimColor>None</Text> : 
                 topCount.map((f, i) => (
                    <Box key={f.id} flexDirection="row">
                         <Text bold>({f.evidence.length}) </Text>
                         <Text wrap="truncate-end">{f.title}</Text>
                    </Box>
                 ))
                }
            </Box>
        </Box>
    </Box>
  );
};
