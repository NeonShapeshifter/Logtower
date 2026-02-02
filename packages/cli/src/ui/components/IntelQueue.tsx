import React from 'react';
import { Box, Text } from 'ink';
import { Finding } from '@neonshapeshifter/logtower-core';
import { CriticalQueueProps } from '../types/index.js';

export const CriticalQueue = ({ findings, height, intelStatus }: CriticalQueueProps) => {
    // Filter: Intel hits OR Critical severity findings
    const criticalFindings = findings.filter(f => f.intel || f.severity === 'CRITICAL');

    // Sort: Intel first, then by evidence count
    const sorted = [...criticalFindings].sort((a, b) => {
        if (a.intel && !b.intel) return -1;
        if (!a.intel && b.intel) return 1;
        return b.evidence.length - a.evidence.length;
    });

    const maxLines = Math.max(1, height - 3);

    // Intel status
    const { loaded, online } = intelStatus;
    const onlineLabel = online === null ? 'checking...' : online ? 'ONLINE' : 'OFFLINE';
    const onlineColor = online === null ? 'yellow' : online ? 'green' : 'grey';

    return (
        <Box flexDirection="column" height={height} borderStyle="double" borderColor="red" marginBottom={1}>
            <Box justifyContent="space-between" paddingX={1}>
                <Text bold color="red">[!] CRITICAL FINDINGS ({sorted.length})</Text>
                {loaded ? (
                    <Text color={onlineColor}>[Intel: {onlineLabel}]</Text>
                ) : (
                    <Text dimColor>[Intel: OFF]</Text>
                )}
            </Box>
            <Box flexDirection="column" paddingX={1} overflow="hidden">
                {sorted.length === 0 ? (
                    <Text color="green">No critical threats detected.</Text>
                ) : (
                    sorted.slice(0, maxLines).map((f, i) => (
                        <Box key={f.id} flexDirection="row">
                            {f.intel ? (
                                <>
                                    <Text color="red" bold>[INTEL] </Text>
                                    <Text color="white" wrap="truncate-end">
                                        [{f.intel.type}] {f.intel.value}
                                    </Text>
                                    <Text dimColor> - {f.intel.description}</Text>
                                </>
                            ) : (
                                <>
                                    <Text color="red" bold>[CRIT] </Text>
                                    <Text color="white" wrap="truncate-end">
                                        {f.title}
                                    </Text>
                                    <Text dimColor> ({f.evidence.length})</Text>
                                </>
                            )}
                        </Box>
                    ))
                )}
                {sorted.length > maxLines && (
                    <Text dimColor>... +{sorted.length - maxLines} more</Text>
                )}
            </Box>
        </Box>
    );
};

// Keep old name as alias for backwards compatibility
export const IntelQueue = CriticalQueue;
