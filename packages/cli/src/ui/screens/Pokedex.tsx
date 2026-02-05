import React, { useState } from 'react';
import { Box, Text, useInput, useApp } from 'ink';
import { Rule } from '@neonshapeshifter/logtower-engine';

type PokedexProps = {
    matches: Rule[];
    onBack: () => void;
};

const SEVERITY_LABELS: Record<string, string> = {
    'CRITICAL': '[CRIT]',
    'HIGH': '[HIGH]',
    'MEDIUM': '[MED]',
    'LOW': '[LOW]',
    'INFO': '[INFO]'
};

const DetailView = ({ rule }: { rule: Rule }) => {
    const label = SEVERITY_LABELS[rule.severity] || '[?]';
    const mitre = rule.mitre ? `(${rule.mitre.join(', ')})` : '';
    
    // Fallbacks if data is missing
    const description = rule.description || "No tactical description available for this threat.";
    const responseSteps = rule.response_steps || [
        "1. TRIAGE: Validate if the activity is authorized.",
        "2. ISOLATE: If unauthorized, isolate the host.",
        "3. INVESTIGATE: Review process tree and parent processes."
    ];

    // Calculate width for the box (fixed or dynamic)
    const BOX_WIDTH = 70;

    return (
        <Box flexDirection="column" padding={1}>
            {/* HEADER */}
            <Box borderStyle="single" borderBottom={false} borderColor="cyan" width={BOX_WIDTH}>
                <Text bold color="cyan"> {label} {rule.title.toUpperCase()} {mitre}</Text>
            </Box>

            {/* BODY */}
            <Box borderStyle="single" borderColor="white" flexDirection="column" width={BOX_WIDTH} padding={1}>
                
                {/* DESCRIPTION */}
                <Box flexDirection="column" marginBottom={1}>
                    <Text bold underline>DESCRIPTION:</Text>
                    <Text>{description}</Text>
                </Box>

                {/* METADATA */}
                <Box flexDirection="column" marginBottom={1}>
                    <Text>SEVERITY: <Text bold color={rule.severity === 'CRITICAL' ? 'red' : rule.severity === 'HIGH' ? 'magenta' : 'yellow'}>{rule.severity}</Text></Text>
                    <Text>MODULE:   {rule.module || 'N/A'}</Text>
                    <Text>ID:       {rule.id}</Text>
                </Box>

                {/* DETECTION LOGIC SUMMARY (Simplified) */}
                <Box flexDirection="column" marginBottom={1}>
                    <Text bold underline>DETECTED BY (Logic):</Text>
                    {Object.entries(rule.detection.selection).map(([key, val]) => (
                        <Text key={key}> - {key}: <Text color="green">{Array.isArray(val) ? val.join(' OR ') : String(val)}</Text></Text>
                    ))}
                </Box>

                {/* RESPONSE PROTOCOL */}
                <Box flexDirection="column">
                    <Text bold underline>RESPONSE (The Protocol):</Text>
                    {responseSteps.map((step: string, i: number) => (
                        <Text key={i} color="white">{step}</Text>
                    ))}
                </Box>

            </Box>
            
            <Box marginTop={0}>
                <Text dimColor>Press 'ESC' to return to list, 'q' to exit.</Text>
            </Box>
        </Box>
    );
};

export const Pokedex = ({ matches, onBack }: PokedexProps) => {
    const { exit } = useApp();
    const [selectedIndex, setSelectedIndex] = useState(0);
    const [viewMode, setViewMode] = useState<'LIST' | 'DETAIL'>(matches.length === 1 ? 'DETAIL' : 'LIST');

    useInput((input, key) => {
        if (key.escape) {
            if (viewMode === 'DETAIL' && matches.length > 1) {
                setViewMode('LIST');
            } else {
                onBack();
            }
            return;
        }

        if (viewMode === 'LIST') {
            if (key.upArrow) {
                setSelectedIndex(prev => Math.max(0, prev - 1));
            }
            if (key.downArrow) {
                setSelectedIndex(prev => Math.min(matches.length - 1, prev + 1));
            }
            if (key.return) {
                setViewMode('DETAIL');
            }
        }
    });

    if (viewMode === 'DETAIL') {
        return <DetailView rule={matches[selectedIndex]} />;
    }

    // LIST VIEW - SMOOTH SCROLLING (Clean & Tall)
    const VIEW_HEIGHT = 30;
    
    // Calculate the start of the window based on selectedIndex
    let windowStart = 0;
    if (selectedIndex >= VIEW_HEIGHT) {
        windowStart = selectedIndex - VIEW_HEIGHT + 1;
    }
    
    const visibleMatches = matches.slice(windowStart, windowStart + VIEW_HEIGHT);

    // FIXED HEIGHT CONTAINER
    return (
        <Box flexDirection="column" borderStyle="single" borderColor="blue" padding={1} height={VIEW_HEIGHT + 6} width={100}>
            {/* CLEAN HEADER */}
            <Box marginBottom={1} justifyContent="space-between">
                <Text bold color="cyan">[RULE CATALOG]</Text>
                <Text dimColor>Loaded: {matches.length} detection rules</Text>
            </Box>

            <Box borderStyle="single" borderColor="grey" borderTop={false} borderLeft={false} borderRight={false} marginBottom={1} />
            
            <Box flexDirection="column" height={VIEW_HEIGHT}>
                {visibleMatches.map((rule, i) => {
                    const isSelected = (windowStart + i) === selectedIndex;
                    return (
                        <Box key={rule.id}>
                            <Text color={isSelected ? 'cyan' : 'white'} bold={isSelected}>
                                {isSelected ? '> ' : '  '} {rule.title.slice(0, 90)} 
                            </Text>
                            <Text dimColor> ({rule.id})</Text>
                        </Box>
                    );
                })}
            </Box>
            
            <Box marginTop={1} justifyContent="space-between" borderStyle="single" borderColor="grey" borderBottom={false} borderLeft={false} borderRight={false} paddingTop={1}>
                <Text dimColor>↑/↓ Scroll | Enter: Details | ESC: Exit</Text>
                <Text dimColor>Page {Math.ceil((windowStart + 1) / VIEW_HEIGHT)} | {windowStart + 1}-{Math.min(windowStart + VIEW_HEIGHT, matches.length)} of {matches.length}</Text>
            </Box>
        </Box>
    );
};