import React, { useState, useEffect, useMemo } from 'react';
import { Box, Text, useInput } from 'ink';
import { Finding, getSampleEvidence, sortFindings, filterFindings, FilterMode } from '@neonshapeshifter/logtower-core';
import { useWindowSize } from '../hooks/useWindowSize.js';
import { useHuntSummary } from '../hooks/useHuntSummary.js';
import { HuntSummary } from './HuntSummary.js';
import { CriticalQueue } from './IntelQueue.js';
import { SplitViewProps } from '../types/index.js';

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

export const SplitView = ({ logs, findings, processedCount, isProcessing, activeEngines, ruleset, onBack, onCancel, replVisible, onToggleRepl, intelStatus }: SplitViewProps) => {
  const [columns, rows] = useWindowSize();
  const [filterMode, setFilterMode] = useState<FilterMode>('IMPORTANT');
  const [showWarning, setShowWarning] = useState(false);
  const [showSummary, setShowSummary] = useState(false);

  const { stats, topSeverity, topCount } = useHuntSummary(findings);
  const criticalCount = findings.filter(f => f.intel || f.severity === 'CRITICAL').length;

  // Clear warning after timeout or when processing stops
  useEffect(() => {
    if (!isProcessing) {
        setShowWarning(false);
    }
    
    if (showWarning) {
      const timer = setTimeout(() => setShowWarning(false), 3000);
      return () => clearTimeout(timer);
    }
  }, [showWarning, isProcessing]);
  
  // Layout Math
  const globalHeaderHeight = 2; // For the box border and text
  const footerHeight = 3; 
  const bodyHeight = Math.max(10, rows - footerHeight - globalHeaderHeight); 

  // Right Panel Heights
  const intelHeight = Math.floor(bodyHeight * 0.20); 
  const radarHeight = Math.floor(bodyHeight * 0.35); 
  const inspectorHeight = bodyHeight - intelHeight - radarHeight - 2; // -2 for margins

  // Left Panel Heights
  const streamHeight = Math.floor(bodyHeight * 0.45);
  const detailHeight = bodyHeight - streamHeight - 1;

  // 1. Stream (Left)
  const maxStreamLines = streamHeight - 2; 
  const visibleLogs = logs.slice(-maxStreamLines);
  const latestLog = logs[logs.length - 1];

  // 2. Radar Logic (Filtering & Sorting)
  const visibleFindings = useMemo(() => {
    return sortFindings(filterFindings(findings, filterMode));
  }, [findings, filterMode]);

  const hiddenCount = findings.length - visibleFindings.length;

  // Selection State
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Auto-select first if nothing selected and findings exist
  useEffect(() => {
      const exists = visibleFindings.find((f: Finding) => f.id === selectedId);
      if (!exists && visibleFindings.length > 0) {
          setSelectedId(visibleFindings[0].id);
      } else if (visibleFindings.length === 0) {
          setSelectedId(null);
      }
  }, [visibleFindings, selectedId]);

  // Ensure selection stays valid
  const activeFinding = useMemo(() => 
      visibleFindings.find((f: Finding) => f.id === selectedId) || visibleFindings[0] || null, 
  [selectedId, visibleFindings]);

  // 3. Inspector Content (Adaptive View)
  const inspectorContent = useMemo(() => {
    if (!activeFinding) return "Waiting for detections...";
    
    let details = '';
    const f = activeFinding;

    // A. THREAT INTEL CARD (High Priority)
    if (f.intel) {
        details += `[THREAT INTEL MATCH]\n`;
        details += `Indicator: ${f.intel.value}\n`;
        details += `Type:      ${f.intel.description}\n`;
        details += `Source:    ${f.intel.source}\n`;
        details += `----------------------------------------\n`;
    }

    // B. WMI PERSISTENCE (New!)
    if (f.wmi && (f.wmi.consumer || f.wmi.filter || f.wmi.query)) {
        details += `[WMI PERSISTENCE]\n`;
        if (f.wmi.operation) details += `Op:      ${f.wmi.operation}\n`;
        if (f.wmi.consumer)  details += `Consumer:${f.wmi.consumer}\n`;
        if (f.wmi.filter)    details += `Filter:  ${f.wmi.filter}\n`;
        if (f.wmi.query)     details += `Query:   ${f.wmi.query}\n`;
        if (f.wmi.destination) details += `Dest:    ${f.wmi.destination}\n`;
    }
    // C. AD CHANGE / GPO / ACL (New!)
    else if (f.ad_change && f.ad_change.object_dn) {
        details += `[AD DIRECTORY CHANGE]\n`;
        details += `Object:  ${f.ad_change.object_dn}\n`;
        details += `Attrib:  ${f.ad_change.attribute}\n`;
        if (f.ad_change.value) details += `Value:   ${f.ad_change.value}\n`;
        details += `Class:   ${f.ad_change.class}\n`;
    }
    // D. INJECTION / PROCESS ACCESS (Updated)
    else if (f.process && (f.process.target_image || f.process.source_image)) {
        details += `[PROCESS INJECTION / ACCESS]\n`;
        details += `Source:  ${f.process.source_image || f.process.image || 'Unknown'}\n`;
        details += `Target:  ${f.process.target_image || 'Unknown'}\n`;
        if (f.process.start_function) details += `Function:${f.process.start_function}\n`;
        if (f.process.start_address)  details += `Address: ${f.process.start_address}\n`;
        if (f.process.granted_access) details += `Access:  ${f.process.granted_access}\n`;
        if (f.process.pid)            details += `PID:     ${f.process.pid}\n`;
    }
    // E. BITS JOB
    else if (f.bits && f.bits.job_title) {
        details += `[BITS JOB]\n`;
        details += `Title:   ${f.bits.job_title}\n`;
        if (f.bits.file_name) details += `File:    ${f.bits.file_name}\n`;
        if (f.bits.url)       details += `URL:     ${f.bits.url}\n`;
        if (f.bits.client_app)details += `Client:  ${f.bits.client_app}\n`;
    }
    // F. REGISTRY CARD
    else if (f.registry && f.registry.target_object) {
        details += `[REGISTRY EVENT]\n`;
        details += `Key:   ${f.registry.target_object}\n`;
        if (f.registry.details) details += `Value: ${f.registry.details}\n`;
        if (f.process?.image)   details += `Image: ${f.process.image}\n`;
    }
    // G. SERVICE CARD
    else if (f.service && f.service.image_path) {
        details += `[SERVICE INSTALLATION]\n`;
        details += `Name: ${f.service.service_name || 'Unknown'}\n`;
        details += `Path: ${f.service.image_path}\n`;
    }
    // H. IMAGE LOAD (DLL)
    else if (f.image_load && f.image_load.file_name) {
        details += `[DLL SIDELOADING]\n`;
        details += `DLL:  ${f.image_load.file_name}\n`;
        details += `Path: ${f.image_load.file_path}\n`;
        if (f.process?.image) details += `Host: ${f.process.image}\n`;
    }
    // I. GENERIC PROCESS EXECUTION
    else if (f.process && f.process.image) {
        details += `[PROCESS EXECUTION]\n`;
        details += `Image:   ${f.process.image}\n`;
        details += `CmdLine: ${f.process.command_line || 'N/A'}\n`;
        details += `Parent:  ${f.process.parent_image || '?'}\n`;
    }
    // J. TASK
    else if (f.task && f.task.task_name) {
        details += `[SCHEDULED TASK]\n`;
        details += `Name: ${f.task.task_name}\n`;
        if (f.task.action) details += `Action: ${f.task.action}\n`;
        const raw = f.evidence[0]?.raw_event || {};
        if (raw['TaskContent']) details += `Content Snippet: ${raw['TaskContent'].substring(0, 100)}...\n`;
    }

    const evidenceList = f.evidence.slice(-3).map((e: any, i: number) =>
        `• [${e.event_ts.split('T')[1]?.split('.')[0] || e.event_ts}] ${e.summary}`
    ).join('\n');

    return `${details}\n` +
           `[RECENT EVIDENCE (${f.evidence.length})]\n${evidenceList}\n\n` +
           `Use 'info ${f.rule_id}' for full details, MITRE mapping, and response steps.`;
  }, [activeFinding]);

  const inspectorLines = useMemo(() => inspectorContent.split('\n'), [inspectorContent]);
  
  // Scroll State
  const [scrollOffset, setScrollOffset] = useState(0);
  const visibleInspectorLinesCount = Math.max(1, inspectorHeight - 2);
  const maxScroll = Math.max(0, inspectorLines.length - visibleInspectorLinesCount);

  useInput((input, key) => {
    // 1. Toggle REPL (Always active)
    if (key.tab) {
        onToggleRepl();
        return;
    }

    // 2. If REPL is visible (Write Mode), block navigation
    if (replVisible) {
        if (key.ctrl && input === 'c' && isProcessing) {
             onCancel();
        }
        if (key.escape && !isProcessing) {
            onBack();
        }
        return; 
    }

    // 3. Navigation Mode (replVisible = false)

    // Back Logic (Esc, q)
    if (key.escape || input === 'q') {
        if (isProcessing) {
            setShowWarning(true);
            return;
        }
        onBack();
        return;
    }

    // Cancel Logic (Ctrl+C)
    if (key.ctrl && input === 'c') {
        if (isProcessing) {
            onCancel();
        }
        return; 
    }

    // Toggle Summary
    if (input === 's') {
        setShowSummary(prev => !prev);
        return;
    }

    // Navigation (Radar)
    if (key.downArrow) {
        const idx = visibleFindings.findIndex((f: Finding) => f.id === activeFinding?.id);
        if (idx < visibleFindings.length - 1) setSelectedId(visibleFindings[idx + 1].id);
    }
    if (key.upArrow) {
        const idx = visibleFindings.findIndex((f: Finding) => f.id === activeFinding?.id);
        if (idx > 0) setSelectedId(visibleFindings[idx - 1].id);
    }

    // Scroll (Inspector)
    if (key.pageDown) setScrollOffset(prev => clamp(prev + 5, 0, maxScroll));
    if (key.pageUp) setScrollOffset(prev => clamp(prev - 5, 0, maxScroll));
    
    // Toggle Filter
    if (input === 'f') {
        setFilterMode((prev: FilterMode) => {
            if (prev === 'IMPORTANT') return 'CRITICAL';
            if (prev === 'CRITICAL') return 'HIGH';
            if (prev === 'HIGH') return 'ALL';
            return 'IMPORTANT';
        });
    }
  });

  const visibleInspectorText = inspectorLines.slice(scrollOffset, scrollOffset + visibleInspectorLinesCount);

  const maxRadarLines = radarHeight - 2;
  const selectedIdx = visibleFindings.findIndex((f: Finding) => f.id === activeFinding?.id);
  let listStartIndex = 0;
  if (selectedIdx >= maxRadarLines) {
      listStartIndex = selectedIdx - maxRadarLines + 1;
  }
  const visibleRadarFindings = visibleFindings.slice(listStartIndex, listStartIndex + maxRadarLines);

  return (
    <Box flexDirection="column" height={rows}>
        {/* GLOBAL HEADER */}
        <Box borderStyle="single" height={globalHeaderHeight + 2} borderColor="white" justifyContent="space-between">
            <Text bold>HEADER: Logtower v1.0</Text>
            {criticalCount > 0 ? (
                <Text bold color="red">[!] CRITICAL: {criticalCount} threats detected</Text>
            ) : (
                <Text color="green">[OK] No critical threats</Text>
            )}
        </Box>

        <Box flexDirection="row" height={bodyHeight}>
            {/* LEFT COLUMN */}
            <Box flexDirection="column" width="45%">
                {/* EVENT STREAM */}
                <Box flexDirection="column" height={streamHeight} borderStyle="single" borderColor="blue">
                    <Text bold color="blue" underline>EVENT STREAM (45%)</Text>
                    <Box flexDirection="column" marginTop={1} overflow="hidden">
                        {visibleLogs.map((log, i) => (
                            <Text key={i} wrap="truncate-end" color="grey">
                                [{log.timestamp.split('T')[1]?.split('.')[0] || log.timestamp}] {log.event_id} {log.channel}
                            </Text>
                        ))}
                        {isProcessing && <Text color="green">... scanning ...</Text>}
                    </Box>
                </Box>
                {/* LOG DETAIL (Bottom Left) */}
                <Box flexDirection="column" height={detailHeight} borderStyle="single" borderColor="grey" marginTop={0}>
                    <Text bold color="white" underline>(Detalle del Log)</Text>
                    <Box marginTop={1} overflow="hidden">
                        <Text color="grey" wrap="wrap">
                            {latestLog ? JSON.stringify(latestLog.raw || latestLog, null, 2) : "Waiting for logs..."}
                        </Text>
                    </Box>
                </Box>
            </Box>

            {/* RIGHT COLUMN */}
            <Box flexDirection="column" width="55%" marginLeft={1}>
                {/* 1. CRITICAL QUEUE (Intel + Critical Findings) */}
                <CriticalQueue findings={findings} height={intelHeight} intelStatus={intelStatus} />

                {/* 2. RADAR (Findings List) */}
                <Box flexDirection="column" height={radarHeight} borderStyle="single" borderColor={isProcessing ? "red" : "green"}>
                    <Box flexDirection="column">
                        <Box justifyContent="space-between">
                            <Text bold color={isProcessing ? "red" : "green"} underline>
                                {isProcessing ? `RADAR (40%) [${ruleset.toUpperCase()}]` : '=== Detection Report ==='}
                            </Text>
                            {showWarning ? (
                                <Text color="red" bold>Run in progress — Ctrl+C to cancel</Text>
                            ) : (
                                <Text dimColor>
                                    {replVisible 
                                        ? "TAB: Nav Mode | Ctrl+C: cancel" 
                                        : "TAB: Write Mode | Esc/q: back | f: filter | s: summary"
                                    }
                                </Text>
                            )}
                        </Box>
                        {/* Summary Stats Line */}
                        <Box marginTop={0}>
                            <Text dimColor>
                                CRIT:{stats.CRITICAL} | HIGH:{stats.HIGH} | MED:{stats.MEDIUM} | LOW:{stats.LOW}
                            </Text>
                        </Box>
                    </Box>
                    
                    {/* Content: List or Summary */}
                    {showSummary ? (
                        <Box marginTop={1}>
                            <HuntSummary stats={stats} topSeverity={topSeverity} topCount={topCount} />
                        </Box>
                    ) : (
                        <Box flexDirection="column" marginTop={1} overflow="hidden">
                            {visibleRadarFindings.map((f: Finding) => {
                                const isSelected = f.id === activeFinding?.id;
                                const color = f.severity === 'CRITICAL' ? 'red' : f.severity === 'HIGH' ? 'magenta' : f.severity === 'MEDIUM' ? 'yellow' : 'cyan';
                                
                                return (
                                    <Box key={f.id} flexDirection="column" marginBottom={0}>
                                        <Box flexDirection="row" justifyContent="space-between">
                                            <Text color={isSelected ? 'black' : color} backgroundColor={isSelected ? color : undefined} wrap="truncate-end" bold={isSelected}>
                                                {isSelected ? '> ' : '  '}[{f.severity.substring(0,3)}] {f.title}
                                            </Text>
                                            <Text color={isSelected ? 'black' : 'white'} backgroundColor={isSelected ? color : undefined}>
                                                ({f.evidence.length})
                                            </Text>
                                        </Box>
                                        <Box marginLeft={2}>
                                            <Text dimColor wrap="truncate-end">
                                                {getSampleEvidence(f)}
                                            </Text>
                                        </Box>
                                    </Box>
                                );
                            })}
                            {hiddenCount > 0 && (
                                <Box marginTop={1} alignSelf="center">
                                    <Text color="yellow" bold>({hiddenCount} hidden - press 'f' to see ALL)</Text>
                                </Box>
                            )}
                            {visibleFindings.length === 0 && hiddenCount === 0 && findings.length > 0 && (
                                <Text dimColor>No findings in {filterMode} view. Press 'f' to toggle.</Text>
                            )}
                        </Box>
                    )}
                </Box>

                {/* 3. INSPECTOR */}
                <Box flexDirection="column" height={inspectorHeight} borderStyle="single" borderColor="yellow" marginTop={1}>
                    <Box justifyContent="space-between">
                        <Text bold color="yellow" underline>INSPECTOR</Text>
                        <Text dimColor>{scrollOffset}/{maxScroll} (PgUp/PgDn)</Text>
                    </Box>
                    <Box marginTop={1} flexDirection="column" overflow="hidden">
                        {visibleInspectorText.map((line, i) => {
                            const truncatedLine = line.length > 200 ? line.substring(0, 197) + '...' : line;
                            return <Text key={i} wrap="truncate-end">{truncatedLine}</Text>;
                        })}
                    </Box>
                </Box>
            </Box>
        </Box>

        {/* FOOTER */}
        <Box borderStyle="single" borderColor="white" marginTop={0} justifyContent="space-between">
            <Text>Processed: {processedCount} events | Visible: {visibleFindings.length} / Total: {findings.length}</Text>
            <Text>Status: {isProcessing ? <Text color="green">RUNNING</Text> : <Text color="red">STOPPED (report mode)</Text>}</Text>
        </Box>
    </Box>
  );
};