import { test, describe } from 'node:test';
import assert from 'node:assert';
import { matchRule } from './matcher.js';
import { LogtowerEvent } from '@neonshapeshifter/logtower-core';
import { Rule } from './types.js';

describe('Matcher Engine', () => {
    
    // Mock Event
    const mockEvent: LogtowerEvent = {
        timestamp: new Date().toISOString(),
        event_id: 1,
        channel: 'Microsoft-Windows-Sysmon/Operational',
        host: 'WORKSTATION-1',
        process: {
            image: 'C:\\Windows\\System32\\cmd.exe',
            command_line: 'cmd.exe /c powershell.exe -nop',
            parent_image: 'C:\\Windows\\explorer.exe',
            pid: 1234
        },
        user: {
            name: 'Admin',
            domain: 'CORP'
        }
    };

    test('should match exact string', () => {
        const rule: Rule = {
            id: 'TEST_001',
            title: 'Test Rule',
            description: 'Test',
            severity: 'HIGH',
            module: 'LOLBAS',
            tags: [],
            author: 'Test',
            date: '2023-01-01',
            detection: {
                selection: {
                    'process.image': 'C:\\Windows\\System32\\cmd.exe'
                }
            }
        };
        assert.strictEqual(matchRule(mockEvent, rule), true);
    });

    test('should match wildcard pattern', () => {
        const rule: Rule = {
            id: 'TEST_002', 
            title: 'Wildcard Test', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': '*\\cmd.exe'
                }
            }
        };
        assert.strictEqual(matchRule(mockEvent, rule), true);
    });

    test('should match case insensitive', () => {
        const rule: Rule = {
            id: 'TEST_003',
            title: 'Case Insensitive', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': 'c:\\windows\\system32\\CMD.EXE'
                }
            }
        };
        assert.strictEqual(matchRule(mockEvent, rule), true);
    });

    test('should match any in list (OR logic)', () => {
        const rule: Rule = {
            id: 'TEST_004',
            title: 'List Match', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': ['*\\powershell.exe', '*\\cmd.exe']
                }
            }
        };
        assert.strictEqual(matchRule(mockEvent, rule), true);
    });

    test('should respect negative matching (!)', () => {
        const rule: Rule = {
            id: 'TEST_005',
            title: 'Negative Match', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': ['*\\cmd.exe', '!*\\explorer.exe']
                }
            }
        };
        // Should Match (cmd.exe matches the positive pattern)
        assert.strictEqual(matchRule(mockEvent, rule), true);

        const ruleFail: Rule = {
            id: 'TEST_006',
            title: 'Negative Fail', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': ['*\\cmd.exe', '!*\\cmd.exe'] // Match cmd AND NOT cmd
                }
            }
        };
        // Should return false because it matches the negative pattern
        assert.strictEqual(matchRule(mockEvent, ruleFail), false);
    });

    test('should fail if one field in selection does not match (AND logic)', () => {
        const rule: Rule = {
            id: 'TEST_007',
            title: 'Multi-field Fail', description: '', severity: 'LOW', module: 'LOLBAS', tags: [], author: '', date: '',
            detection: {
                selection: {
                    'process.image': '*\\cmd.exe',      // Matches
                    'process.command_line': '*malware*' // Does NOT match
                }
            }
        };
        assert.strictEqual(matchRule(mockEvent, rule), false);
    });
});