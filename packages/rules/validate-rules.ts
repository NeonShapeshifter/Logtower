#!/usr/bin/env node
/**
 * Rule Validation Script
 *
 * Validates Logtower rules for:
 * - Unique IDs
 * - Valid MITRE ATT&CK technique IDs
 * - Required fields
 * - Pattern quality (not too broad)
 */

import { Rule } from '@neonshapeshifter/logtower-engine';

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const VALID_MODULES = ['LOLBAS', 'LATERAL', 'INTEL', 'PERSISTENCE', 'CRED_ACCESS'];

// Common MITRE ATT&CK techniques (not exhaustive, just common ones)
const KNOWN_MITRE_TECHNIQUES = new Set([
  'T1003.001', 'T1053.005', 'T1055', 'T1059.001', 'T1059.003', 'T1059.005',
  'T1070.001', 'T1071', 'T1071.001', 'T1078', 'T1087', 'T1105', 'T1112',
  'T1135', 'T1140', 'T1197', 'T1218', 'T1218.005', 'T1218.010', 'T1218.011',
  'T1543.003', 'T1547.001', 'T1562.001', 'T1569.002'
]);

function validateRule(rule: Rule): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // 1. Required Fields
  if (!rule.id) errors.push('Missing required field: id');
  if (!rule.title) errors.push('Missing required field: title');
  if (!rule.severity) errors.push('Missing required field: severity');
  if (!rule.module) errors.push('Missing required field: module');
  if (!rule.detection) errors.push('Missing required field: detection');

  // 2. ID Format
  if (rule.id && !/^[A-Z_]+_\d{3}_[A-Z_]+$/.test(rule.id)) {
    warnings.push(`ID format should be MODULE_NNN_NAME (e.g., LOLBAS_001_CERTUTIL). Got: ${rule.id}`);
  }

  // 3. Severity
  if (rule.severity && !VALID_SEVERITIES.includes(rule.severity)) {
    errors.push(`Invalid severity: ${rule.severity}. Must be one of: ${VALID_SEVERITIES.join(', ')}`);
  }

  // 4. Module
  if (rule.module && !VALID_MODULES.includes(rule.module)) {
    warnings.push(`Uncommon module: ${rule.module}. Known modules: ${VALID_MODULES.join(', ')}`);
  }

  // 5. Title Length
  if (rule.title && rule.title.length > 60) {
    warnings.push(`Title is long (${rule.title.length} chars). Consider keeping under 60 chars.`);
  }

  // 6. Description
  if (!rule.description) {
    warnings.push('Missing description. Analysts need context about why this is suspicious.');
  } else if (rule.description.length < 30) {
    warnings.push('Description is very short. Add more context for SOC analysts.');
  }

  // 7. MITRE ATT&CK
  if (!rule.mitre || rule.mitre.length === 0) {
    warnings.push('No MITRE ATT&CK techniques mapped. This helps with threat intelligence correlation.');
  } else {
    rule.mitre.forEach(tech => {
      if (!KNOWN_MITRE_TECHNIQUES.has(tech)) {
        warnings.push(`Unknown MITRE technique: ${tech}. Verify at https://attack.mitre.org/`);
      }
    });
  }

  // 8. Detection Patterns
  if (rule.detection?.selection) {
    const selection = rule.detection.selection;

    // Check for overly broad patterns
    Object.entries(selection).forEach(([field, patterns]) => {
      const patternArray = Array.isArray(patterns) ? patterns : [patterns];

      patternArray.forEach(pattern => {
        if (typeof pattern === 'string') {
          // Pattern is just "*" (matches everything)
          if (pattern === '*') {
            errors.push(`Overly broad pattern in ${field}: "${pattern}" matches everything`);
          }

          // Pattern has no wildcards and is very short (too specific)
          if (!pattern.includes('*') && pattern.length < 5) {
            warnings.push(`Very specific pattern in ${field}: "${pattern}". Consider if this is too narrow.`);
          }

          // Pattern is just a single wildcard at start or end
          if (pattern === '**' || pattern === '*.*') {
            warnings.push(`Potentially too broad pattern in ${field}: "${pattern}"`);
          }
        }
      });
    });
  }

  // 9. False Positives
  if (!rule.false_positives || rule.false_positives.length === 0) {
    warnings.push('No false positives documented. Every rule has potential FPs - document them.');
  }

  // 10. References
  if (!rule.references || rule.references.length === 0) {
    warnings.push('No references provided. Link to LOLBAS/ATT&CK documentation.');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

function validateRuleSet(rules: Rule[]): void {
  console.log(`\n🔍 Validating ${rules.length} rules...\n`);

  const ids = new Set<string>();
  let totalErrors = 0;
  let totalWarnings = 0;

  rules.forEach((rule, index) => {
    const result = validateRule(rule);

    // Check for duplicate IDs
    if (rule.id) {
      if (ids.has(rule.id)) {
        result.errors.push(`Duplicate rule ID: ${rule.id}`);
      }
      ids.add(rule.id);
    }

    // Print results
    if (result.errors.length > 0 || result.warnings.length > 0) {
      console.log(`📋 Rule ${index + 1}: ${rule.id || 'UNKNOWN'}`);

      result.errors.forEach(err => {
        console.log(`  ❌ ERROR: ${err}`);
        totalErrors++;
      });

      result.warnings.forEach(warn => {
        console.log(`  ⚠️  WARNING: ${warn}`);
        totalWarnings++;
      });

      console.log('');
    }
  });

  // Summary
  console.log(`\n📊 Validation Summary:`);
  console.log(`   Total Rules: ${rules.length}`);
  console.log(`   Errors: ${totalErrors}`);
  console.log(`   Warnings: ${totalWarnings}`);

  if (totalErrors === 0 && totalWarnings === 0) {
    console.log(`\n✅ All rules passed validation!`);
  } else if (totalErrors === 0) {
    console.log(`\n✅ No errors found, but ${totalWarnings} warnings to review.`);
  } else {
    console.log(`\n❌ Found ${totalErrors} errors. Fix before deployment.`);
    process.exit(1);
  }
}

// Export for use in tests
export { validateRule, validateRuleSet };

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('Rule validation script');
  console.log('Usage: Import BASE_RULES and call validateRuleSet(BASE_RULES)');
}
