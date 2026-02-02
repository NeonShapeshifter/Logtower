import { LogtowerEvent } from '@neonshapeshifter/logtower-core';
import { Rule } from './types.js';

// Global cache for compiled regexes to avoid recompilation per event
const REGEX_CACHE = new Map<string, RegExp>();
const MAX_CACHE_SIZE = 2000;

/**
 * Checks if a value (from event) matches a pattern (from rule).
 * Pattern is a glob-like string where '*' matches any sequence of characters.
 * Comparison is case-insensitive.
 * Uses a LRU cache to store compiled Regex objects.
 */
function valueMatches(actual: any, pattern: string): boolean {
  if (actual === null || actual === undefined) return false;
  const sActual = String(actual);
  
  let regex = REGEX_CACHE.get(pattern);
  if (regex) {
    // LRU: Refresh key position
    REGEX_CACHE.delete(pattern);
    REGEX_CACHE.set(pattern, regex);
  } else {
    // Convert glob pattern to regex
    // 1. Escape regex special characters (except *)
    //    Specials: . + ? ^ $ { } ( ) | [ ] \
    // 2. Replace * with .*
    // 3. Anchor start (^) and end ($) to ensure full string match (like globs usually imply, unless * is explicit)
    const regexString = '^' + pattern.replace(/[.+?^${}()|[\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
    regex = new RegExp(regexString, 'i'); // Case insensitive
    
    // LRU: Evict oldest if full
    if (REGEX_CACHE.size >= MAX_CACHE_SIZE) {
      const firstKey = REGEX_CACHE.keys().next().value;
      if (firstKey) REGEX_CACHE.delete(firstKey);
    }
    
    REGEX_CACHE.set(pattern, regex);
  }
  
  return regex.test(sActual);
}

export function matchRule(event: LogtowerEvent, rule: Rule): boolean {
  // Simple "AND" logic for all fields in selection
  for (const [fieldPath, expectedValue] of Object.entries(rule.detection.selection)) {
    // Resolve nested path "process.image"
    const parts = fieldPath.split('.');
    let value: any = event;
    for (const part of parts) {
      value = value?.[part];
    }

    // Check match
    const patterns = Array.isArray(expectedValue) ? expectedValue : [expectedValue];
    
    const positivePatterns = patterns.filter(p => !p.startsWith('!'));
    const negativePatterns = patterns.filter(p => p.startsWith('!')).map(p => p.slice(1));

    // 1. Check Negative Patterns (fail fast)
    if (negativePatterns.some(p => valueMatches(value, p))) {
      return false;
    }

    // 2. Check Positive Patterns
    // If there are positive patterns, AT LEAST ONE must match.
    if (positivePatterns.length > 0) {
      if (!positivePatterns.some(p => valueMatches(value, p))) {
        return false;
      }
    }
  }
  
  return true;
}