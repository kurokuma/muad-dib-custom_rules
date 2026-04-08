const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');

function toPosix(value) {
  return String(value || '').replace(/\\/g, '/');
}

function matchesGlobs(relativePath, rule) {
  const normalized = toPosix(relativePath);
  if (rule.fileGlobRegexes.length > 0 && !rule.fileGlobRegexes.some(re => re.test(normalized))) {
    return false;
  }
  if (rule.excludeGlobRegexes.length > 0 && rule.excludeGlobRegexes.some(re => re.test(normalized))) {
    return false;
  }
  return true;
}

function isProbablyTextBuffer(buffer) {
  if (!buffer || buffer.length === 0) return true;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  let suspicious = 0;
  for (const byte of sample) {
    if (byte === 0) return false;
    const printable = byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126);
    if (!printable) suspicious++;
  }
  return suspicious / sample.length < 0.3;
}

function getSnippet(value, index, matchLength) {
  const start = Math.max(0, index - 40);
  const end = Math.min(value.length, index + Math.max(matchLength, 1) + 80);
  return value.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 240);
}

function evaluateMatch(match, value) {
  if (typeof value !== 'string' || value.length === 0) return null;

  if (match.type === 'regex') {
    match.compiled.lastIndex = 0;
    const found = match.compiled.exec(value);
    if (!found) return null;
    const text = found[0] || '';
    return {
      matchedValue: text,
      snippet: getSnippet(value, found.index || 0, text.length)
    };
  }

  if (match.type === 'contains') {
    const index = value.indexOf(match.pattern);
    if (index === -1) return null;
    return {
      matchedValue: match.pattern,
      snippet: getSnippet(value, index, match.pattern.length)
    };
  }

  if (match.type === 'contains_any') {
    for (const pattern of match.patterns) {
      const index = value.indexOf(pattern);
      if (index !== -1) {
        return {
          matchedValue: pattern,
          snippet: getSnippet(value, index, pattern.length)
        };
      }
    }
    return null;
  }

  const indexes = match.patterns.map(pattern => value.indexOf(pattern));
  if (indexes.some(index => index === -1)) return null;
  const firstIndex = Math.min(...indexes);
  return {
    matchedValue: match.patterns.join(', '),
    snippet: getSnippet(value, firstIndex, 0)
  };
}

function buildThreat(rule, relPath, extras = {}) {
  const targetLabel = extras.matchedField || rule.target;
  return {
    type: rule.typeKey,
    severity: rule.severity,
    message: `Custom rule matched ${targetLabel}`,
    file: relPath,
    source: 'custom_rule',
    matchedTarget: rule.target,
    matchedField: extras.matchedField || undefined,
    matchedValue: extras.matchedValue || undefined,
    snippet: extras.snippet || undefined,
    origin: rule.origin,
    customRuleId: rule.id,
    customRuleName: rule.name,
    description: rule.description || undefined,
    references: rule.references,
    mitre: rule.mitre || undefined
  };
}

function getDottedField(obj, dottedPath) {
  const parts = String(dottedPath || '').split('.');
  let current = obj;
  for (const part of parts) {
    if (!current || typeof current !== 'object' || !(part in current)) return undefined;
    current = current[part];
  }
  return current;
}

function scanCustomPatterns(targetPath, customRules) {
  if (!Array.isArray(customRules) || customRules.length === 0) return [];

  const threats = [];
  const rulesByTarget = {
    file_content: customRules.filter(rule => rule.target === 'file_content'),
    filename: customRules.filter(rule => rule.target === 'filename'),
    package_json_field: customRules.filter(rule => rule.target === 'package_json_field')
  };

  const files = findFiles(targetPath, { extensions: [''] });
  for (const absPath of files) {
    const relPath = toPosix(path.relative(targetPath, absPath) || path.basename(absPath));

    for (const rule of rulesByTarget.filename) {
      if (!matchesGlobs(relPath, rule)) continue;
      const match = evaluateMatch(rule.match, relPath);
      if (!match) continue;
      threats.push(buildThreat(rule, relPath, match));
    }

    const fileRules = rulesByTarget.file_content.filter(rule => matchesGlobs(relPath, rule));
    if (fileRules.length === 0) continue;

    let stat;
    try {
      stat = fs.statSync(absPath);
    } catch {
      continue;
    }
    if (stat.size > getMaxFileSize()) continue;

    let buffer;
    try {
      buffer = fs.readFileSync(absPath);
    } catch {
      continue;
    }
    if (!isProbablyTextBuffer(buffer)) continue;

    const content = buffer.toString('utf8');
    for (const rule of fileRules) {
      const match = evaluateMatch(rule.match, content);
      if (!match) continue;
      threats.push(buildThreat(rule, relPath, match));
    }
  }

  if (rulesByTarget.package_json_field.length > 0) {
    const pkgPath = path.join(targetPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        for (const rule of rulesByTarget.package_json_field) {
          const relPath = 'package.json';
          if (!matchesGlobs(relPath, rule)) continue;
          const fieldValue = getDottedField(pkg, rule.field);
          if (typeof fieldValue !== 'string') continue;
          const match = evaluateMatch(rule.match, fieldValue);
          if (!match) continue;
          threats.push(buildThreat(rule, relPath, {
            ...match,
            matchedField: rule.field
          }));
        }
      } catch {
        // Ignore invalid package.json here; package scanner already warns separately.
      }
    }
  }

  return threats;
}

module.exports = {
  scanCustomPatterns,
  evaluateMatch,
  isProbablyTextBuffer,
  getDottedField,
  matchesGlobs
};
