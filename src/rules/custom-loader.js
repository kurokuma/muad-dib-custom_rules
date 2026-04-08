const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const VALID_TARGETS = new Set(['file_content', 'filename', 'package_json_field']);
const VALID_MATCH_TYPES = new Set(['regex', 'contains', 'contains_any', 'contains_all']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const VALID_CONFIDENCES = new Set(['high', 'medium', 'low']);
const RULE_FILE_RE = /\.(?:ya?ml|json)$/i;

function toPosix(value) {
  return String(value || '').replace(/\\/g, '/');
}

function globToRegExp(glob) {
  const normalized = toPosix(glob);
  let out = '^';
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    if (ch === '*') {
      const next = normalized[i + 1];
      if (next === '*') {
        const after = normalized[i + 2];
        if (after === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i++;
        }
      } else {
        out += '[^/]*';
      }
    } else if (ch === '?') {
      out += '[^/]';
    } else if ('\\.[]{}()+-^$|'.includes(ch)) {
      out += '\\' + ch;
    } else {
      out += ch;
    }
  }
  out += '$';
  return new RegExp(out);
}

function normalizeStringArray(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return null;
  const arr = value.filter(item => typeof item === 'string' && item.trim());
  return arr.length === value.length ? arr : null;
}

function normalizeMatch(match, contextLabel) {
  if (!match || typeof match !== 'object' || Array.isArray(match)) {
    return { error: `${contextLabel}: "match" must be an object` };
  }
  if (typeof match.type !== 'string' || !VALID_MATCH_TYPES.has(match.type)) {
    return { error: `${contextLabel}: invalid match.type` };
  }

  if (match.type === 'regex') {
    if (typeof match.pattern !== 'string' || !match.pattern) {
      return { error: `${contextLabel}: regex match.pattern is required` };
    }
    if (match.flags !== undefined && typeof match.flags !== 'string') {
      return { error: `${contextLabel}: regex flags must be a string` };
    }
    try {
      return {
        value: {
          type: 'regex',
          pattern: match.pattern,
          flags: match.flags || '',
          compiled: new RegExp(match.pattern, match.flags || '')
        }
      };
    } catch (err) {
      return { error: `${contextLabel}: invalid regex (${err.message})` };
    }
  }

  if (match.type === 'contains') {
    if (typeof match.pattern !== 'string' || !match.pattern) {
      return { error: `${contextLabel}: contains match.pattern is required` };
    }
    return { value: { type: 'contains', pattern: match.pattern } };
  }

  const patterns = normalizeStringArray(match.patterns);
  if (!patterns || patterns.length === 0) {
    return { error: `${contextLabel}: ${match.type} match.patterns must be a non-empty string array` };
  }
  return { value: { type: match.type, patterns } };
}

function normalizeRule(rawRule, origin, index) {
  const contextLabel = `${origin} rule #${index + 1}`;
  if (!rawRule || typeof rawRule !== 'object' || Array.isArray(rawRule)) {
    return { error: `${contextLabel}: rule must be an object` };
  }
  if (typeof rawRule.id !== 'string' || !rawRule.id.trim()) {
    return { error: `${contextLabel}: "id" is required` };
  }
  if (typeof rawRule.name !== 'string' || !rawRule.name.trim()) {
    return { error: `${contextLabel}: "name" is required` };
  }
  if (typeof rawRule.target !== 'string' || !VALID_TARGETS.has(rawRule.target)) {
    return { error: `${contextLabel}: invalid "target"` };
  }

  const severity = String(rawRule.severity || 'medium').toLowerCase();
  if (!VALID_SEVERITIES.has(severity)) {
    return { error: `${contextLabel}: invalid "severity"` };
  }
  const confidence = String(rawRule.confidence || 'medium').toLowerCase();
  if (!VALID_CONFIDENCES.has(confidence)) {
    return { error: `${contextLabel}: invalid "confidence"` };
  }

  const fileGlob = normalizeStringArray(rawRule.file_glob);
  if (fileGlob === null) return { error: `${contextLabel}: "file_glob" must be an array of strings` };
  const excludeGlob = normalizeStringArray(rawRule.exclude_glob);
  if (excludeGlob === null) return { error: `${contextLabel}: "exclude_glob" must be an array of strings` };
  const references = normalizeStringArray(rawRule.references);
  if (references === null) return { error: `${contextLabel}: "references" must be an array of strings` };

  if (rawRule.target === 'package_json_field' && (typeof rawRule.field !== 'string' || !rawRule.field.trim())) {
    return { error: `${contextLabel}: "field" is required for package_json_field` };
  }

  const normalizedMatch = normalizeMatch(rawRule.match, contextLabel);
  if (normalizedMatch.error) return normalizedMatch;

  return {
    value: {
      id: rawRule.id.trim(),
      name: rawRule.name.trim(),
      severity: severity.toUpperCase(),
      confidence,
      description: typeof rawRule.description === 'string' ? rawRule.description : '',
      mitre: typeof rawRule.mitre === 'string' ? rawRule.mitre : null,
      references: references || [],
      target: rawRule.target,
      field: typeof rawRule.field === 'string' ? rawRule.field.trim() : null,
      fileGlob: (fileGlob || []).map(toPosix),
      fileGlobRegexes: (fileGlob || []).map(globToRegExp),
      excludeGlob: (excludeGlob || []).map(toPosix),
      excludeGlobRegexes: (excludeGlob || []).map(globToRegExp),
      match: normalizedMatch.value,
      origin,
      typeKey: rawRule.id.trim(),
      source: 'custom_rule'
    }
  };
}

function parseRuleFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  if (/\.json$/i.test(filePath)) {
    return JSON.parse(raw);
  }
  return yaml.load(raw);
}

function discoverRuleFiles(dirPath, results = []) {
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      discoverRuleFiles(fullPath, results);
      continue;
    }
    if (entry.isFile() && RULE_FILE_RE.test(entry.name)) {
      results.push(fullPath);
    }
  }

  return results;
}

function resolveRulesDirs(targetPath, ruleDirs) {
  if (Array.isArray(ruleDirs) && ruleDirs.length > 0) {
    return [...new Set(ruleDirs.map(dir => path.resolve(dir)))];
  }
  return [path.join(path.resolve(targetPath), 'custom-rules')];
}

function loadCustomRules(targetPath, ruleDirs) {
  const warnings = [];
  const rules = [];
  const directories = resolveRulesDirs(targetPath, ruleDirs);

  for (const dirPath of directories) {
    if (!fs.existsSync(dirPath)) continue;
    let stat;
    try {
      stat = fs.statSync(dirPath);
    } catch {
      warnings.push(`[CUSTOM-RULES] Unable to read rules directory: ${dirPath}`);
      continue;
    }
    if (!stat.isDirectory()) {
      warnings.push(`[CUSTOM-RULES] Rules path is not a directory: ${dirPath}`);
      continue;
    }

    const files = discoverRuleFiles(dirPath).sort();
    for (const filePath of files) {
      let parsed;
      try {
        parsed = parseRuleFile(filePath);
      } catch (err) {
        const warning = `[CUSTOM-RULES] Failed to parse ${filePath}: ${err.message}`;
        warnings.push(warning);
        console.warn(warning);
        continue;
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Array.isArray(parsed.rules)) {
        const warning = `[CUSTOM-RULES] Ignoring ${filePath}: top-level "rules" array is required`;
        warnings.push(warning);
        console.warn(warning);
        continue;
      }

      for (let i = 0; i < parsed.rules.length; i++) {
        const normalized = normalizeRule(parsed.rules[i], filePath, i);
        if (normalized.error) {
          const warning = `[CUSTOM-RULES] ${normalized.error}`;
          warnings.push(warning);
          console.warn(warning);
          continue;
        }
        rules.push(normalized.value);
      }
    }
  }

  return { rules, warnings, directories };
}

module.exports = {
  loadCustomRules,
  resolveRulesDirs,
  globToRegExp
};
