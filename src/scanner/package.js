const fs = require('fs');
const path = require('path');

const SUSPICIOUS_SCRIPTS = [
  'preinstall',
  'postinstall',
  'preuninstall',
  'postuninstall'
];

const DANGEROUS_PATTERNS = [
  { pattern: /curl\s+.*\|.*sh/, name: 'curl_pipe_sh' },
  { pattern: /wget\s+.*\|.*sh/, name: 'wget_pipe_sh' },
  { pattern: /eval\s*\(/, name: 'eval_usage' },
  { pattern: /child_process/, name: 'child_process' },
  { pattern: /\.npmrc/, name: 'npmrc_access' },
  { pattern: /GITHUB_TOKEN/, name: 'github_token_access' },
  { pattern: /AWS_/, name: 'aws_credential_access' },
  { pattern: /base64/, name: 'base64_encoding' }
];

async function scanPackageJson(targetPath) {
  const threats = [];
  const pkgPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    console.log('[INFO] Pas de package.json trouve.\n');
    return threats;
  }

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const scripts = pkg.scripts || {};

  for (const scriptName of SUSPICIOUS_SCRIPTS) {
    if (scripts[scriptName]) {
      const scriptContent = scripts[scriptName];

      threats.push({
        type: 'lifecycle_script',
        severity: 'MEDIUM',
        message: `Script "${scriptName}" detecte. Vecteur d'attaque courant.`,
        file: 'package.json'
      });

      for (const { pattern, name } of DANGEROUS_PATTERNS) {
        if (pattern.test(scriptContent)) {
          threats.push({
            type: name,
            severity: 'HIGH',
            message: `Pattern dangereux "${name}" dans script "${scriptName}".`,
            file: 'package.json'
          });
        }
      }
    }
  }

  return threats;
}

module.exports = { scanPackageJson };