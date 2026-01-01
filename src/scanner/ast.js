const fs = require('fs');
const path = require('path');

const DANGEROUS_PATTERNS = [
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/, name: 'child_process_import', severity: 'MEDIUM' },
  { pattern: /process\.env\.(NPM_TOKEN|GITHUB_TOKEN|AWS_)/, name: 'sensitive_env_access', severity: 'HIGH' },
  { pattern: /eval\s*\(/, name: 'eval_usage', severity: 'HIGH' },
  { pattern: /new\s+Function\s*\(/, name: 'function_constructor', severity: 'HIGH' },
  { pattern: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)/, name: 'base64_decode', severity: 'MEDIUM' },
  { pattern: /fs\.(readFileSync|readFile).*\.npmrc/, name: 'npmrc_read', severity: 'CRITICAL' },
  { pattern: /fs\.(readFileSync|readFile).*\.ssh/, name: 'ssh_key_read', severity: 'CRITICAL' },
  { pattern: /https?\.request.*api\.github\.com/, name: 'github_api_call', severity: 'MEDIUM' },
  { pattern: /exec\s*\(\s*['"`].*curl/, name: 'exec_curl', severity: 'HIGH' },
  { pattern: /exec\s*\(\s*['"`].*wget/, name: 'exec_wget', severity: 'HIGH' }
];

async function analyzeAST(targetPath) {
  const threats = [];
  
  const files = findJsFiles(targetPath);
  
  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    
    for (const { pattern, name, severity } of DANGEROUS_PATTERNS) {
      if (pattern.test(content)) {
        threats.push({
          type: name,
          severity: severity,
          message: `Comportement suspect "${name}" detecte.`,
          file: path.relative(targetPath, file)
        });
      }
    }
  }

  return threats;
}

function findJsFiles(dir) {
  const results = [];
  
  if (!fs.existsSync(dir)) return results;
  
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    if (item === 'node_modules' || item === '.git') continue;
    
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      results.push(...findJsFiles(fullPath));
    } else if (item.endsWith('.js')) {
      results.push(fullPath);
    }
  }
  
  return results;
}

module.exports = { analyzeAST };