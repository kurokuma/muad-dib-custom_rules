const fs = require('fs');
const path = require('path');
const { isKnownMalicious, isKnownMaliciousHash, KNOWN_MALICIOUS_PACKAGES } = require('../ioc/feeds.js');
const crypto = require('crypto');

async function scanDependencies(targetPath) {
  const threats = [];
  const nodeModulesPath = path.join(targetPath, 'node_modules');

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  const packages = listPackages(nodeModulesPath);

  for (const pkg of packages) {
    // Verifie si package connu malveillant
    if (isKnownMalicious(pkg.name)) {
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Package malveillant connu: ${pkg.name}`,
        file: `node_modules/${pkg.name}`
      });
      continue;
    }

    // Verifie les scripts suspects dans le package.json
    const pkgJsonPath = path.join(pkg.path, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      const scripts = pkgJson.scripts || {};

      if (scripts.preinstall || scripts.postinstall) {
        threats.push({
          type: 'lifecycle_script_dependency',
          severity: 'MEDIUM',
          message: `Dependance "${pkg.name}" a un script ${scripts.preinstall ? 'preinstall' : 'postinstall'}`,
          file: `node_modules/${pkg.name}/package.json`
        });
      }
    }

    // Verifie les fichiers suspects
    const suspiciousFiles = ['setup_bun.js', 'bun_environment.js', 'bundle.js'];
    for (const suspFile of suspiciousFiles) {
      const filePath = path.join(pkg.path, suspFile);
      if (fs.existsSync(filePath)) {
        threats.push({
          type: 'suspicious_file',
          severity: 'HIGH',
          message: `Fichier suspect "${suspFile}" dans ${pkg.name}`,
          file: `node_modules/${pkg.name}/${suspFile}`
        });
      }
    }
  }

  return threats;
}

function listPackages(nodeModulesPath) {
  const packages = [];
  const items = fs.readdirSync(nodeModulesPath);

  for (const item of items) {
    if (item.startsWith('.')) continue;

    const itemPath = path.join(nodeModulesPath, item);
    const stat = fs.statSync(itemPath);

    if (!stat.isDirectory()) continue;

    // Scope packages (@org/package)
    if (item.startsWith('@')) {
      const scopedItems = fs.readdirSync(itemPath);
      for (const scopedItem of scopedItems) {
        const scopedPath = path.join(itemPath, scopedItem);
        if (fs.statSync(scopedPath).isDirectory()) {
          packages.push({
            name: `${item}/${scopedItem}`,
            path: scopedPath
          });
        }
      }
    } else {
      packages.push({
        name: item,
        path: itemPath
      });
    }
  }

  return packages;
}

module.exports = { scanDependencies };