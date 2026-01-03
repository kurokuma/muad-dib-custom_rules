const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');

// Packages legitimes avec lifecycle scripts
const TRUSTED_PACKAGES = [
  'esbuild', 'sharp', 'bcrypt', 'node-sass', 'puppeteer',
  'playwright', 'sqlite3', 'better-sqlite3', 'canvas',
  'grpc', 'fsevents', 'msgpackr-extract', 'lmdb'
];

// Fichiers legitimes qui ressemblent a des fichiers suspects
const SAFE_FILES = {
  'inject.js': ['async', 'awilix', 'inversify'],
  'install.js': ['esbuild', 'sharp', 'bcrypt', 'node-sass', 'puppeteer', 'playwright']
};

async function scanDependencies(targetPath) {
  const threats = [];
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  const iocs = loadCachedIOCs();

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  const packages = listPackages(nodeModulesPath);

  for (const pkg of packages) {
    // Verifie si package connu malveillant (IOCs caches) avec VERSION
    const maliciousPkg = iocs.packages.find(p => {
      if (p.name !== pkg.name) return false;
      // Si version "*" = toutes versions, sinon compare
      if (p.version === '*') return true;
      return p.version === pkg.version;
    });
    
    if (maliciousPkg) {
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Package malveillant connu: ${pkg.name}@${pkg.version} (source: ${maliciousPkg.source})`,
        file: `node_modules/${pkg.name}`
      });
      continue;
    }

    // Verifie les fichiers suspects (IOCs caches) avec whitelist
    for (const suspFile of iocs.files || []) {
      // Skip si fichier legitime pour ce package
      if (SAFE_FILES[suspFile] && SAFE_FILES[suspFile].includes(pkg.name)) {
        continue;
      }
      
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

    // Verifie les lifecycle scripts (skip packages trusted)
    if (TRUSTED_PACKAGES.includes(pkg.name)) continue;
    
    const pkgJsonPath = path.join(pkg.path, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const pkgContent = fs.readFileSync(pkgJsonPath, 'utf8');
        const pkgJson = JSON.parse(pkgContent);
        const scripts = pkgJson.scripts || {};

        // Verifie les marqueurs Shai-Hulud
        for (const marker of iocs.markers || []) {
          if (pkgContent.includes(marker)) {
            threats.push({
              type: 'shai_hulud_marker',
              severity: 'CRITICAL',
              message: `Marqueur "${marker}" detecte dans ${pkg.name}`,
              file: `node_modules/${pkg.name}/package.json`
            });
          }
        }

        // Verifie les lifecycle scripts (seulement si pas trusted)
        if (scripts.preinstall || scripts.postinstall) {
          threats.push({
            type: 'lifecycle_script_dependency',
            severity: 'LOW',
            message: `Dependance "${pkg.name}" a un script ${scripts.preinstall ? 'preinstall' : 'postinstall'}`,
            file: `node_modules/${pkg.name}/package.json`
          });
        }
      } catch (e) {
        // JSON parse error, skip
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
    
    try {
      const stat = fs.statSync(itemPath);
      if (!stat.isDirectory()) continue;

      if (item.startsWith('@')) {
        const scopedItems = fs.readdirSync(itemPath);
        for (const scopedItem of scopedItems) {
          const scopedPath = path.join(itemPath, scopedItem);
          if (fs.statSync(scopedPath).isDirectory()) {
            const version = getPackageVersion(scopedPath);
            packages.push({
              name: `${item}/${scopedItem}`,
              path: scopedPath,
              version: version
            });
          }
        }
      } else {
        const version = getPackageVersion(itemPath);
        packages.push({
          name: item,
          path: itemPath,
          version: version
        });
      }
    } catch (e) {
      // Skip inaccessible
    }
  }

  return packages;
}

function getPackageVersion(pkgPath) {
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(pkgPath, 'package.json'), 'utf8'));
    return pkgJson.version || '*';
  } catch (e) {
    return '*';
  }
}

module.exports = { scanDependencies };