const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const IOCS_DIR = path.join(__dirname, '../../iocs');

function loadYAMLIOCs() {
  const iocs = {
    packages: [],
    hashes: [],
    markers: [],
    files: []
  };

  // Charger packages.yaml
  loadPackagesYAML(path.join(IOCS_DIR, 'packages.yaml'), iocs);
  
  // Charger builtin.yaml (fallback)
  loadBuiltinYAML(path.join(IOCS_DIR, 'builtin.yaml'), iocs);

  // Charger hashes.yaml
  loadHashesYAML(path.join(IOCS_DIR, 'hashes.yaml'), iocs);

  return iocs;
}

function loadPackagesYAML(filePath, iocs) {
  if (!fs.existsSync(filePath)) return;
  
  try {
    const data = yaml.load(fs.readFileSync(filePath, 'utf8'));
    if (data && data.packages) {
      for (const p of data.packages) {
        if (!iocs.packages.find(x => x.name === p.name && x.version === p.version)) {
          iocs.packages.push({
            id: p.id,
            name: p.name,
            version: p.version,
            severity: p.severity || 'critical',
            confidence: p.confidence || 'high',
            source: p.source,
            description: p.description,
            references: p.references || [],
            mitre: p.mitre || 'T1195.002'
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing packages.yaml:', e.message);
  }
}

function loadBuiltinYAML(filePath, iocs) {
  if (!fs.existsSync(filePath)) return;
  
  try {
    const data = yaml.load(fs.readFileSync(filePath, 'utf8'));
    
    // Packages
    if (data && data.packages) {
      for (const p of data.packages) {
        if (!iocs.packages.find(x => x.name === p.name && x.version === p.version)) {
          iocs.packages.push({
            id: `BUILTIN-${p.name}`,
            name: p.name,
            version: p.version,
            severity: p.severity || 'critical',
            confidence: p.confidence || 'high',
            source: p.source,
            description: p.description || `Malicious package: ${p.name}`,
            references: p.references || [],
            mitre: p.mitre || 'T1195.002'
          });
        }
      }
    }
    
    // Files
    if (data && data.files) {
      for (const f of data.files) {
        const fileName = typeof f === 'string' ? f : f.name;
        if (!iocs.files.find(x => x.name === fileName)) {
          iocs.files.push({
            id: `BUILTIN-FILE-${fileName}`,
            name: fileName,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: `Suspicious file: ${fileName}`
          });
        }
      }
    }
    
    // Hashes
    if (data && data.hashes) {
      for (const h of data.hashes) {
        const hash = typeof h === 'string' ? h : h.sha256;
        if (!iocs.hashes.find(x => x.sha256 === hash)) {
          iocs.hashes.push({
            id: `BUILTIN-HASH-${hash.slice(0, 8)}`,
            sha256: hash,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: 'Known malicious hash'
          });
        }
      }
    }
    
    // Markers
    if (data && data.markers) {
      for (const m of data.markers) {
        const pattern = typeof m === 'string' ? m : m.pattern;
        if (!iocs.markers.find(x => x.pattern === pattern)) {
          iocs.markers.push({
            id: `BUILTIN-MARKER-${pattern.slice(0, 10)}`,
            pattern: pattern,
            severity: 'critical',
            confidence: 'high',
            source: 'builtin',
            description: `Malware marker: ${pattern}`
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing builtin.yaml:', e.message);
  }
}

function loadHashesYAML(filePath, iocs) {
  if (!fs.existsSync(filePath)) return;
  
  try {
    const data = yaml.load(fs.readFileSync(filePath, 'utf8'));
    
    if (data && data.hashes) {
      for (const h of data.hashes) {
        if (!iocs.hashes.find(x => x.sha256 === h.sha256)) {
          iocs.hashes.push({
            id: h.id,
            sha256: h.sha256,
            file: h.file,
            severity: h.severity || 'critical',
            confidence: h.confidence || 'high',
            source: h.source,
            description: h.description,
            references: h.references || []
          });
        }
      }
    }
    
    if (data && data.markers) {
      for (const m of data.markers) {
        if (!iocs.markers.find(x => x.pattern === m.pattern)) {
          iocs.markers.push({
            id: m.id,
            pattern: m.pattern,
            severity: m.severity || 'critical',
            confidence: m.confidence || 'high',
            source: m.source,
            description: m.description
          });
        }
      }
    }
    
    if (data && data.files) {
      for (const f of data.files) {
        if (!iocs.files.find(x => x.name === f.name)) {
          iocs.files.push({
            id: f.id,
            name: f.name,
            severity: f.severity || 'critical',
            confidence: f.confidence || 'high',
            source: f.source,
            description: f.description
          });
        }
      }
    }
  } catch (e) {
    console.error('[WARN] Erreur parsing hashes.yaml:', e.message);
  }
}

function getIOCStats() {
  const iocs = loadYAMLIOCs();
  return {
    packages: iocs.packages.length,
    hashes: iocs.hashes.length,
    markers: iocs.markers.length,
    files: iocs.files.length
  };
}

module.exports = { loadYAMLIOCs, getIOCStats };