const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_FILE = path.join(__dirname, '../../data/iocs.json');

// Sources d'advisories
const SOURCES = {
  github: 'https://api.github.com/advisories?ecosystem=npm&per_page=100',
  osv: 'https://api.osv.dev/v1/query'
};

async function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/1.0',
        'Accept': 'application/json',
        ...options.headers
      }
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

async function scrapeGitHubAdvisories() {
  console.log('[SCRAPER] Recuperation GitHub Security Advisories...');
  
  const packages = [];
  
  try {
    const data = await fetchJSON(SOURCES.github);
    
    if (Array.isArray(data)) {
      for (const advisory of data) {
        if (advisory.severity === 'critical' || advisory.severity === 'high') {
          for (const vuln of advisory.vulnerabilities || []) {
            if (vuln.package?.ecosystem === 'npm') {
              packages.push({
                id: `GHSA-${advisory.ghsa_id || Date.now()}`,
                name: vuln.package.name,
                version: vuln.vulnerable_version_range || '*',
                severity: advisory.severity === 'critical' ? 'critical' : 'high',
                confidence: 'high',
                source: 'github-advisory',
                description: advisory.summary || 'GitHub Security Advisory',
                references: [advisory.html_url].filter(Boolean),
                mitre: 'T1195.002',
                cve: advisory.cve_id
              });
            }
          }
        }
      }
    }
    
    console.log(`[SCRAPER] GitHub: ${packages.length} packages malveillants trouves`);
  } catch (e) {
    console.log(`[SCRAPER] GitHub erreur: ${e.message}`);
  }
  
  return packages;
}

async function scrapeOSV() {
  console.log('[SCRAPER] Recuperation OSV.dev (Open Source Vulnerabilities)...');
  
  const packages = [];
  
  try {
    // OSV requiert une requete POST
    const data = await fetchJSON(SOURCES.osv, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: {
        ecosystem: 'npm',
        page_token: ''
      }
    });
    
    if (data.vulns && Array.isArray(data.vulns)) {
      for (const vuln of data.vulns) {
        const severity = vuln.database_specific?.severity || 'high';
        
        if (severity === 'CRITICAL' || severity === 'HIGH') {
          for (const affected of vuln.affected || []) {
            if (affected.package?.ecosystem === 'npm') {
              packages.push({
                id: vuln.id,
                name: affected.package.name,
                version: affected.ranges?.[0]?.events?.[0]?.introduced || '*',
                severity: severity.toLowerCase(),
                confidence: 'high',
                source: 'osv',
                description: vuln.summary || vuln.details || 'OSV Advisory',
                references: (vuln.references || []).map(r => r.url).filter(Boolean).slice(0, 3),
                mitre: 'T1195.002'
              });
            }
          }
        }
      }
    }
    
    console.log(`[SCRAPER] OSV: ${packages.length} packages malveillants trouves`);
  } catch (e) {
    console.log(`[SCRAPER] OSV erreur: ${e.message}`);
  }
  
  return packages;
}

async function scrapeNpmAudit() {
  console.log('[SCRAPER] Recuperation npm audit advisories...');
  
  const packages = [];
  
  try {
    // npm registry advisories (bulk endpoint)
    const data = await fetchJSON('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: {}
    });
    
    // Parse les advisories si disponibles
    if (data && typeof data === 'object') {
      for (const [pkgName, advisories] of Object.entries(data)) {
        for (const adv of advisories || []) {
          if (adv.severity === 'critical' || adv.severity === 'high') {
            packages.push({
              id: `NPM-${adv.id || Date.now()}`,
              name: pkgName,
              version: adv.vulnerable_versions || '*',
              severity: adv.severity,
              confidence: 'high',
              source: 'npm-audit',
              description: adv.title || adv.overview || 'npm audit advisory',
              references: [adv.url].filter(Boolean),
              mitre: 'T1195.002'
            });
          }
        }
      }
    }
    
    console.log(`[SCRAPER] npm audit: ${packages.length} packages malveillants trouves`);
  } catch (e) {
    console.log(`[SCRAPER] npm audit erreur: ${e.message}`);
  }
  
  return packages;
}

async function runScraper() {
  console.log('\n[SCRAPER] === Demarrage du scraping IOCs ===\n');
  
  // Charger les IOCs existants
  let existingIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  
  const existingNames = new Set(existingIOCs.packages.map(p => p.name));
  
  // Scraper toutes les sources
  const [githubPkgs, osvPkgs, npmPkgs] = await Promise.all([
    scrapeGitHubAdvisories(),
    scrapeOSV(),
    scrapeNpmAudit()
  ]);
  
  // Fusionner sans doublons
  const allNew = [...githubPkgs, ...osvPkgs, ...npmPkgs];
  let added = 0;
  
  for (const pkg of allNew) {
    if (!existingNames.has(pkg.name)) {
      existingIOCs.packages.push(pkg);
      existingNames.add(pkg.name);
      added++;
    }
  }
  
  // Sauvegarder
  fs.writeFileSync(IOC_FILE, JSON.stringify(existingIOCs, null, 2));
  
  console.log(`\n[SCRAPER] === Resultats ===`);
  console.log(`[SCRAPER] Nouveaux packages ajoutes: ${added}`);
  console.log(`[SCRAPER] Total packages IOCs: ${existingIOCs.packages.length}`);
  console.log(`[SCRAPER] Fichier: ${IOC_FILE}\n`);
  
  return { added, total: existingIOCs.packages.length };
}

module.exports = { runScraper, scrapeGitHubAdvisories, scrapeOSV, scrapeNpmAudit };