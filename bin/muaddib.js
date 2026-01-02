#!/usr/bin/env node

const { run } = require('../src/index.js');
const { updateIOCs } = require('../src/ioc/updater.js');
const { watch } = require('../src/watch.js');
const { startDaemon } = require('../src/daemon.js');
const { runScraper } = require('../src/ioc/scraper.js');

const args = process.argv.slice(2);
const command = args[0];
const options = args.slice(1);

let target = '.';
let jsonOutput = false;
let htmlOutput = null;
let sarifOutput = null;
let explainMode = false;
let failLevel = 'high';
let webhookUrl = null;

for (let i = 0; i < options.length; i++) {
  if (options[i] === '--json') {
    jsonOutput = true;
  } else if (options[i] === '--html') {
    htmlOutput = options[i + 1] || 'muaddib-report.html';
    i++;
  } else if (options[i] === '--sarif') {
    sarifOutput = options[i + 1] || 'muaddib-results.sarif';
    i++;
  } else if (options[i] === '--explain') {
    explainMode = true;
  } else if (options[i] === '--fail-on') {
    failLevel = options[i + 1] || 'high';
    i++;
  } else if (options[i] === '--webhook') {
    webhookUrl = options[i + 1];
    i++;
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

if (!command) {
  console.log(`
  MUAD'DIB - Chasseur de vers npm
  
  Usage:
    muaddib scan [path] [options]   Analyse un projet
    muaddib watch [path]            Surveille un projet en temps reel
    muaddib update                  Met a jour les IOCs
    muaddib help                    Affiche l'aide
  
  Options:
    --json              Sortie au format JSON
    --html [file]       Genere un rapport HTML
    --sarif [file]      Genere un rapport SARIF (GitHub Security)
    --explain           Affiche les details de chaque detection
    --fail-on [level]   Niveau de severite pour exit code (critical|high|medium|low)
                        Defaut: high (fail sur HIGH et CRITICAL)
    --webhook [url]     Envoie une alerte Discord/Slack
    muaddib daemon [options]        Lance le daemon de surveillance
    muaddib scrape                  Scrape les advisories pour nouveaux IOCs
  `);
  process.exit(0);
}

if (command === 'scan') {
  run(target, { 
    json: jsonOutput, 
    html: htmlOutput, 
    sarif: sarifOutput,
    explain: explainMode,
    failLevel: failLevel,
    webhook: webhookUrl
  }).then(exitCode => {
    process.exit(exitCode);
  });
} else if (command === 'watch') {
  watch(target);
} else if (command === 'update') {
  updateIOCs().then(() => {
    process.exit(0);
  }).catch(err => {
    console.error('[ERREUR]', err.message);
    process.exit(1);
  });
} else if (command === 'help') {
  console.log('muaddib scan [path] [--json] [--html file] [--sarif file] [--explain] [--fail-on level] [--webhook url]');
  console.log('muaddib watch [path] - Surveille un projet en temps reel');
  console.log('muaddib update - Met a jour les IOCs');
} else if (command === 'daemon') {
  startDaemon({ webhook: webhookUrl });
} else if (command === 'scrape') {
  runScraper().then(result => {
    console.log(`[OK] ${result.added} nouveaux IOCs ajoutes (total: ${result.total})`);
    process.exit(0);
  }).catch(err => {
    console.error('[ERREUR]', err.message);
    process.exit(1);
  });
} else {
  console.log(`Commande inconnue: ${command}`);
  process.exit(1);
} 