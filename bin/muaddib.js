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
let paranoidMode = false;

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
  } else if (options[i] === '--paranoid') {
    paranoidMode = true;
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

if (!command) {
  console.log(`
  MUAD'DIB - npm Supply Chain Threat Hunter
  
  Usage:
    muaddib scan [path] [options]    Scan a project
    muaddib watch [path]             Watch a project in real-time
    muaddib daemon [options]         Start background daemon
    muaddib update                   Update IOCs
    muaddib scrape                   Scrape new IOCs from advisories
    muaddib help                     Show help
  
  Options:
    --json              Output as JSON
    --html [file]       Generate HTML report
    --sarif [file]      Generate SARIF report (GitHub Security)
    --explain           Show detailed explanations
    --fail-on [level]   Severity level for exit code (critical|high|medium|low)
                        Default: high (fail on HIGH and CRITICAL)
    --webhook [url]     Send Discord/Slack alert
    --paranoid          Enable ultra-strict rules (more false positives)
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
    webhook: webhookUrl,
    paranoid: paranoidMode
  }).then(exitCode => {
    process.exit(exitCode);
  });
} else if (command === 'watch') {
  watch(target);
} else if (command === 'update') {
  updateIOCs().then(() => {
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'scrape') {
  runScraper().then(result => {
    console.log(`[OK] ${result.added} new IOCs added (total: ${result.total})`);
    process.exit(0);
  }).catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
  });
} else if (command === 'daemon') {
  startDaemon({ webhook: webhookUrl });
} else if (command === 'help') {
  console.log('muaddib scan [path] [--json] [--html file] [--sarif file] [--explain] [--fail-on level] [--webhook url] [--paranoid]');
  console.log('muaddib watch [path] - Watch a project in real-time');
  console.log('muaddib daemon [--webhook url] - Start background daemon');
  console.log('muaddib update - Update IOCs');
  console.log('muaddib scrape - Scrape new IOCs');
} else {
  console.log(`Unknown command: ${command}`);
  process.exit(1);
}