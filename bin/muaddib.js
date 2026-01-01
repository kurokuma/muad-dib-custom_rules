#!/usr/bin/env node

const { run } = require('../src/index.js');

const args = process.argv.slice(2);
const command = args[0];
const target = args[1] || '.';

if (!command) {
  console.log(`
  MUAD'DIB - Chasseur de vers npm
  
  Usage:
    muaddib scan [path]    Analyse un projet
    muaddib help           Affiche l'aide
  `);
  process.exit(0);
}

if (command === 'scan') {
  run(target).then(exitCode => {
    process.exit(exitCode);
  });
} else if (command === 'help') {
  console.log('muaddib scan [path] - Analyse un projet npm');
} else {
  console.log(`Commande inconnue: ${command}`);
  process.exit(1);
}