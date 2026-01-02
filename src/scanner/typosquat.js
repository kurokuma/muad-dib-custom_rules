const fs = require('fs');
const path = require('path');

// Top 100 packages npm les plus populaires (cibles de typosquatting)
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment',
  'request', 'async', 'bluebird', 'underscore', 'uuid', 'debug', 'mkdirp',
  'glob', 'minimist', 'webpack', 'babel-core', 'typescript', 'eslint',
  'prettier', 'jest', 'mocha', 'chai', 'sinon', 'mongoose', 'sequelize',
  'mysql', 'redis', 'mongodb', 'socket.io', 'express-session',
  'body-parser', 'cookie-parser', 'cors', 'helmet', 'morgan', 'dotenv',
  'jsonwebtoken', 'bcrypt', 'passport', 'nodemailer', 'aws-sdk', 'stripe',
  'twilio', 'firebase', 'graphql', 'apollo-server', 'next', 'nuxt',
  'gatsby', 'angular', 'svelte', 'electron', 'puppeteer', 'cheerio',
  'sharp', 'jimp', 'canvas', 'pdf-lib', 'exceljs', 'csv-parser', 'xml2js',
  'yaml', 'config', 'yargs', 'inquirer', 'ora', 'colors',
  'winston', 'bunyan', 'pino', 'log4js', 'ramda', 'immutable',
  'mobx', 'redux', 'zustand', 'formik', 'yup', 'ajv', 'validator',
  'date-fns', 'dayjs', 'luxon', 'numeral', 'accounting', 'currency.js',
  'lodash-es', 'core-js', 'regenerator-runtime', 'tslib', 'classnames',
  'prop-types', 'cross-env', 'node-fetch', 'got'
];

// Packages legitimes courts ou qui ressemblent a des populaires
const WHITELIST = [
  // Packages tres courts legitimes
  'qs', 'pg', 'ms', 'ws', 'ip', 'on', 'is', 'it', 'to', 'or', 'fs', 'os',
  'co', 'q', 'n', 'i', 'a', 'v', 'x', 'y', 'z',
  'ejs', 'nyc', 'ini', 'joi', 'vue', 'npm', 'got', 'ora',
  'vary', 'mime', 'send', 'etag', 'raw', 'tar', 'uid', 'cjs',
  'rxjs', 'yarn', 'pnpm',
  
  // Packages legitimes avec noms similaires
  'acorn', 'acorn-walk', 'js-yaml', 'cross-env', 'node-fetch', 'node-gyp',
  'core-js', 'lodash-es', 'date-fns', 'ts-node', 'ts-jest',
  'css-loader', 'style-loader', 'file-loader', 'url-loader', 'babel-loader',
  'vue-loader', 'react-dom', 'react-router', 'react-redux', 'vue-router',
  'express-session', 'body-parser', 'cookie-parser',
  
  // Packages Express.js communs
  'accepts', 'array-flatten', 'content-disposition', 'content-type',
  'depd', 'destroy', 'encodeurl', 'escape-html', 'fresh', 'merge-descriptors',
  'methods', 'on-finished', 'parseurl', 'path-to-regexp', 'proxy-addr',
  'range-parser', 'safe-buffer', 'safer-buffer', 'setprototypeof',
  'statuses', 'type-is', 'unpipe', 'utils-merge'
];

// Seuil minimum de longueur pour eviter faux positifs
const MIN_PACKAGE_LENGTH = 4;

async function scanTyposquatting(targetPath) {
  const threats = [];
  const packageJsonPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return threats;
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies
  };

  for (const depName of Object.keys(dependencies)) {
    const match = findTyposquatMatch(depName);
    if (match) {
      threats.push({
        type: 'typosquat_detected',
        severity: 'HIGH',
        message: `Package "${depName}" ressemble a "${match.original}" (${match.type}). Possible typosquatting.`,
        file: 'package.json',
        details: {
          suspicious: depName,
          legitimate: match.original,
          technique: match.type,
          distance: match.distance
        }
      });
    }
  }

  return threats;
}

function findTyposquatMatch(name) {
  // Ignore les packages whitelistes
  if (WHITELIST.includes(name.toLowerCase())) return null;
  
  // Ignore les packages scoped (@org/package)
  if (name.startsWith('@')) return null;

  // Ignore les packages tres courts (trop de faux positifs)
  if (name.length < MIN_PACKAGE_LENGTH) return null;

  for (const popular of POPULAR_PACKAGES) {
    // Ignore si c'est exactement le meme
    if (name.toLowerCase() === popular.toLowerCase()) continue;

    // Ignore si le package populaire est trop court
    if (popular.length < MIN_PACKAGE_LENGTH) continue;

    const distance = levenshteinDistance(name.toLowerCase(), popular.toLowerCase());
    
    // Distance de 1 = tres suspect (une seule lettre de difference)
    if (distance === 1) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }

    // Distance de 2 seulement si le package est assez long (>= 8 chars)
    if (distance === 2 && popular.length >= 8) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }

    // Verifie les tricks de suffixe
    if (isSuffixTrick(name, popular)) {
      return {
        original: popular,
        type: 'suffix_trick',
        distance: distance
      };
    }
  }

  return null;
}

function detectTyposquatType(typo, original) {
  if (typo.length === original.length - 1) return 'missing_char';
  if (typo.length === original.length + 1) return 'extra_char';
  if (typo.length === original.length) {
    // Verifie si swap
    let diffs = 0;
    for (let i = 0; i < typo.length; i++) {
      if (typo[i] !== original[i]) diffs++;
    }
    if (diffs === 2) return 'swapped_chars';
    return 'wrong_char';
  }
  return 'unknown';
}

function isSuffixTrick(name, popular) {
  const nameLower = name.toLowerCase();
  const popularLower = popular.toLowerCase();
  
  const suffixes = ['-js', '.js', '-node', '-npm', '-cli', '-api', '-lib', '-pkg', '-dev', '-pro'];
  for (const suffix of suffixes) {
    if (nameLower === popularLower + suffix) return true;
    if (nameLower === popularLower.replace('-', '') + suffix) return true;
  }
  
  // Verifie aussi les prefixes
  const prefixes = ['node-', 'npm-', 'js-', 'get-', 'the-'];
  for (const prefix of prefixes) {
    if (nameLower === prefix + popularLower) return true;
  }
  
  return false;
}

function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

module.exports = { scanTyposquatting, levenshteinDistance };