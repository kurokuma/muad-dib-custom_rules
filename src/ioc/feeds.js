const KNOWN_MALICIOUS_PACKAGES = [
  'setup_bun.js',
  'bun_environment.js',
  '@ctrl/tinycolor',
  'flatmap-stream',
  'event-stream'
];

const KNOWN_MALICIOUS_HASHES = [
  '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0',
  'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd',
  'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068'
];

const SUSPICIOUS_REPO_MARKERS = [
  'Sha1-Hulud',
  'Shai-Hulud',
  'The Second Coming'
];

function isKnownMalicious(packageName) {
  return KNOWN_MALICIOUS_PACKAGES.includes(packageName);
}

function isKnownMaliciousHash(hash) {
  return KNOWN_MALICIOUS_HASHES.includes(hash.toLowerCase());
}

function hasSuspiciousMarker(text) {
  return SUSPICIOUS_REPO_MARKERS.some(marker => 
    text.toLowerCase().includes(marker.toLowerCase())
  );
}

module.exports = { 
  isKnownMalicious, 
  isKnownMaliciousHash, 
  hasSuspiciousMarker,
  KNOWN_MALICIOUS_PACKAGES,
  KNOWN_MALICIOUS_HASHES,
  SUSPICIOUS_REPO_MARKERS
};