<p align="center">
  <img src="MUADDIBLOGO.png" alt="MUAD'DIB Logo" width="200">
</p>

<h1 align="center">MUAD'DIB</h1>

<p align="center">
  <strong>Supply-chain threat detection & response for npm</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-58%2B%20packages-red" alt="IOCs">
</p>

---

## Pourquoi MUAD'DIB ?

Les attaques supply chain npm explosent. Shai-Hulud a compromis 25K+ repos en 2025. Les outils existants detectent, mais n'aident pas a repondre.

MUAD'DIB detecte ET guide la reponse.

| Feature | MUAD'DIB | Socket | Snyk |
|---------|----------|--------|------|
| Detection IOCs | Oui | Oui | Oui |
| Analyse AST | Oui | Oui | Non |
| Analyse Dataflow | Oui | Non | Non |
| Playbooks reponse | Oui | Non | Non |
| SARIF / GitHub Security | Oui | Oui | Oui |
| MITRE ATT&CK mapping | Oui | Non | Non |
| 100% Open Source | Oui | Non | Non |

---

## Installation
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
```

---

## Utilisation

### Scan basique
```bash
node bin/muaddib.js scan .
node bin/muaddib.js scan /chemin/vers/projet
```

### Mode explain (details complets)
```bash
node bin/muaddib.js scan . --explain
```

Affiche pour chaque detection :
- Rule ID
- MITRE ATT&CK technique
- References (articles, CVEs)
- Playbook de reponse

### Export JSON
```bash
node bin/muaddib.js scan . --json > results.json
```

### Rapport HTML
```bash
node bin/muaddib.js scan . --html rapport.html
```

### Rapport SARIF (GitHub Security)
```bash
node bin/muaddib.js scan . --sarif results.sarif
```

### Seuil de severite
```bash
node bin/muaddib.js scan . --fail-on critical  # Fail seulement sur CRITICAL
node bin/muaddib.js scan . --fail-on high      # Fail sur HIGH et CRITICAL (defaut)
node bin/muaddib.js scan . --fail-on medium    # Fail sur MEDIUM, HIGH, CRITICAL
```

### Surveillance temps reel
```bash
node bin/muaddib.js watch .
```

### Mise a jour des IOCs
```bash
node bin/muaddib.js update
```

---

## Detection

### Attaques detectees

| Campagne | Packages | Status |
|----------|----------|--------|
| Shai-Hulud v1 | @ctrl/tinycolor, ng2-file-upload | Detecte |
| Shai-Hulud v2 | @asyncapi/specs, posthog-node, kill-port | Detecte |
| Shai-Hulud v3 | @vietmoney/react-big-calendar | Detecte |
| event-stream (2018) | flatmap-stream, event-stream | Detecte |
| eslint-scope (2018) | eslint-scope | Detecte |
| Protestware | node-ipc, colors, faker | Detecte |
| Typosquats | crossenv, mongose, babelcli | Detecte |

### Techniques detectees

| Technique | MITRE | Detection |
|-----------|-------|-----------|
| Vol credentials (.npmrc, .ssh) | T1552.001 | AST |
| Exfiltration env vars | T1552.001 | AST |
| Execution code distant | T1105 | Pattern |
| Reverse shell | T1059.004 | Pattern |
| Dead man's switch | T1485 | Pattern |
| Code obfusque | T1027 | Heuristiques |
| Supply chain compromise | T1195.002 | IOC matching |

---

## Integration CI/CD

### GitHub Actions
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install
      - run: node bin/muaddib.js scan . --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Les alertes apparaissent dans Security > Code scanning alerts.

---

## Architecture
```
MUAD'DIB Scanner
|
+-- IOC Match (YAML DB)
+-- AST Parse (acorn)
+-- Pattern Matching (shell, scripts)
|
v
Dataflow Analysis (credential read -> network send)
|
v
Threat Enrichment (rules, MITRE ATT&CK, playbooks)
```

---

## Contribuer

### Ajouter des IOCs

Editez les fichiers YAML dans `iocs/` :
```yaml
- id: NEW-MALWARE-001
  name: "malicious-package"
  version: "*"
  severity: critical
  confidence: high
  source: community
  description: "Description de la menace"
  references:
    - https://example.com/article
  mitre: T1195.002
```

### Developper
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
node bin/muaddib.js scan test/samples --explain
```

---

## Documentation

- [Threat Model](docs/threat-model.md) - Ce que MUAD'DIB detecte et ne detecte pas
- [IOCs YAML](iocs/) - Base de donnees des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>