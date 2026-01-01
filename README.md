# MUAD'DIB

Detection et reponse aux attaques supply chain npm.

## Pourquoi MUAD'DIB ?

Les attaques type Shai-Hulud ont compromis 25K+ repos en 2025. Les outils existants detectent, mais n'aident pas a repondre.

MUAD'DIB detecte ET guide la reponse.

## Installation
```bash
npm install -g muaddib
```

Ou en local :
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
```

## Utilisation

### Scan basique
```bash
muaddib scan .
muaddib scan /chemin/vers/projet
```

### Export JSON
```bash
muaddib scan . --json
muaddib scan . --json > resultat.json
```

### Rapport HTML
```bash
muaddib scan . --html rapport.html
```

### Surveillance temps reel
```bash
muaddib watch .
```

### Mise a jour des IOCs
```bash
muaddib update
```

## Ce que MUAD'DIB detecte

### Fichiers et patterns Shai-Hulud
- setup_bun.js, bun_environment.js, bundle.js
- Marqueurs "Sha1-Hulud", "The Second Coming", "Goldox-T3chs"
- Hashes connus des payloads malveillants

### Comportements suspects
- Scripts lifecycle (preinstall, postinstall)
- Acces aux credentials (.npmrc, .ssh, tokens)
- Exfiltration de donnees (curl, wget vers API)
- Execution de commandes (child_process, exec)
- Variables d'environnement sensibles (GITHUB_TOKEN, AWS_*, NPM_TOKEN)

### Code malveillant
- Obfuscation (hex escapes, variables _0x, string arrays)
- eval() et new Function()
- Reverse shells
- Dead man's switch (rm -rf, shred)

## Ce que MUAD'DIB propose

Pour chaque menace detectee, un playbook de reponse :
- Quoi faire immediatement
- Comment verifier si compromis
- Comment regenerer les secrets

## Integration CI/CD

### GitHub Actions
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install
      - run: npx muaddib scan .
```

## IOCs integres

MUAD'DIB inclut les IOCs de :
- Shai-Hulud v1 (septembre 2025)
- Shai-Hulud v2 "The Second Coming" (novembre 2025)
- Shai-Hulud v3 "Golden Path" (decembre 2025)
- event-stream (2018)
- eslint-scope (2018)

## Contribuer

1. Fork le repo
2. Cree une branche (`git checkout -b feature/amelioration`)
3. Commit (`git commit -m "Ajout feature"`)
4. Push (`git push origin feature/amelioration`)
5. Ouvre une Pull Request

## Licence

MIT