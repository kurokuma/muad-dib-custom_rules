# MUAD'DIB

Detection et reponse aux attaques supply chain npm.

## Le probleme

Les attaques type Shai-Hulud compromettent des milliers de packages npm via des scripts malveillants. Les outils existants detectent, mais n'aident pas a repondre.

MUAD'DIB detecte ET guide la reponse.

## Installation
```bash
npm install -g muaddib
```

## Utilisation
```bash
muaddib scan .
muaddib scan /chemin/vers/projet
```

## Ce que MUAD'DIB detecte

- Scripts lifecycle suspects (preinstall, postinstall)
- Acces aux credentials (.npmrc, .ssh, tokens)
- Exfiltration de donnees (curl, wget)
- Reverse shells
- Dead man's switch (suppression de fichiers)
- Patterns d'obfuscation

## Ce que MUAD'DIB propose

Pour chaque menace detectee, un playbook de reponse:
- Quoi faire immediatement
- Comment verifier si compromis
- Comment regenerer les secrets

## Licence

MIT