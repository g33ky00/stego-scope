# stego-scope

[![CI](https://github.com/g33ky00/stego-scope/actions/workflows/ci-unified.yml/badge.svg)](https://github.com/g33ky00/stego-scope/actions/workflows/ci-unified.yml)

Forensic analyzer for hidden messages in images. Detects steganography signals — never hides.

**Made with [pollinations.ai](https://pollinations.ai)**

[![Made with pollinations.ai](https://raw.githubusercontent.com/pollinations/pollinations/main/packages/ui/src/brand/badge-made-with.svg)](https://pollinations.ai/?ref=badge)

## What it does
- LSB balance and chi-square per channel (R/G/B)
- Trailing bytes after image end (PNG IEND / JPEG EOI)
- PNG text chunks (tEXt/iTXt/zTXt)
- Per-channel entropy
- Optional Pollinations vision second opinion (BYOP — your own Pollen)

## Run
Open `index.html` in a browser. Or deploy to GitHub Pages.

## Tests
```
node --test tests/analyzer.test.js
```

## License
MIT

## About

Projet maintenu par g33ky00.

## Structure

Voir l'arborescence du dépôt.

## Stack

Voir le code source.

## Contributing

Les contributions sont les bienvenues via pull request.
