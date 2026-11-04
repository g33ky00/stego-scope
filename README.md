# stego-scope

Forensic analyzer for hidden messages in images. Detects steganography signals — never hides.

**Made with [pollinations.ai](https://pollinations.ai)**

![Made with pollinations.ai](https://pollinations.ai/badge-made-with.svg)

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
