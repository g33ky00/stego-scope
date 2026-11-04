// stego-scope analyzer core (pure functions, CommonJS)
// Detects likely steganography signals in an image's decoded RGBA + metadata.

function lsbBalance(rgba, channel = 0) {
  // channel: 0=R,1=G,2=B
  let ones = 0, total = 0;
  for (let i = 0; i < rgba.length; i += 4) {
    const v = rgba[i + channel];
    ones += v & 1;
    total++;
  }
  if (total === 0) return { ones: 0, total: 0, ratio: 0.5 };
  return { ones, total, ratio: ones / total };
}

function chiSquareLSB(rgba, channel = 0) {
  // chi-square on pairs of values (2k, 2k+1) for LSB stego detection
  const pairs = new Array(128).fill(0).map(() => [0, 0]);
  for (let i = 0; i < rgba.length; i += 4) {
    const v = rgba[i + channel];
    const k = v >> 1;
    if (k < 128) pairs[k][v & 1]++;
  }
  let chi = 0;
  for (const [a, b] of pairs) {
    const n = a + b;
    if (n === 0) continue;
    const expected = n / 2;
    chi += ((a - expected) ** 2) / expected + ((b - expected) ** 2) / expected;
  }
  // normalize-ish: high chi ~ natural, low chi ~ suspiciously balanced
  return { chi, pairs: pairs.length };
}

function shannonEntropy(values) {
  const freq = {};
  let n = 0;
  for (const v of values) { freq[v] = (freq[v] || 0) + 1; n++; }
  if (n === 0) return 0;
  let e = 0;
  for (const c of Object.values(freq)) {
    const p = c / n;
    e -= p * Math.log2(p);
  }
  return e;
}

function channelEntropy(rgba, channel = 0) {
  const vals = [];
  for (let i = 0; i < rgba.length; i += 4) vals.push(rgba[i + channel]);
  return shannonEntropy(vals);
}

function trailingBytes(buffer) {
  // detect bytes after PNG IEND / JPEG EOI
  if (!buffer || buffer.length < 8) return { trailing: 0, hasIEND: false, hasEOI: false };
  // PNG
  const iendSig = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
  let iendAt = -1;
  for (let i = 0; i <= buffer.length - 8; i++) {
    let ok = true;
    for (let j = 0; j < 8; j++) if (buffer[i + j] !== iendSig[j]) { ok = false; break; }
    if (ok) { iendAt = i + 8; break; }
  }
  if (iendAt !== -1 && iendAt < buffer.length) {
    return { trailing: buffer.length - iendAt, hasIEND: true, hasEOI: false, offset: iendAt };
  }
  // JPEG EOI
  let eoiAt = -1;
  for (let i = buffer.length - 2; i >= 0; i--) {
    if (buffer[i] === 0xFF && buffer[i + 1] === 0xD9) { eoiAt = i + 2; break; }
  }
  if (eoiAt !== -1 && eoiAt < buffer.length) {
    return { trailing: buffer.length - eoiAt, hasIEND: false, hasEOI: true, offset: eoiAt };
  }
  return { trailing: 0, hasIEND: iendAt !== -1, hasEOI: eoiAt !== -1 };
}

function pngTextChunks(buffer) {
  // parse tEXt/iTXt/zTXt chunk types and lengths
  const out = [];
  if (!buffer || buffer.length < 8) return out;
  // PNG signature 8 bytes
  let pos = 8;
  while (pos + 12 <= buffer.length) {
    const len = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | buffer[pos + 3];
    const type = String.fromCharCode(buffer[pos + 4], buffer[pos + 5], buffer[pos + 6], buffer[pos + 7]);
    if (len < 0 || pos + 12 + len > buffer.length) break;
    if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt' || type === 'caBX') {
      const data = buffer.slice(pos + 8, pos + 8 + len);
      out.push({ type, length: len, preview: Array.from(data.slice(0, 60)).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('') });
    }
    pos += 12 + len;
    if (type === 'IEND') break;
  }
  return out;
}

function verdict(signals) {
  let score = 0;
  const reasons = [];
  for (const ch of ['R', 'G', 'B']) {
    const bal = signals.lsbBalance[ch];
    if (bal && Math.abs(bal.ratio - 0.5) < 0.005) { score += 1; reasons.push(`${ch} LSB unusually balanced (${bal.ratio.toFixed(4)})`); }
  }
  if (signals.trailing && signals.trailing.trailing > 0) { score += 2; reasons.push(`trailing bytes after image end (${signals.trailing.trailing})`); }
  if (signals.pngText && signals.pngText.length > 0) { score += 1; reasons.push(`text chunks present (${signals.pngText.length})`); }
  const level = score >= 3 ? 'HIGH' : score >= 1 ? 'MEDIUM' : 'LOW';
  return { score, level, reasons };
}

const _exp = { lsbBalance, chiSquareLSB, shannonEntropy, channelEntropy, trailingBytes, pngTextChunks, verdict };
if (typeof module !== 'undefined') module.exports = _exp;
if (typeof window !== 'undefined') window.stegoAnalyzer = _exp;
if (typeof module !== 'undefined') module.exports._channels = ['R','G','B'];
if (typeof window !== 'undefined' && window.stegoAnalyzer) window.stegoAnalyzer._channels = ['R','G','B'];
const _ci = { R: 0, G: 1, B: 2 };
if (typeof module !== 'undefined') module.exports.channelIndex = _ci;
if (typeof window !== 'undefined' && window.stegoAnalyzer) window.stegoAnalyzer.channelIndex = _ci;
const _analyze = function (rgba, buffer) {
  const lsbBalance = {};
  const chiSquare = {};
  const entropy = {};
  for (const [name, idx] of Object.entries(module.exports.channelIndex)) {
    lsbBalance[name] = module.exports.lsbBalance(rgba, idx);
    chiSquare[name] = module.exports.chiSquareLSB(rgba, idx);
    entropy[name] = module.exports.channelEntropy(rgba, idx);
  }
  const trailing = module.exports.trailingBytes(buffer);
  const pngText = module.exports.pngTextChunks(buffer);
  const signals = { lsbBalance, chiSquare, entropy, trailing, pngText };
  const v = module.exports.verdict(signals);
  return { ...signals, verdict: v };
};
if (typeof module !== 'undefined') { module.exports.analyze = _analyze; module.exports.analyzeImage = _analyze; }
if (typeof window !== 'undefined' && window.stegoAnalyzer) { window.stegoAnalyzer.analyze = _analyze; window.stegoAnalyzer.analyzeImage = _analyze; }
if (typeof window !== "undefined") { try { window.stegoAnalyzer = (typeof module !== "undefined" && module.exports) ? module.exports : {}; } catch (e) {} }
