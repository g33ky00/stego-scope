const assert = require('assert');
const { lsbBalance, trailingBytes, pngTextChunks, verdict, analyze } = require('../src/analyzer');

// lsbBalance
{
  const rgba = new Uint8Array([0,0,0,255, 1,0,0,255, 2,0,0,255, 3,0,0,255]);
  const r = lsbBalance(rgba, 0);
  assert.strictEqual(r.total, 4);
  assert.strictEqual(r.ones, 2); // values 1,3
  assert.strictEqual(r.ratio, 0.5);
}

// trailingBytes PNG
{
  const sig = [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A];
  const iend = [0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82];
  const buf = Buffer.from([...sig, ...iend, 0x41,0x42]);
  const t = trailingBytes(buf);
  assert.strictEqual(t.trailing, 2);
  assert.strictEqual(t.hasIEND, true);
}

// trailingBytes no trailing
{
  const sig = [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A];
  const iend = [0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82];
  const buf = Buffer.from([...sig, ...iend]);
  const t = trailingBytes(buf);
  assert.strictEqual(t.trailing, 0);
}

// verdict trailing => HIGH-ish
{
  const v = verdict({ lsbBalance: { R: {ratio:0.5}, G:{ratio:0.5}, B:{ratio:0.5} }, trailing: { trailing: 5 }, pngText: [] });
  assert.ok(v.score >= 2);
  assert.ok(v.reasons.some(r => r.includes('trailing')));
}

// analyze runs
{
  const rgba = new Uint8Array(4*4); // 4 pixels all 0
  const buf = Buffer.from([0x89,0x50,0x4E,0x47]);
  const a = analyze(rgba, buf);
  assert.ok(a.verdict);
  assert.ok(a.lsbBalance.R);
}

console.log('all tests passed');
