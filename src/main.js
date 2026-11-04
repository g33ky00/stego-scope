import './analyzer.js';

const A = window.stegoAnalyzer;

const fileInput = document.getElementById('file');
const btn = document.getElementById('analyzeBtn');
const report = document.getElementById('report');

btn.addEventListener('click', async () => {
  const f = fileInput.files && fileInput.files[0];
  if (!f) return;
  const buf = await f.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const img = new Image();
  const url = URL.createObjectURL(f);
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = img.width; canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const data = ctx.getImageData(0, 0, img.width, img.height);
    const res = A.analyze(data.data, bytes);
    render(res, img.width, img.height, f.name);
    URL.revokeObjectURL(url);
  };
  img.src = url;
});

function render(res, w, h, name) {
  report.hidden = false;
  const v = res.verdict;
  let html = `<h2>Report — ${name} (${w}×${h})</h2>`;
  html += `<p class="badge ${v.level}">Verdict: ${v.level} (score ${v.score})</p>`;
  if (v.reasons.length) {
    html += '<ul>' + v.reasons.map(r => `<li>${r}</li>`).join('') + '</ul>';
  } else {
    html += '<p>No suspicious signals detected.</p>';
  }
  html += '<h3>LSB balance (R/G/B)</h3><div class="kv">';
  for (const c of ['R','G','B']) {
    const b = res.lsbBalance[c];
    html += `<span>${c}</span><span>${b.ones}/${b.total} = ${b.ratio.toFixed(4)}</span>`;
  }
  html += '</div>';
  html += `<h3>Trailing bytes</h3><p>${res.trailing.trailing} (IEND: ${res.trailing.hasIEND}, EOI: ${res.trailing.hasEOI})</p>`;
  html += `<h3>PNG text chunks</h3><p>${res.pngText.length}</p>`;
  if (res.pngText.length) {
    html += '<ul>' + res.pngText.map(c => `<li>${c.type} (${c.length}): ${c.preview}</li>`).join('') + '</ul>';
  }
  report.innerHTML = html;
}

// BYOP vision second opinion
document.getElementById('visionBtn').addEventListener('click', async () => {
  const key = document.getElementById('key').value.trim();
  const f = fileInput.files && fileInput.files[0];
  const out = document.getElementById('visionOut');
  if (!key || !f) { out.textContent = 'Need key + image.'; return; }
  out.textContent = 'Calling...';
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = reader.result.split(',')[1];
    const dataUrl = `data:${f.type};base64,${b64}`;
    try {
      const r = await fetch('https://gen.pollinations.ai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'openai/gpt-4o-mini',
          messages: [{ role: 'user', content: [
            { type: 'text', text: 'Does this image likely hide a secret message (steganography)? Answer yes/no with one short reason.' },
            { type: 'image_url', image_url: { url: dataUrl } }
          ]}]
        })
      });
      const j = await r.json();
      out.textContent = (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || JSON.stringify(j);
    } catch (e) { out.textContent = String(e); }
  };
  reader.readAsDataURL(f);
});
