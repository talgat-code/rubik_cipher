'use strict';

/* ── Shorthand ─────────────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);

/* ── DOM refs ──────────────────────────────────────────────────────────────── */
const cipherKey     = $('cipherKey');
const keyEye        = $('keyEye');
const eyeShow       = $('eyeShow');
const eyeHide       = $('eyeHide');
const keyStrFill    = $('keyStrFill');
const keyStrLabel   = $('keyStrLabel');
const modeToggle    = $('modeToggle');
const textPanel     = $('textPanel');
const filePanel     = $('filePanel');
const inputText     = $('inputText');
const outputText    = $('outputText');
const charCount     = $('charCount');
const copyBtn       = $('copyBtn');
const copyLabel     = $('copyLabel');
const swapBtn       = $('swapBtn');
const encryptBtn    = $('encryptBtn');
const decryptBtn    = $('decryptBtn');
const dropzone      = $('dropzone');
const fileInput     = $('fileInput');
const fileInfo      = $('fileInfo');
const fileName      = $('fileName');
const fileSize      = $('fileSize');
const clearFileBtn  = $('clearFileBtn');
const encryptFileBtn = $('encryptFileBtn');
const decryptFileBtn = $('decryptFileBtn');
const analysisKey   = $('analysisKey');
const analyzeBtn    = $('analyzeBtn');
const results       = $('results');
const toastShelf    = $('toastShelf');

/* ── State ─────────────────────────────────────────────────────────────────── */
let selectedFile = null;

/* ════════════════════════════════════════════════════════════════════════════
   TAB SWITCHING
══════════════════════════════════════════════════════════════════════════════ */
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('is-active'));

    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    $(`tab-${btn.dataset.tab}`).classList.add('is-active');
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   PILL TOGGLE  (Text / File)
══════════════════════════════════════════════════════════════════════════════ */
const pillBtns  = modeToggle.querySelectorAll('.pill-btn');
const pillTrack = modeToggle.querySelector('.pill-track');

function syncPillTrack() {
  const active = modeToggle.querySelector('.pill-btn.active');
  if (!active) return;
  pillTrack.style.width     = `${active.offsetWidth}px`;
  pillTrack.style.transform = `translateX(${active.offsetLeft - 4}px)`;
}

pillBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    pillBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    syncPillTrack();

    if (btn.dataset.mode === 'text') {
      textPanel.classList.remove('hidden');
      filePanel.classList.add('hidden');
    } else {
      textPanel.classList.add('hidden');
      filePanel.classList.remove('hidden');
    }
  });
});

window.addEventListener('load', syncPillTrack);

/* ════════════════════════════════════════════════════════════════════════════
   KEY FIELD
══════════════════════════════════════════════════════════════════════════════ */
keyEye.addEventListener('click', () => {
  const isPass = cipherKey.type === 'password';
  cipherKey.type = isPass ? 'text' : 'password';
  eyeShow.style.display = isPass ? 'none'  : '';
  eyeHide.style.display = isPass ? ''      : 'none';
  keyEye.title = isPass ? 'Скрыть ключ' : 'Показать ключ';
});

const STRENGTH_LEVELS = [
  { min: 0,  max: 0,        label: '',          color: 'transparent', w: '0%'   },
  { min: 1,  max: 7,        label: 'Слабый',    color: '#ef4444',     w: '25%'  },
  { min: 8,  max: 11,       label: 'Средний',   color: '#f59e0b',     w: '50%'  },
  { min: 12, max: 15,       label: 'Хороший',   color: '#10b981',     w: '75%'  },
  { min: 16, max: Infinity, label: 'Сильный',   color: '#059669',     w: '100%' },
];

cipherKey.addEventListener('input', () => {
  const len = cipherKey.value.length;
  const s   = STRENGTH_LEVELS.find(l => len >= l.min && len <= l.max);
  keyStrFill.style.width      = s.w;
  keyStrFill.style.background = s.color;
  keyStrLabel.textContent     = s.label;
  keyStrLabel.style.color     = s.color;
});

/* ════════════════════════════════════════════════════════════════════════════
   TEXT PANEL
══════════════════════════════════════════════════════════════════════════════ */
inputText.addEventListener('input', () => {
  const n = inputText.value.length;
  charCount.textContent = n ? `${n.toLocaleString('ru')} симв.` : '';
});

swapBtn.addEventListener('click', () => {
  const tmp = inputText.value;
  inputText.value  = outputText.value;
  outputText.value = tmp;
  charCount.textContent = inputText.value.length
    ? `${inputText.value.length.toLocaleString('ru')} симв.` : '';
  swapBtn.style.transform =
    swapBtn.style.transform === 'rotate(180deg)' ? '' : 'rotate(180deg)';
});

copyBtn.addEventListener('click', async () => {
  if (!outputText.value) return;
  await navigator.clipboard.writeText(outputText.value);
  copyBtn.classList.add('copied');
  copyLabel.textContent = 'Скопировано!';
  setTimeout(() => {
    copyBtn.classList.remove('copied');
    copyLabel.textContent = 'Копировать';
  }, 2200);
});

encryptBtn.addEventListener('click', () => doTextOp('/api/encrypt', encryptBtn));
decryptBtn.addEventListener('click', () => doTextOp('/api/decrypt', decryptBtn));

async function doTextOp(endpoint, btn) {
  const key  = cipherKey.value;
  const text = inputText.value;
  if (!key)  return toast('Введите ключ шифрования', 'warn');
  if (!text) return toast('Введите текст', 'warn');

  setLoading(btn, true);
  try {
    const data = await apiJSON(endpoint, { key, text });
    outputText.value = data.result;
    flashTextarea(outputText);
    toast('Готово!', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    setLoading(btn, false);
  }
}

/* ════════════════════════════════════════════════════════════════════════════
   FILE PANEL
══════════════════════════════════════════════════════════════════════════════ */
dropzone.addEventListener('click',   () => fileInput.click());
dropzone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
dropzone.addEventListener('dragleave', ()  => dropzone.classList.remove('drag-over'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });
clearFileBtn.addEventListener('click', clearFile);

function setFile(file) {
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = fmtSize(file.size);
  dropzone.classList.add('hidden');
  fileInfo.classList.remove('hidden');
  if (file.name.endsWith('.rubik'))
    toast('Файл .rubik обнаружен — используйте «Расшифровать файл»', 'warn');
}

function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  fileInfo.classList.add('hidden');
  dropzone.classList.remove('hidden');
}

function fmtSize(b) {
  if (b < 1024)        return `${b} Б`;
  if (b < 1024 ** 2)   return `${(b / 1024).toFixed(1)} КБ`;
  return `${(b / 1024 ** 2).toFixed(2)} МБ`;
}

encryptFileBtn.addEventListener('click', () => doFileOp('/api/encrypt-file', encryptFileBtn));
decryptFileBtn.addEventListener('click', () => doFileOp('/api/decrypt-file', decryptFileBtn));

async function doFileOp(endpoint, btn) {
  const key = cipherKey.value;
  if (!key)          return toast('Введите ключ шифрования', 'warn');
  if (!selectedFile) return toast('Выберите файл', 'warn');

  setLoading(btn, true);
  try {
    const form = new FormData();
    form.append('key',  key);
    form.append('file', selectedFile);

    const res = await fetch(endpoint, { method: 'POST', body: form });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Ошибка сервера' }));
      throw new Error(err.detail || 'Ошибка сервера');
    }
    const blob    = await res.blob();
    const cd      = res.headers.get('content-disposition') || '';
    const match   = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
    const outName = match ? match[1].replace(/['"]/g, '') : 'output';
    downloadBlob(blob, outName);
    toast(`Сохранено: ${outName}`, 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    setLoading(btn, false);
  }
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a   = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 8000);
}

/* ════════════════════════════════════════════════════════════════════════════
   ANALYSIS
══════════════════════════════════════════════════════════════════════════════ */
analyzeBtn.addEventListener('click', doAnalyze);

async function doAnalyze() {
  const key = analysisKey.value.trim();
  if (!key) return toast('Введите ключ для анализа', 'warn');

  setLoading(analyzeBtn, true);
  results.classList.add('hidden');

  try {
    const data = await apiJSON('/api/analyze', { key, trials: 300, size_kb: 5 });
    renderResults(data);
    results.classList.remove('hidden');
    replayStaggerIn(results);
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    setLoading(analyzeBtn, false);
  }
}

function replayStaggerIn(root) {
  root.querySelectorAll('[class*="stagger-"]').forEach(el => {
    el.style.animation = 'none';
    void el.offsetWidth;          // force reflow
    el.style.animation = '';
  });
}

/* ─── Render helpers ────────────────────────────────────────────────────────── */
function renderResults(data) {
  renderAvalanche(data.avalanche);
  renderEntropy(data.entropy);
  renderBenchmark(data.benchmark);
  renderKeySpace(data.key_space);
  $('comparisonPre').textContent = data.comparison;
}

/* Avalanche gauge */
function renderAvalanche(d) {
  const ring = $('avalancheRing');
  const val  = $('avalancheVal');
  const note = $('avalancheNote');
  const circ = 2 * Math.PI * 52;   // r = 52 → 326.73

  ring.style.transition    = 'none';
  ring.style.strokeDashoffset = circ;
  void ring.offsetWidth;
  ring.style.transition    = 'stroke-dashoffset 1.5s cubic-bezier(.4,0,.2,1)';
  ring.style.strokeDasharray   = circ;
  ring.style.strokeDashoffset  = circ * (1 - d.avg_pct / 100);

  countUp(val, 0, d.avg_pct, 1500, 1);
  note.textContent = `min ${d.min} бит · max ${d.max} бит · из 128 возможных`;
}

/* Entropy bar */
function renderEntropy(d) {
  const num  = $('entropyNum');
  const bar  = $('entropyBar');
  const note = $('entropyNote');

  countUp(num, 0, d.entropy_score, 1300, 2);
  bar.style.width = `${Math.min(d.entropy_score / 8 * 100, 100).toFixed(1)}%`;
  note.textContent = `${d.unique_bytes} уникальных байт из ${d.total_bytes} · идеал: 8 бит`;
}

/* Benchmark */
function renderBenchmark(d) {
  const list   = $('benchList');
  const maxKbps = Math.max(d.encrypt_kbps, d.decrypt_kbps, 1);

  list.innerHTML = [
    { label: 'Шифрование', kbps: d.encrypt_kbps, ms: d.encrypt_ms },
    { label: 'Расшифровка', kbps: d.decrypt_kbps, ms: d.decrypt_ms },
  ].map(({ label, kbps, ms }) => `
    <div class="bench-row">
      <div class="bench-lbl">
        <span>${label}</span>
        <b>${Math.round(kbps).toLocaleString('ru')} КБ/с</b>
      </div>
      <div class="bench-track">
        <div class="bench-fill" style="width: ${(kbps / maxKbps * 100).toFixed(1)}%"></div>
      </div>
      <div class="bench-sub">${ms.toFixed(2)} мс</div>
    </div>
  `).join('');
}

/* Key space bars */
function renderKeySpace(ks) {
  const wrap    = $('ksWrap');
  const maxBits = 160;  // ~24-char ASCII password
  const labels  = { 8: 'Слабый', 12: 'Средний', 16: 'Хороший', 20: 'Сильный', 24: 'Отличный' };

  wrap.innerHTML = Object.entries(ks).map(([len, { bit_security }]) => {
    const pct   = Math.min(bit_security / maxBits * 100, 100).toFixed(1);
    const lbl   = labels[len] || '';
    return `
      <div class="ks-row">
        <span class="ks-len">${len} симв.</span>
        <div class="ks-track">
          <div class="ks-fill" style="width: ${pct}%">
            <span class="ks-fill-label">${lbl}</span>
          </div>
        </div>
        <span class="ks-bits">${Math.round(bit_security)} бит</span>
      </div>
    `;
  }).join('');
}

/* ════════════════════════════════════════════════════════════════════════════
   UTILITIES
══════════════════════════════════════════════════════════════════════════════ */

async function apiJSON(endpoint, body) {
  const res  = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ detail: 'Неверный ответ сервера' }));
  if (!res.ok) throw new Error(data.detail || 'Ошибка сервера');
  return data;
}

function setLoading(btn, on) {
  if (on) {
    btn._html     = btn.innerHTML;
    btn.disabled  = true;
    btn.innerHTML = '<div class="spinner"></div> Загрузка…';
  } else {
    btn.disabled  = false;
    btn.innerHTML = btn._html || btn.innerHTML;
  }
}

function toast(msg, type = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  toastShelf.appendChild(el);
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('show')));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 380);
  }, 3200);
}

function flashTextarea(el) {
  el.style.transition = 'background .28s';
  el.style.background = '#f0ebff';
  setTimeout(() => { el.style.background = ''; }, 420);
}

function countUp(el, from, to, durationMs, decimals = 1) {
  const start = performance.now();
  const tick  = now => {
    const progress = Math.min((now - start) / durationMs, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);   // ease-out cubic
    el.textContent = (from + (to - from) * eased).toFixed(decimals);
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
