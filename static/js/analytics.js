async function fetchJSON(url, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const resp = await fetch(url + (qs ? ('?' + qs) : ''));
  return resp.json();
}

/* DOM refs */
const graphsTabBtn = document.querySelector('#analyticsTabs [data-view="graphs"]');
const applyBtn = document.getElementById('applyBtn');
const fromDate = document.getElementById('fromDate');
const toDate = document.getElementById('toDate');
const periodSelect = document.getElementById('periodSelect');
const exportCsvBtn = document.getElementById('exportCsvBtn');

const mainCanvas = document.getElementById('mainChart');
const sideCanvas = document.getElementById('sideChart');
let mainChart = null;
let sideChart = null;

const rawTableBody = document.querySelector('#rawTable tbody');

const sumTotal = document.getElementById('sumTotal');
const sumCount = document.getElementById('sumCount');
const sumAvg = document.getElementById('sumAvg');
const sumMedian = document.getElementById('sumMedian');
const sumMin = document.getElementById('sumMin');
const sumMax = document.getElementById('sumMax');
const sumPrev = document.getElementById('sumPrev');
const sumPct = document.getElementById('sumPct');
const sumTopCat = document.getElementById('sumTopCat');
const sumLargest = document.getElementById('sumLargest');

const insightsArea = document.getElementById('insightsArea');

/* UI: toggle date controls based on period */
periodSelect.addEventListener('change', () => {
  fromDate.disabled = false;
  toDate.disabled = false;
});

/* Resize / destroy charts helper */
function destroyCharts() {
  if (mainChart) {
    try { mainChart.destroy(); } catch (e) {}
    mainChart = null;
  }
  if (sideChart) {
    try { sideChart.destroy(); } catch (e) {}
    sideChart = null;
  }
  // clear canvas drawing buffer
  [mainCanvas, sideCanvas].forEach(c => {
    if (c && c.getContext) {
      const ctx = c.getContext('2d');
      try { ctx.clearRect(0, 0, c.width, c.height); } catch (e) {}
      c.width = c.clientWidth;
      c.height = c.clientHeight;
    }
  });
}

/* compute simple moving average (window=3) */
function movingAverage(arr, window = 3) {
  if (!arr || arr.length === 0) return [];
  const res = [];
  for (let i = 0; i < arr.length; i++) {
    const start = Math.max(0, i - window + 1);
    const slice = arr.slice(start, i + 1);
    const sum = slice.reduce((a, b) => a + b, 0);
    res.push(sum / slice.length);
  }
  return res;
}

/* Render graphs */
async function renderGraphs(params) {
  destroyCharts();
  const totals = await fetchJSON('/api/totals', params);
  const cat = await fetchJSON('/api/category_breakdown', params);

  const labels = totals.labels || [];
  const values = totals.values || [];

  // main chart (fixed to line since selector removed)
  mainChart = new Chart(mainCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Amount',
        data: values,
        fill: true
      }, {
        label: 'Moving Avg (3)',
        data: movingAverage(values, 3),
        type: 'line',
        borderDash: [5, 5],
        pointRadius: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { tooltip: { mode: 'index', intersect: false } },
      scales: { x: { ticks: { maxRotation: 0 } } }
    }
  });

  // side (category) chart
  sideChart = new Chart(sideCanvas.getContext('2d'), {
    type: 'pie',
    data: {
      labels: cat.map(c => c.category),
      datasets: [{ data: cat.map(c => c.amount) }]
    },
    options: { responsive: true, maintainAspectRatio: false }
  });

  // update summary
  updateSummary(totals.summary || {});
  // quick insights
  renderInsights(totals, cat);
}

/* Render raw table */
async function renderRaw(params) {
  if (!rawTableBody) return; // guard in case raw pane isn't present
  rawTableBody.innerHTML = '';
  const tx = await fetchJSON('/api/transactions_range', params);
  const period = params.period || 'daily';

  tx.transactions.forEach(t => {
    let displayDate = t.timestamp;
    const d = new Date(t.timestamp);

    if (period === 'monthly') {
      displayDate = d.toISOString().slice(0, 7); // YYYY-MM
    } else if (period === 'yearly') {
      displayDate = d.getFullYear();
    } else if (period === 'daily') {
      displayDate = d.toISOString().slice(0, 10); // YYYY-MM-DD
    } else {
      displayDate = t.timestamp;
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${displayDate}</td>
                    <td>${escapeHtml(t.description)}</td>
                    <td>${escapeHtml(t.category)}</td>
                    <td class="text-end">${Number(t.amount).toFixed(2)}</td>`;
    rawTableBody.appendChild(tr);
  });

  // update summary (use totals API for summary)
  const totals = await fetchJSON('/api/totals', params);
  updateSummary(totals.summary || {});
  renderInsights(totals, null);
}

/* small utilities */
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe).replace(/[&<>"'`=\/]/g, function (s) {
    return ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    })[s];
  });
}

function updateSummary(s) {
  sumTotal.innerText = (s.total || 0).toFixed(2);
  sumCount.innerText = (s.count || 0);
  sumAvg.innerText = (s.avg || 0).toFixed(2);
  sumMedian.innerText = (s.median || 0).toFixed(2);
  sumMin.innerText = (s.min || 0).toFixed(2);
  sumMax.innerText = (s.max || 0).toFixed(2);
  sumPrev.innerText = (s.prev_total || 0).toFixed(2);
  sumPct.innerText = (s.pct_change === null || s.pct_change === undefined) ? 'N/A' : `${s.pct_change.toFixed(2)}%`;
  sumTopCat.innerText = (s.top_category && s.top_category.category) ? `${escapeHtml(s.top_category.category)} (${Number(s.top_category.amount).toFixed(2)})` : '-';
  sumLargest.innerText = (s.largest_transaction) ? `${Number(s.largest_transaction.amount).toFixed(2)} — ${escapeHtml(s.largest_transaction.description || '')}` : '-';
}

function renderInsights(totals, cat) {
  let html = '';

  if (totals && totals.summary) {
    const s = totals.summary;
    html += `<p>In the selected range the total amount is <strong>${(s.total||0).toFixed(2)}</strong> across <strong>${s.count||0}</strong> transactions. Average per transaction is <strong>${(s.avg||0).toFixed(2)}</strong>.</p>`;

    if (s.pct_change !== null && s.pct_change !== undefined) {
      const arrow = s.pct_change > 0 ? '▲' : (s.pct_change < 0 ? '▼' : '→');
      html += `<p>Compared to the previous period the total is <strong>${arrow} ${Math.abs(s.pct_change).toFixed(2)}%</strong> (${(s.prev_total||0).toFixed(2)} previously).</p>`;
    } else {
      html += `<p>No previous-period data to compare.</p>`;
    }
  }

  if (cat && cat.length) {
    const sorted = [...cat].sort((a,b) => b.amount - a.amount);
    const top = sorted[0];
    html += `<p>Top category: <strong>${escapeHtml(top.category)}</strong> with <strong>${(top.amount||0).toFixed(2)}</strong>.</p>`;
    if (sorted.length > 1) {
      const sub = sorted.slice(1,4).map(c => `${escapeHtml(c.category)} (${(c.amount||0).toFixed(2)})`).join(', ');
      html += `<p>Other notable categories: ${sub}.</p>`;
    }
  }

  // quick trend from chart values
  if (totals && totals.values && totals.values.length >= 2) {
    const vals = totals.values;
    const first = vals[0], last = vals[vals.length - 1];
    const delta = last - first;
    const pct = first !== 0 ? (delta / Math.abs(first)) * 100 : null;
    if (pct !== null && !isNaN(pct)) {
      const dir = pct > 0 ? 'increasing' : (pct < 0 ? 'decreasing' : 'flat');
      html += `<p>Trend: the series is <strong>${dir}</strong> (change ${pct.toFixed(2)}% from first to last point).</p>`;
    } else {
      html += `<p>Trend: not enough data to compute a reliable percent change.</p>`;
    }
  }

  if (!html) html = '<p>No additional insights available.</p>';
  insightsArea.innerHTML = html;
}

/* build params from UI */
function buildParams() {
  const period = periodSelect.value;
  const count = 30;
  const from = fromDate.value || '';
  const to = toDate.value || '';
  const params = { period, count, from, to };
  return params;
}

/* CSV export button */
exportCsvBtn.addEventListener('click', () => {
  const params = buildParams();
  const qs = new URLSearchParams(params).toString();
  window.open('/export/transactions_csv?' + qs, '_blank');
});

/* Apply button behavior: choose active tab and render appropriately */
applyBtn.addEventListener('click', async () => {
  const graphsActive = graphsTabBtn.classList.contains('active');
  const params = buildParams();
  if (graphsActive) {
    await renderGraphs(params);
    // show graphs pane
    document.getElementById('graphsPane').classList.add('show', 'active');
    document.getElementById('rawPane') && document.getElementById('rawPane').classList.remove('show', 'active');
    graphsTabBtn.classList.add('active');
  } else {
    await renderRaw(params);
    document.getElementById('rawPane') && document.getElementById('rawPane').classList.add('show', 'active');
    document.getElementById('graphsPane').classList.remove('show', 'active');
    graphsTabBtn.classList.remove('active');
  }
});

/* Manage tab clicks so Apply determines which to load */
graphsTabBtn.addEventListener('click', (e) => {
  graphsTabBtn.classList.add('active');
  // show graphs pane (but do not auto-load - user must press Apply)
  document.getElementById('graphsPane').classList.add('show', 'active');
  document.getElementById('rawPane') && document.getElementById('rawPane').classList.remove('show', 'active');
});

/* initialize dates and load default view (graphs) on DOM ready */
document.addEventListener('DOMContentLoaded', () => {
  const today = new Date().toISOString().slice(0, 10);
  toDate.value = today;
  const prev = new Date();
  prev.setMonth(prev.getMonth() - 1);
  fromDate.value = prev.toISOString().slice(0, 10);

  // default to graphs tab selected; user must press Apply to load
  graphsTabBtn.classList.add('active');
  document.getElementById('graphsPane').classList.add('show', 'active');

  fromDate.disabled = false;
  toDate.disabled = false;
});