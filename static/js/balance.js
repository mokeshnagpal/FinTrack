/* small JSON helper */
async function fetchJSON(url, params = {}, opts = {}) {
  let full = url;
  if (params && Object.keys(params).length) {
    const qs = new URLSearchParams(params).toString();
    full = url + (qs ? ('?' + qs) : '');
  }
  const resp = await fetch(full, opts);
  return resp.json();
}

/* DOM refs */
const currentBalanceEl = document.getElementById('currentBalance');
const balanceTimestampEl = document.getElementById('balanceTimestamp');
const periodSelect = document.getElementById('periodSelect');
const refreshBtn = document.getElementById('refreshBtn');

const addAmount = document.getElementById('addAmount');
const addNote = document.getElementById('addNote');
const addBtn = document.getElementById('addBtn');

const syncAmount = document.getElementById('syncAmount');
const syncNote = document.getElementById('syncNote');
const syncBtn = document.getElementById('syncBtn');

const undoBtn = document.getElementById('undoBtn');

const historyBody = document.getElementById('historyBody');
const balanceCanvas = document.getElementById('balanceChart');
const toastContainer = document.getElementById('toastContainer');
let balanceChart = null;

/* helpers */
function formatNumber(n) {
  return Number(n || 0).toFixed(2);
}
function rupee(n) { return `₹ ${formatNumber(n)}`; }

function destroyChart() {
  if (balanceChart) {
    try { balanceChart.destroy(); } catch (e) {}
    balanceChart = null;
  }
  if (balanceCanvas && balanceCanvas.getContext) {
    const ctx = balanceCanvas.getContext('2d');
    try { ctx.clearRect(0, 0, balanceCanvas.width, balanceCanvas.height); } catch (e) {}
    balanceCanvas.width = balanceCanvas.clientWidth;
    balanceCanvas.height = balanceCanvas.clientHeight;
  }
}
function showToast(title, type = 'info', message = '') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    // fallback in case base.html didn't load container
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '2000';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast text-bg-${type} border-0 shadow-sm mb-2`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');
  toast.innerHTML = `
    <div class="d-flex align-items-center">
      <div class="toast-body">
        <strong>${title}</strong>${message ? `<div class="small mt-1">${message}</div>` : ''}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto"
        data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;

  container.appendChild(toast);

  // Create and show Bootstrap toast
  const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
  bsToast.show();

  // Remove after hidden
  toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

/* render chart */
async function renderChart(period = 'daily') {
  destroyChart();
  let resp = { labels: [], values: [] };
  try {
    resp = await fetchJSON('/api/balance_series', { period: period, count: 30 });
  } catch (e) {
    console.error('chart fetch failed', e);
    showToast('Failed to load chart', 'warning');
  }

  const labels = resp.labels || [];
  const values = resp.values || [];

  if (typeof Chart === 'undefined') {
    // Chart.js missing
    return;
  }

  balanceChart = new Chart(balanceCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Balance',
        data: values,
        fill: true,
        tension: 0.2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { tooltip: { mode: 'index', intersect: false } },
      scales: { x: { ticks: { maxRotation: 0 } } }
    }
  });
}

/* refresh current & history */
async function refreshAll() {
  try {
    const data = await fetchJSON('/api/balance_current');
    const cur = data.current || { balance: 0.0, timestamp: null };
    currentBalanceEl.innerText = formatNumber(cur.balance);
    balanceTimestampEl.innerText = cur.timestamp ? `Updated: ${cur.timestamp}` : 'No entries yet';

    // history
    historyBody.innerHTML = '';
    (data.history || []).forEach(h => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(h.timestamp || '')}</td>
                      <td>${escapeHtml(h.type || '')}</td>
                      <td style="text-align:right">${formatNumber(h.delta)}</td>
                      <td style="text-align:right">${formatNumber(h.balance)}</td>
                      <td>${escapeHtml(h.note || '')}</td>`;
      historyBody.appendChild(tr);
    });
  } catch (e) {
    console.error('refreshAll failed', e);
    showToast('Failed to refresh balance', 'danger');
  }
}

/* small util */
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

/* input empty guard helper */
function isEmptyInput(el) {
  // Works for type="number" (value is "" when empty) and text inputs
  return !el || String(el.value || '').trim() === '';
}

/* confirm helper that supports Promise-based overrides of window.confirm */
async function confirmAsync(msg) {
  try {
    const res = confirm(msg);
    if (res instanceof Promise) {
      // some code may have replaced window.confirm with an async version returning Promise<boolean>
      return await res;
    }
    return Boolean(res);
  } catch (e) {
    // fallback: deny
    return false;
  }
}

/* actions */
addBtn.addEventListener('click', async () => {
  if (isEmptyInput(addAmount)) {
    showToast('Enter an amount to add.', 'warning');
    return;
  }

  const v = parseFloat(addAmount.value);
  if (isNaN(v) || v === 0) {
    // preserves previous behaviour (blocking 0); remove `v === 0` if you want to allow zero
    showToast('Enter a valid amount to add.', 'warning');
    return;
  }
  addBtn.disabled = true;
  try {
    const res = await fetchJSON('/api/balance/add', {}, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: v, note: addNote.value || '' })
    });
    if (res && res.balance !== undefined) {
      showToast(`Added ${rupee(v)}`, 'success', `New balance ${rupee(res.balance)}`);
    } else {
      showToast('Added (server returned no balance)', 'info');
    }
    addAmount.value = '';
    addNote.value = '';
    // reflect UI updates
    await refreshAll();
    await renderChart(periodSelect.value);
  } catch (e) {
    console.error('add failed', e);
    showToast('Add failed', 'danger');
  } finally {
    addBtn.disabled = false;
  }
});

syncBtn.addEventListener('click', async () => {
  if (isEmptyInput(syncAmount)) {
    showToast('Enter a balance to sync.', 'warning');
    return;
  }

  const v = parseFloat(syncAmount.value);
  if (isNaN(v)) {
    showToast('Enter a valid balance value to sync.', 'warning');
    return;
  }
  syncBtn.disabled = true;
  try {
    const res = await fetchJSON('/api/balance/sync', {}, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ balance: v, note: syncNote.value || '' })
    });
    if (res && res.balance !== undefined) {
      showToast(`Balance synced to ${rupee(res.balance)}`, 'success', `Δ ${formatNumber(res.delta || 0)}`);
    } else {
      showToast('Sync completed', 'info');
    }
    syncAmount.value = '';
    syncNote.value = '';
    await refreshAll();
    await renderChart(periodSelect.value);
  } catch (e) {
    console.error('sync failed', e);
    showToast('Sync failed', 'danger');
  } finally {
    syncBtn.disabled = false;
  }
});
undoBtn.addEventListener('click', async () => {
  const ok = await confirmAsync('Undo last balance entry? This will remove the most recent add/sync.');
  if (!ok) return;
  undoBtn.disabled = true;
  try {
    const res = await fetchJSON('/api/balance/undo', {}, { method: 'POST' });

    if (res && res.error) {
      // if backend sent extra advice, show it as sub-message
      showToast(res.error, 'danger', res.advice || '');
    } else if (res && res.current_balance !== undefined) {
      showToast('Undo successful ✅', 'success', `New balance ${rupee(res.current_balance)}`);
    } else {
      showToast('Undo completed.', 'info');
    }

    await refreshAll();
    await renderChart(periodSelect.value);
  } catch (e) {
    console.error('undo failed', e);
    showToast('Undo failed ❌', 'danger');
  } finally {
    undoBtn.disabled = false;
  }
});

/* UI wiring */
refreshBtn.addEventListener('click', async () => {
  await refreshAll();
  await renderChart(periodSelect.value);
});

periodSelect.addEventListener('change', async () => {
  await renderChart(periodSelect.value);
});

/* enable/disable buttons live based on input presence */
if (addAmount) {
  addAmount.addEventListener('input', () => {
    addBtn.disabled = isEmptyInput(addAmount);
  });
}
if (syncAmount) {
  syncAmount.addEventListener('input', () => {
    syncBtn.disabled = isEmptyInput(syncAmount);
  });
}

/* initial load */
document.addEventListener('DOMContentLoaded', async () => {
  // ensure add/sync buttons are disabled if their inputs are empty initially
  if (addBtn) addBtn.disabled = isEmptyInput(addAmount);
  if (syncBtn) syncBtn.disabled = isEmptyInput(syncAmount);

  await refreshAll();
  await renderChart(periodSelect.value);
});
