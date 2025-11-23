/* balance.js — DOM-ready wiring for balance page (no disabling of buttons) */

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

/* utils */
function formatNumber(n) {
  return Number(n || 0).toFixed(2);
}
function rupee(n) { return `₹ ${formatNumber(n)}`; }
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
function isEmptyInput(el) {
  return !el || String(el.value || '').trim() === '';
}

/* toast helper (Bootstrap) */
function showToast(title, type = 'info', message = '') {
  let container = document.getElementById('toastContainer');
  if (!container) {
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
  try {
    const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
  } catch (e) {
    setTimeout(() => toast.remove(), 4000);
  }
}

/* Chart handling */
let balanceChart = null;
function destroyChart(canvas) {
  if (balanceChart && typeof balanceChart.destroy === 'function') {
    try { balanceChart.destroy(); } catch (e) { console.warn('destroyChart error', e); }
    balanceChart = null;
  }
  if (canvas && canvas.getContext) {
    try {
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = canvas.clientWidth || canvas.width;
      canvas.height = canvas.clientHeight || canvas.height;
    } catch (e) {}
  }
}

async function renderChart(period = 'daily', canvasEl) {
  if (!canvasEl) return;
  destroyChart(canvasEl);
  let resp = { labels: [], values: [] };
  try {
    resp = await fetchJSON('/api/balance_series', { period: period, count: 30 });
  } catch (e) {
    console.error('chart fetch failed', e);
    showToast('Failed to load chart', 'warning');
    return;
  }

  const labels = resp.labels || [];
  const values = resp.values || [];

  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not found — skipping chart render');
    return;
  }

  try {
    balanceChart = new Chart(canvasEl.getContext('2d'), {
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
  } catch (e) {
    console.error('Chart render error', e);
  }
}

/* refresh current & history */
async function refreshAll(currentBalanceEl, balanceTimestampEl, historyBody) {
  try {
    const data = await fetchJSON('/api/balance_current');
    const cur = data.current || { balance: 0.0, timestamp: null };
    if (currentBalanceEl) currentBalanceEl.innerText = formatNumber(cur.balance);
    if (balanceTimestampEl) balanceTimestampEl.innerText = cur.timestamp ? `Updated: ${cur.timestamp}` : 'No entries yet';

    if (historyBody) {
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
    }
  } catch (e) {
    console.error('refreshAll failed', e);
    showToast('Failed to refresh balance', 'danger');
  }
}

/* confirm helper supporting async confirm overrides (your template replaces window.confirm) */
async function confirmAsync(msg) {
  try {
    const res = window.confirm(msg);
    if (res instanceof Promise) {
      return await res;
    }
    return Boolean(res);
  } catch (e) {
    return false;
  }
}

/* MAIN: attach after DOM ready */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // DOM refs (grab AFTER DOM ready)
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

    // Basic presence warnings
    if (!currentBalanceEl || !balanceTimestampEl || !historyBody || !balanceCanvas) {
      console.warn('Balance page missing expected elements — page may render partially.');
    }

    // Attach add handler if elements exist (no disabling)
    if (addBtn && addAmount) {
      addBtn.addEventListener('click', async () => {
        if (isEmptyInput(addAmount)) {
          showToast('Enter an amount to add.', 'warning');
          return;
        }
        const v = parseFloat(addAmount.value);
        if (isNaN(v) || v === 0) {
          showToast('Enter a valid amount to add.', 'warning');
          return;
        }
        try {
          const res = await fetchJSON('/api/balance/add', {}, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: v, note: addNote ? (addNote.value || '') : '' })
          });
          if (res && res.balance !== undefined) {
            showToast(`Added ${rupee(v)}`, 'success', `New balance ${rupee(res.balance)}`);
          } else {
            showToast('Added (server returned no balance)', 'info');
          }
          if (addAmount) addAmount.value = '';
          if (addNote) addNote.value = '';
          await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
          await renderChart(periodSelect ? periodSelect.value : 'daily', balanceCanvas);
        } catch (e) {
          console.error('add failed', e);
          showToast('Add failed', 'danger');
        }
      });

      // enable/disable based on input presence only for UX (no programmatic disabling)
      addAmount.addEventListener('input', () => {
        // no-op for disabling; we could change button style instead if desired
      });
    }

    // Attach sync handler if elements exist (no disabling)
    if (syncBtn && syncAmount) {
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
        try {
          const res = await fetchJSON('/api/balance/sync', {}, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ balance: v, note: syncNote ? (syncNote.value || '') : '' })
          });
          if (res && res.balance !== undefined) {
            showToast(`Balance synced to ${rupee(res.balance)}`, 'success', `Δ ${formatNumber(res.delta || 0)}`);
          } else {
            showToast('Sync completed', 'info');
          }
          if (syncAmount) syncAmount.value = '';
          if (syncNote) syncNote.value = '';
          await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
          await renderChart(periodSelect ? periodSelect.value : 'daily', balanceCanvas);
        } catch (e) {
          console.error('sync failed', e);
          showToast('Sync failed', 'danger');
        }
      });

      syncAmount.addEventListener('input', () => {
        // no-op for disabling
      });
    }

    // Attach undo handler if element exists (no disabling)
    if (undoBtn) {
      undoBtn.addEventListener('click', async () => {
        const ok = await confirmAsync('Undo last balance entry? This will remove the most recent add/sync.');
        if (!ok) return;
        try {
          const res = await fetchJSON('/api/balance/undo', {}, { method: 'POST' });
          if (res && res.error) {
            showToast(res.error, 'danger', res.advice || '');
          } else if (res && res.current_balance !== undefined) {
            showToast('Undo successful ✅', 'success', `New balance ${rupee(res.current_balance)}`);
          } else {
            showToast('Undo completed.', 'info');
          }
          await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
          await renderChart(periodSelect ? periodSelect.value : 'daily', balanceCanvas);
        } catch (e) {
          console.error('undo failed', e);
          showToast('Undo failed ❌', 'danger');
        }
      });
    }

    // refresh & period wiring (these exist in both modes)
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
        await renderChart(periodSelect ? periodSelect.value : 'daily', balanceCanvas);
      });
    }
    if (periodSelect) {
      periodSelect.addEventListener('change', async () => {
        await renderChart(periodSelect.value, balanceCanvas);
      });
    }

    // initial load
    await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
    await renderChart(periodSelect ? periodSelect.value : 'daily', balanceCanvas);

  } catch (err) {
    console.error('Balance script initialization error', err);
    showToast('Balance script error', 'danger', String(err));
  }
});
