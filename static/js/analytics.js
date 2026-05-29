async function fetchJSON(url, params = {}) {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(url + (query ? `?${query}` : ''));
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

const elements = {
  applyBtn: document.getElementById('applyBtn'),
  fromDate: document.getElementById('fromDate'),
  toDate: document.getElementById('toDate'),
  periodSelect: document.getElementById('periodSelect'),
  exportCsvBtn: document.getElementById('exportCsvBtn'),
  status: document.getElementById('analyticsStatus'),
  mainCanvas: document.getElementById('mainChart'),
  sideCanvas: document.getElementById('sideChart'),
  rawPane: document.getElementById('rawPane'),
  graphsPane: document.getElementById('graphsPane'),
  rawTable: document.getElementById('rawTable'),
  rawTableBody: document.querySelector('#rawTable tbody'),
  insightsArea: document.getElementById('insightsArea'),
  tabs: Array.from(document.querySelectorAll('#analyticsTabs [data-view]')),
  presets: Array.from(document.querySelectorAll('[data-range]')),
  summary: {
    total: document.getElementById('sumTotal'),
    count: document.getElementById('sumCount'),
    avg: document.getElementById('sumAvg'),
    median: document.getElementById('sumMedian'),
    min: document.getElementById('sumMin'),
    max: document.getElementById('sumMax'),
    prev: document.getElementById('sumPrev'),
    pct: document.getElementById('sumPct'),
    topCat: document.getElementById('sumTopCat'),
    largest: document.getElementById('sumLargest'),
  },
};

let mainChart = null;
let sideChart = null;

function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe).replace(/[&<>"'`=/]/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;',
  })[char]);
}

function formatDateInput(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function formatDisplayDate(value) {
  return window.FinTrak && window.FinTrak.formatFriendlyDate
    ? window.FinTrak.formatFriendlyDate(value)
    : value;
}

function setStatus(message = '', type = 'info') {
  if (!elements.status) return;
  elements.status.textContent = message;
  elements.status.className = message ? `analytics-status analytics-status-${type} mb-3` : 'analytics-status mb-3';
}

function setText(node, value) {
  if (node) node.innerText = value;
}

function buildParams() {
  return {
    period: elements.periodSelect.value,
    count: 30,
    from: elements.fromDate.value || '',
    to: elements.toDate.value || '',
  };
}

function destroyCharts() {
  [mainChart, sideChart].forEach((chart) => {
    if (chart && typeof chart.destroy === 'function') chart.destroy();
  });
  mainChart = null;
  sideChart = null;
}

function movingAverage(values, windowSize = 3) {
  return values.map((_, index) => {
    const start = Math.max(0, index - windowSize + 1);
    const slice = values.slice(start, index + 1);
    return slice.reduce((sum, value) => sum + value, 0) / slice.length;
  });
}

function updateSummary(summary = {}) {
  const top = summary.top_category;
  const largest = summary.largest_transaction;

  setText(elements.summary.total, Number(summary.total || 0).toFixed(2));
  setText(elements.summary.count, summary.count || 0);
  setText(elements.summary.avg, Number(summary.avg || 0).toFixed(2));
  setText(elements.summary.median, Number(summary.median || 0).toFixed(2));
  setText(elements.summary.min, Number(summary.min || 0).toFixed(2));
  setText(elements.summary.max, Number(summary.max || 0).toFixed(2));
  setText(elements.summary.prev, Number(summary.prev_total || 0).toFixed(2));
  setText(
    elements.summary.pct,
    summary.pct_change === null || summary.pct_change === undefined
      ? 'N/A'
      : `${Number(summary.pct_change).toFixed(2)}%`,
  );
  setText(
    elements.summary.topCat,
    top && top.category ? `${top.category} (${Number(top.amount).toFixed(2)})` : '-',
  );
  setText(
    elements.summary.largest,
    largest ? `${Number(largest.amount).toFixed(2)} - ${largest.description || ''}` : '-',
  );
}

function renderInsights(totals, categories) {
  const chunks = [];
  const summary = totals && totals.summary;

  if (summary) {
    chunks.push(`Total spending is <strong>${Number(summary.total || 0).toFixed(2)}</strong> across <strong>${summary.count || 0}</strong> transactions.`);

    if (summary.pct_change !== null && summary.pct_change !== undefined) {
      const direction = summary.pct_change > 0 ? 'up' : summary.pct_change < 0 ? 'down' : 'flat';
      chunks.push(`Compared with the previous period, spending is <strong>${direction} ${Math.abs(summary.pct_change).toFixed(2)}%</strong>.`);
    } else {
      chunks.push('Previous-period comparison is not available for this range.');
    }
  }

  if (categories && categories.length) {
    const sorted = [...categories].sort((a, b) => b.amount - a.amount);
    const top = sorted[0];
    chunks.push(`Biggest category: <strong>${escapeHtml(top.category)}</strong> with <strong>${Number(top.amount || 0).toFixed(2)}</strong>.`);

    if (sorted.length > 1) {
      const nextCategories = sorted
        .slice(1, 4)
        .map((item) => `${escapeHtml(item.category)} (${Number(item.amount || 0).toFixed(2)})`)
        .join(', ');
      chunks.push(`Other notable categories: ${nextCategories}.`);
    }
  }

  if (totals && totals.values && totals.values.length >= 2) {
    const values = totals.values;
    const first = values[0];
    const last = values[values.length - 1];
    const pct = first !== 0 ? ((last - first) / Math.abs(first)) * 100 : null;
    chunks.push(
      pct === null || Number.isNaN(pct)
        ? 'Trend needs a non-zero starting value for a reliable percentage.'
        : `Trend is <strong>${pct > 0 ? 'increasing' : pct < 0 ? 'decreasing' : 'flat'}</strong> by ${Math.abs(pct).toFixed(2)}% from first to last point.`,
    );
  }

  elements.insightsArea.innerHTML = chunks.length
    ? chunks.map((chunk) => `<p>${chunk}</p>`).join('')
    : '<p>No insights available for this range.</p>';
}

function renderCharts(totals, categories) {
  destroyCharts();

  if (typeof Chart === 'undefined') {
    setStatus('Chart library is unavailable. Summary and transactions are still shown.', 'warning');
    return false;
  }

  const labels = totals.labels || [];
  const values = totals.values || [];

  mainChart = new Chart(elements.mainCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Amount',
        data: values,
        fill: true,
        tension: 0.25,
      }, {
        label: 'Moving Avg (3)',
        data: movingAverage(values, 3),
        type: 'line',
        borderDash: [5, 5],
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { tooltip: { mode: 'index', intersect: false } },
      scales: { x: { ticks: { maxRotation: 0 } } },
    },
  });

  sideChart = new Chart(elements.sideCanvas.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: categories.map((item) => item.category),
      datasets: [{ data: categories.map((item) => item.amount) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom' } },
    },
  });
  return true;
}

function renderTransactions(transactions) {
  if (!elements.rawTableBody) return;
  elements.rawTableBody.innerHTML = '';
  const canEdit = elements.rawTable && elements.rawTable.dataset.canEdit === 'true';
  const emptyColspan = canEdit ? 5 : 4;

  if (!transactions.length) {
    elements.rawTableBody.innerHTML = `<tr><td colspan="${emptyColspan}" class="text-center text-muted py-4">No transactions in this range.</td></tr>`;
    return;
  }

  transactions.forEach((transaction) => {
    const tr = document.createElement('tr');
    const editCell = canEdit
      ? `<td class="text-end"><a class="btn btn-sm btn-outline-primary" href="/edit/${encodeURIComponent(transaction.id)}">Edit</a></td>`
      : '';
    tr.innerHTML = `<td>${escapeHtml(formatDisplayDate(transaction.timestamp))}</td>
                    <td>${escapeHtml(transaction.description)}</td>
                    <td>${escapeHtml(transaction.category)}</td>
                    <td class="text-end">${Number(transaction.amount).toFixed(2)}</td>
                    ${editCell}`;
    elements.rawTableBody.appendChild(tr);
  });
}

async function refreshAnalytics() {
  const params = buildParams();
  setStatus('Loading analytics...', 'info');
  elements.applyBtn.disabled = true;

  try {
    const [totals, categories, tx] = await Promise.all([
      fetchJSON('/api/totals', params),
      fetchJSON('/api/category_breakdown', params),
      fetchJSON('/api/transactions_range', params),
    ]);

    updateSummary(totals.summary || {});
    renderInsights(totals, categories || []);
    const chartsRendered = renderCharts(totals, categories || []);
    renderTransactions(tx.transactions || []);
    if (chartsRendered) {
      setStatus(`Showing ${params.from} to ${params.to}, grouped ${params.period}.`, 'success');
    }
  } catch (error) {
    console.error('analytics render failed', error);
    const snapshot = window.FinTrak?.cache?.readSnapshot?.();
    if (snapshot?.transactions?.length) {
      destroyCharts();
      updateSummary({});
      renderTransactions(snapshot.transactions || []);
      setStatus('Showing cached recent transactions. Full analytics will load when the service wakes.', 'warning');
      elements.insightsArea.innerHTML = '<p>Full analytics and graphs need fresh server data.</p>';
    } else {
      setStatus(error.message, 'danger');
      elements.insightsArea.innerHTML = `<p>${escapeHtml(error.message)}</p>`;
    }
  } finally {
    elements.applyBtn.disabled = false;
  }
}

function setActiveView(view) {
  elements.tabs.forEach((tab) => {
    const active = tab.dataset.view === view;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });

  elements.graphsPane.classList.toggle('show', view === 'graphs');
  elements.graphsPane.classList.toggle('active', view === 'graphs');
  elements.rawPane.classList.toggle('show', view === 'raw');
  elements.rawPane.classList.toggle('active', view === 'raw');
}

function setRange(range) {
  const today = new Date();
  const from = new Date(today);

  if (range === '90d') {
    from.setDate(today.getDate() - 89);
    elements.periodSelect.value = 'daily';
  } else if (range === '12m') {
    from.setMonth(today.getMonth() - 11);
    from.setDate(1);
    elements.periodSelect.value = 'monthly';
  } else if (range === 'ytd') {
    from.setMonth(0, 1);
    elements.periodSelect.value = 'monthly';
  } else {
    from.setDate(today.getDate() - 29);
    elements.periodSelect.value = 'daily';
  }

  elements.fromDate.value = formatDateInput(from);
  elements.toDate.value = formatDateInput(today);
}

document.addEventListener('DOMContentLoaded', () => {
  setRange('30d');
  setActiveView('graphs');

  elements.presets.forEach((button) => {
    button.addEventListener('click', async () => {
      elements.presets.forEach((item) => item.classList.remove('active'));
      button.classList.add('active');
      setRange(button.dataset.range);
      await refreshAnalytics();
    });
  });

  if (elements.presets[0]) {
    elements.presets[0].classList.add('active');
  }

  elements.tabs.forEach((tab) => {
    tab.addEventListener('click', () => setActiveView(tab.dataset.view));
  });

  elements.periodSelect.addEventListener('change', refreshAnalytics);
  elements.fromDate.addEventListener('change', () => {
    elements.presets.forEach((item) => item.classList.remove('active'));
    refreshAnalytics();
  });
  elements.toDate.addEventListener('change', () => {
    elements.presets.forEach((item) => item.classList.remove('active'));
    refreshAnalytics();
  });

  elements.exportCsvBtn.addEventListener('click', () => {
    window.open(`/export/transactions_csv?${new URLSearchParams(buildParams()).toString()}`, '_blank');
  });

  elements.applyBtn.addEventListener('click', refreshAnalytics);
  refreshAnalytics();
});
