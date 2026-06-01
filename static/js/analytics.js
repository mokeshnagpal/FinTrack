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
  panelHeading: document.getElementById('panelHeading'),
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

const controls = window.FinTrak?.analyticsControls;
let controlApi = null;

function formatDisplayDate(value) {
  if (window.FinTrak?.formatFriendlyDateHtml) {
    return window.FinTrak.formatFriendlyDateHtml(value);
  }
  return escapeHtml(value || '');
}

function formatDisplayDateText(value) {
  if (window.FinTrak?.formatFriendlyDate) {
    return window.FinTrak.formatFriendlyDate(value);
  }
  return value || '';
}

function setStatus(message = '', type = 'info') {
  if (controls?.setStatus) {
    controls.setStatus(elements.status, message, type);
    return;
  }
  if (!elements.status) return;
  elements.status.textContent = message;
  elements.status.className = message ? `analytics-status analytics-status-${type} mb-3` : 'analytics-status mb-3';
}

function setText(node, value) {
  if (node) node.innerText = value;
}

function buildParams() {
  return controlApi ? controlApi.buildParams() : {
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

function buildCachedSpendFallback(snapshot) {
  const transactions = Array.isArray(snapshot?.transactions) ? snapshot.transactions : [];
  const total = transactions.reduce((sum, item) => sum + Number(item.amount || 0), 0);
  const amounts = transactions.map((item) => Number(item.amount || 0)).sort((a, b) => a - b);
  const count = transactions.length;
  const avg = count ? total / count : 0;
  const median = count
    ? (count % 2 ? amounts[Math.floor(count / 2)] : (amounts[count / 2 - 1] + amounts[count / 2]) / 2)
    : 0;
  const min = count ? amounts[0] : 0;
  const max = count ? amounts[count - 1] : 0;
  const byCategory = transactions.reduce((acc, item) => {
    const category = item.category || 'Uncategorized';
    acc[category] = (acc[category] || 0) + Number(item.amount || 0);
    return acc;
  }, {});
  const categories = Object.entries(byCategory)
    .map(([category, amount]) => ({ category, amount }))
    .sort((a, b) => b.amount - a.amount);
  const largest = transactions.reduce((best, item) => (
    !best || Number(item.amount || 0) > Number(best.amount || 0) ? item : best
  ), null);

  return {
    transactions,
    categories,
    summary: {
      total,
      count,
      avg,
      median,
      min,
      max,
      prev_total: 0,
      pct_change: null,
      top_category: categories[0] || null,
      largest_transaction: largest,
    },
  };
}

function renderOfflineSpendNotice(fallback) {
  const categoryText = fallback.categories.length
    ? `Top cached category: <strong>${escapeHtml(fallback.categories[0].category)}</strong> (${Number(fallback.categories[0].amount || 0).toFixed(2)}).`
    : 'No category breakdown is available from cache.';

  elements.insightsArea.innerHTML = `
    <p><strong>Offline limited view.</strong> Full spend analytics need the server because date filtering, previous-period comparison, and complete chart data are calculated from Firestore.</p>
    <p>Showing only <strong>${fallback.transactions.length}</strong> cached recent transaction${fallback.transactions.length === 1 ? '' : 's'} stored in this browser.</p>
    <p>${categoryText}</p>
  `;
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

  const labels = (totals.labels || []).map(formatDisplayDateText);
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
      scales: {
        x: {
          ticks: {
            minRotation: 45,
            maxRotation: 45,
          },
        },
      },
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

  if (!transactions.length) {
    elements.rawTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted py-4">No transactions in this range.</td></tr>`;
    return;
  }

  transactions.forEach((transaction) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td data-label="When">${formatDisplayDate(transaction.timestamp)}</td>
                    <td data-label="Description">${escapeHtml(transaction.description)}</td>
                    <td data-label="Category">${escapeHtml(transaction.category)}</td>
                    <td data-label="Amount" class="text-end">${Number(transaction.amount).toFixed(2)}</td>`;
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
    if (elements.rawTable && window.FinTrak && typeof window.FinTrak.initUnifiedTable === 'function') {
      window.FinTrak.initUnifiedTable(elements.rawTable);
    }
    if (chartsRendered) {
      setStatus(`Showing ${formatDisplayDateText(params.from)} to ${formatDisplayDateText(params.to)}, grouped ${params.period}.`, 'success');
    }
  } catch (error) {
    console.error('analytics render failed', error);
    const snapshot = window.FinTrak?.cache?.readSnapshot?.();
    if (snapshot?.transactions?.length) {
      const fallback = buildCachedSpendFallback(snapshot);
      destroyCharts();
      updateSummary(fallback.summary);
      renderTransactions(fallback.transactions);
      if (elements.rawTable && window.FinTrak && typeof window.FinTrak.initUnifiedTable === 'function') {
        window.FinTrak.initUnifiedTable(elements.rawTable);
      }
      setStatus('Offline: showing limited cached spend data only. Full analytics will load when the service wakes.', 'warning');
      renderOfflineSpendNotice(fallback);
    } else {
      destroyCharts();
      updateSummary({});
      renderTransactions([]);
      setStatus('Offline: spend analytics are unavailable because no cached transactions were found.', 'danger');
      elements.insightsArea.innerHTML = '<p><strong>Offline.</strong> Full spend analytics need server data. Open this page once online to cache recent transactions for a small offline view.</p>';
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

  if (elements.panelHeading) {
    elements.panelHeading.textContent = view === 'raw' ? 'Transaction' : 'Insight';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setActiveView('graphs');

  if (controls?.init) {
    controlApi = controls.init(
      {
        applyBtn: elements.applyBtn,
        fromDate: elements.fromDate,
        toDate: elements.toDate,
        periodSelect: elements.periodSelect,
        presets: elements.presets,
      },
      { onRefresh: refreshAnalytics, defaultRange: '30d' },
    );
  }

  elements.tabs.forEach((tab) => {
    tab.addEventListener('click', () => setActiveView(tab.dataset.view));
  });

  elements.exportCsvBtn.addEventListener('click', () => {
    window.open(`/export/transactions_csv?${new URLSearchParams(buildParams()).toString()}`, '_blank');
  });

  refreshAnalytics();
});
