async function fetchJSON(url, params = {}) {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(url + (query ? `?${query}` : ''));
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

let activePage = 1;
let activeSort = 'when';
let activeDir = 'desc';

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

// Use centralized function from utils.js
const escapeHtml = (v) => window.FinTrak.escapeHtml(v);

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

function renderPagination(container, page, totalPages, totalItems, onPageChange) {
  if (!container) return;
  container.innerHTML = '';
  if (totalPages <= 1) return;

  const nav = document.createElement('nav');
  nav.setAttribute('aria-label', 'Pagination');
  nav.className = 'd-flex justify-content-center mt-3';

  const ul = document.createElement('ul');
  ul.className = 'pagination mb-0';

  function addPageItem(targetPage, label, active = false, disabled = false) {
    const li = document.createElement('li');
    li.className = `page-item${active ? ' active' : ''}${disabled ? ' disabled' : ''}`;
    
    if (disabled || active) {
      const span = document.createElement('span');
      span.className = 'page-link';
      span.textContent = label;
      li.appendChild(span);
    } else {
      const btn = document.createElement('button');
      btn.className = 'page-link';
      btn.type = 'button';
      btn.textContent = label;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        onPageChange(targetPage);
      });
      li.appendChild(btn);
    }
    ul.appendChild(li);
  }

  addPageItem(1, '«', false, page <= 1);
  addPageItem(page - 1, '‹', false, page <= 1);

  const start = Math.max(1, page - 2);
  const end = Math.min(totalPages, page + 2);

  if (start > 1) {
    addPageItem(null, '...', false, true);
  }

  for (let i = start; i <= end; i++) {
    addPageItem(i, String(i), i === page);
  }

  if (end < totalPages) {
    addPageItem(null, '...', false, true);
  }

  addPageItem(page + 1, '›', false, page >= totalPages);
  addPageItem(totalPages, '»', false, page >= totalPages);

  nav.appendChild(ul);
  container.appendChild(nav);

  const showingDiv = document.createElement('div');
  showingDiv.className = 'text-center text-muted small mt-2';
  const from = (page - 1) * 12 + 1;
  const to = Math.min(page * 12, totalItems);
  showingDiv.innerHTML = `Showing <strong>${totalItems > 0 ? from : 0}</strong>-<strong>${to}</strong> of <strong>${totalItems}</strong>`;
  container.appendChild(showingDiv);
}

async function refreshAnalyticsTransactionsOnly() {
  const params = buildParams();
  setStatus('Loading page...', 'info');
  try {
    const tx = await fetchJSON('/api/transactions_range', { 
      ...params, 
      page: activePage,
      sort: activeSort,
      dir: activeDir
    });
    renderTransactions(tx.transactions || []);
    renderPagination(
      document.getElementById('analyticsPagination'),
      tx.page || 1,
      tx.total_pages || 1,
      tx.total_items || 0,
      (newPage) => {
        activePage = newPage;
        refreshAnalyticsTransactionsOnly();
      }
    );
    setStatus('Page loaded.', 'success');
  } catch (error) {
    console.error('Failed to load transaction page', error);
    setStatus('Unable to load page.', 'danger');
  }
}

function initTableHeaders() {
  const table = elements.rawTable;
  if (!table) return;
  const headers = table.querySelectorAll('th.sortable-header');
  
  const doubleArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="ms-1 sort-svg-icon sort-svg-icon-muted"><path d="m7 15 5 5 5-5M7 9l5-5 5 5"/></svg>`;
  const upArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="ms-1 text-primary sort-svg-icon"><path d="m18 15-6-6-6 6"/></svg>`;
  const downArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="ms-1 text-primary sort-svg-icon"><path d="m6 9 6 6 6-6"/></svg>`;

  headers.forEach(header => {
    const colKey = header.getAttribute('data-sort-key');
    if (!colKey) return;
    
    header.style.cursor = 'pointer';
    let iconSpan = header.querySelector('.sort-icon');
    if (!iconSpan) {
      iconSpan = document.createElement('span');
      iconSpan.className = 'sort-icon';
      header.appendChild(iconSpan);
    }
    
    if (activeSort === colKey) {
      header.classList.add('active');
      header.setAttribute('data-dir', activeDir);
      iconSpan.innerHTML = (activeDir === 'desc') ? downArrowSvg : upArrowSvg;
    } else {
      header.classList.remove('active');
      header.removeAttribute('data-dir');
      iconSpan.innerHTML = doubleArrowSvg;
    }
    
    header.addEventListener('click', (e) => {
      e.preventDefault();
      const nextDir = (activeSort === colKey && activeDir === 'asc') ? 'desc' : 'asc';
      activeSort = colKey;
      activeDir = nextDir;
      activePage = 1;
      
      headers.forEach(h => {
        const hKey = h.getAttribute('data-sort-key');
        const hIcon = h.querySelector('.sort-icon');
        if (hKey === activeSort) {
          h.classList.add('active');
          h.setAttribute('data-dir', activeDir);
          if (hIcon) hIcon.innerHTML = (activeDir === 'desc') ? downArrowSvg : upArrowSvg;
        } else {
          h.classList.remove('active');
          h.removeAttribute('data-dir');
          if (hIcon) hIcon.innerHTML = doubleArrowSvg;
        }
      });
      
      refreshAnalyticsTransactionsOnly();
    });
  });
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
      fetchJSON('/api/transactions_range', { 
        ...params, 
        page: activePage,
        sort: activeSort,
        dir: activeDir
      }),
    ]);

    updateSummary(totals.summary || {});
    renderInsights(totals, categories || []);
    const chartsRendered = renderCharts(totals, categories || []);
    renderTransactions(tx.transactions || []);
    renderPagination(
      document.getElementById('analyticsPagination'),
      tx.page || 1,
      tx.total_pages || 1,
      tx.total_items || 0,
      (newPage) => {
        activePage = newPage;
        refreshAnalyticsTransactionsOnly();
      }
    );
    if (chartsRendered) {
      setStatus(`Showing ${formatDisplayDateText(params.from)} to ${formatDisplayDateText(params.to)}, grouped ${params.period}.`, 'success');
    }
  } catch (error) {
    console.error('analytics render failed', error);
    destroyCharts();
    updateSummary({});
    renderTransactions([]);
    setStatus('Unable to load spend analytics. Check the connection and try again.', 'danger');
    elements.insightsArea.innerHTML = '<p>Spend analytics could not be loaded from the server.</p>';
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
  initTableHeaders();

  if (controls?.init) {
    controlApi = controls.init(
      {
        applyBtn: elements.applyBtn,
        fromDate: elements.fromDate,
        toDate: elements.toDate,
        periodSelect: elements.periodSelect,
        presets: elements.presets,
      },
      { onRefresh: () => { activePage = 1; refreshAnalytics(); }, defaultRange: '30d' },
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
