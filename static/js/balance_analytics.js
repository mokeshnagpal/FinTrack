async function fetchJSON(url, params = {}) {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(url + (query ? `?${query}` : ''));
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

const controls = window.FinTrak?.analyticsControls;

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
  presets: Array.from(document.querySelectorAll('[data-range]')),
  tabs: Array.from(document.querySelectorAll('#balanceAnalyticsTabs [data-view]')),
  graphsPane: document.getElementById('graphsPane'),
  rawPane: document.getElementById('rawPane'),
  insightsArea: document.getElementById('insightsArea'),
  entriesTable: document.getElementById('entriesTable'),
  entriesTableBody: document.querySelector('#entriesTable tbody'),
  balanceTrendCanvas: document.getElementById('balanceTrendChart'),
  deltaCanvas: document.getElementById('deltaChart'),
  cumulativeCanvas: document.getElementById('cumulativeChart'),
  typeCanvas: document.getElementById('typeChart'),
  summary: {
    current: document.getElementById('sumCurrent'),
    net: document.getElementById('sumNet'),
    count: document.getElementById('sumCount'),
    avg: document.getElementById('sumAvg'),
    pct: document.getElementById('sumPct'),
    closing: document.getElementById('sumClosing'),
    opening: document.getElementById('sumOpening'),
    min: document.getElementById('sumMin'),
    max: document.getElementById('sumMax'),
    median: document.getElementById('sumMedian'),
    topType: document.getElementById('sumTopType'),
    largest: document.getElementById('sumLargest'),
  },
};

let balanceTrendChart = null;
let deltaChart = null;
let cumulativeChart = null;
let typeChart = null;
let controlApi = null;

// Use centralized function from utils.js
const escapeHtml = (v) => window.FinTrak.escapeHtml(v);

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

function formatDisplayNote(note) {
  return window.FinTrak?.formatBalanceNote
    ? window.FinTrak.formatBalanceNote(note)
    : note;
}

function setText(node, value) {
  if (node) node.innerText = value;
}

function setStatus(message = '', type = 'info') {
  if (controls?.setStatus) {
    controls.setStatus(elements.status, message, type);
    return;
  }
  if (elements.status) elements.status.textContent = message;
}

function movingAverage(values, windowSize = 3) {
  return values.map((_, index) => {
    const start = Math.max(0, index - windowSize + 1);
    const slice = values.slice(start, index + 1);
    return slice.reduce((sum, value) => sum + value, 0) / slice.length;
  });
}

function cumulativeSum(values) {
  let total = 0;
  return values.map((value) => {
    total += value;
    return Math.round(total * 100) / 100;
  });
}

function destroyCharts() {
  [balanceTrendChart, deltaChart, cumulativeChart, typeChart].forEach((chart) => {
    if (chart && typeof chart.destroy === 'function') chart.destroy();
  });
  balanceTrendChart = null;
  deltaChart = null;
  cumulativeChart = null;
  typeChart = null;
}

function updateSummary(summary = {}) {
  setText(elements.summary.current, Number(summary.current_balance || 0).toFixed(2));
  setText(elements.summary.net, Number(summary.net_change || 0).toFixed(2));
  setText(elements.summary.count, summary.count || 0);
  setText(elements.summary.avg, Number(summary.avg_delta || 0).toFixed(2));
  setText(elements.summary.closing, Number(summary.closing_balance || 0).toFixed(2));
  setText(elements.summary.opening, Number(summary.opening_balance || 0).toFixed(2));
  setText(elements.summary.min, Number(summary.min_delta || 0).toFixed(2));
  setText(elements.summary.max, Number(summary.max_delta || 0).toFixed(2));
  setText(elements.summary.median, Number(summary.median_delta || 0).toFixed(2));
  setText(
    elements.summary.pct,
    summary.pct_change === null || summary.pct_change === undefined
      ? 'N/A'
      : `${Number(summary.pct_change).toFixed(2)}%`,
  );

  const topType = summary.top_type;
  setText(
    elements.summary.topType,
    topType ? `${topType.label} (${Number(topType.total_delta).toFixed(2)})` : '-',
  );

  const largest = summary.largest_entry;
  setText(
    elements.summary.largest,
    largest
      ? `${Number(largest.delta).toFixed(2)} (${largest.type_label || ''})`
      : '-',
  );
}

function renderInsights(data) {
  const summary = data.summary || {};
  const chunks = [];

  chunks.push(
    `Net balance change in this range is <strong>${Number(summary.net_change || 0).toFixed(2)}</strong> across <strong>${summary.count || 0}</strong> entries.`,
  );
  chunks.push(
    `Balance moved from <strong>${Number(summary.opening_balance || 0).toFixed(2)}</strong> to <strong>${Number(summary.closing_balance || 0).toFixed(2)}</strong>.`,
  );

  if (summary.pct_change !== null && summary.pct_change !== undefined) {
    const direction = summary.pct_change > 0 ? 'up' : summary.pct_change < 0 ? 'down' : 'flat';
    chunks.push(
      `Compared with the previous period, net change is <strong>${direction} ${Math.abs(summary.pct_change).toFixed(2)}%</strong>.`,
    );
  }

  if (data.by_type?.length) {
    const top = data.by_type[0];
    chunks.push(
      `Largest impact by type: <strong>${escapeHtml(top.label)}</strong> (${Number(top.total_delta).toFixed(2)}).`,
    );
  }

  const deltas = data.delta_values || [];
  const positive = deltas.filter((value) => value > 0).length;
  const negative = deltas.filter((value) => value < 0).length;
  if (deltas.length) {
    chunks.push(
      `<strong>${positive}</strong> period(s) had a net increase and <strong>${negative}</strong> had a net decrease.`,
    );
  }

  elements.insightsArea.innerHTML = chunks.length
    ? chunks.map((chunk) => `<p>${chunk}</p>`).join('')
    : '<p>No insights available for this range.</p>';
}

function renderCharts(data) {
  destroyCharts();

  if (typeof Chart === 'undefined') {
    setStatus('Chart library is unavailable. Summary and entries are still shown.', 'warning');
    return false;
  }

  const labels = (data.labels || []).map(formatDisplayDateText);
  const balanceValues = data.balance_values || [];
  const deltaValues = data.delta_values || [];

  balanceTrendChart = new Chart(elements.balanceTrendCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Balance',
        data: balanceValues,
        fill: true,
        tension: 0.25,
      }, {
        label: 'Moving avg (3)',
        data: movingAverage(balanceValues, 3),
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

  deltaChart = new Chart(elements.deltaCanvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Net change',
        data: deltaValues,
        backgroundColor: deltaValues.map((value) => (
          value >= 0 ? 'rgba(32, 139, 122, 0.65)' : 'rgba(239, 68, 68, 0.65)'
        )),
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
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

  cumulativeChart = new Chart(elements.cumulativeCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Cumulative change',
        data: cumulativeSum(deltaValues),
        fill: true,
        tension: 0.2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
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

  const byType = data.by_type || [];
  typeChart = new Chart(elements.typeCanvas.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: byType.map((item) => item.label),
      datasets: [{
        data: byType.map((item) => Math.abs(item.total_delta)),
      }],
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

async function refreshAnalyticsEntriesOnly() {
  const params = controlApi ? controlApi.buildParams() : {};
  setStatus('Loading page...', 'info');
  try {
    const data = await fetchJSON('/api/balance_analytics', { 
      ...params, 
      page: activePage,
      sort: activeSort,
      dir: activeDir
    });
    renderEntries(data.entries || []);
    renderPagination(
      document.getElementById('balanceAnalyticsPagination'),
      data.page || 1,
      data.total_pages || 1,
      data.total_items || 0,
      (newPage) => {
        activePage = newPage;
        refreshAnalyticsEntriesOnly();
      }
    );
    setStatus('Page loaded.', 'success');
  } catch (error) {
    console.error('Failed to load balance entry page', error);
    setStatus('Unable to load page.', 'danger');
  }
}

function initTableHeaders() {
  const table = elements.entriesTable;
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
      
      refreshAnalyticsEntriesOnly();
    });
  });
}

function renderEntries(entries) {
  if (!elements.entriesTableBody) return;
  elements.entriesTableBody.innerHTML = '';

  if (!entries.length) {
    elements.entriesTableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No balance entries in this range.</td></tr>';
    return;
  }

  entries.forEach((entry) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td data-label="When">${formatDisplayDate(entry.timestamp || '')}</td>
                    <td data-label="Type">${escapeHtml(entry.type_label || entry.type || '')}</td>
                    <td data-label="Delta" class="text-end">${Number(entry.delta || 0).toFixed(2)}</td>
                    <td data-label="Balance" class="text-end">${Number(entry.balance || 0).toFixed(2)}</td>
                    <td data-label="Note">${escapeHtml(formatDisplayNote(entry.note || ''))}</td>`;
    elements.entriesTableBody.appendChild(tr);
  });
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

async function refreshAnalytics() {
  const params = controlApi ? controlApi.buildParams() : {};
  setStatus('Loading balance analytics...', 'info');
  elements.applyBtn.disabled = true;

  try {
    const data = await fetchJSON('/api/balance_analytics', { 
      ...params, 
      page: activePage,
      sort: activeSort,
      dir: activeDir
    });
    updateSummary(data.summary || {});
    renderInsights(data);
    const chartsRendered = renderCharts(data);
    renderEntries(data.entries || []);
    renderPagination(
      document.getElementById('balanceAnalyticsPagination'),
      data.page || 1,
      data.total_pages || 1,
      data.total_items || 0,
      (newPage) => {
        activePage = newPage;
        refreshAnalyticsEntriesOnly();
      }
    );

    if (chartsRendered) {
      const rangeLabel = params.from && params.to
        ? `${formatDisplayDateText(params.from)} to ${formatDisplayDateText(params.to)}`
        : 'selected range';
      setStatus(`Showing ${rangeLabel}, grouped ${params.period}.`, 'success');
    }
  } catch (error) {
    console.error('balance analytics render failed', error);
    destroyCharts();
    updateSummary({});
    renderEntries([]);
    setStatus('Unable to load balance analytics. Check the connection and try again.', 'danger');
    elements.insightsArea.innerHTML = '<p>Balance analytics could not be loaded from the server.</p>';
  } finally {
    elements.applyBtn.disabled = false;
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
    window.open(`/export/balances_csv?${new URLSearchParams(controlApi ? controlApi.buildParams() : {}).toString()}`, '_blank');
  });

  refreshAnalytics();
});
