(function () {
  const refreshTimeoutMs = 8000;

  // Use centralized functions from utils.js
  const formatNumber = (v) => window.FinTrak.formatNumber(v);
  const escapeHtml = (v) => window.FinTrak.escapeHtml(v);

  function formatDate(value) {
    if (window.FinTrak?.formatFriendlyDateHtml) {
      return window.FinTrak.formatFriendlyDateHtml(value);
    }
    return escapeHtml(value || '');
  }

  function showNotice(message, type = 'warning') {
    if (window.FinTrak && typeof window.FinTrak.showToast === 'function') {
      window.FinTrak.showToast(message, type === 'warning' ? 'warning' : 'info');
    }
  }

  function renderTotalsData(split) {
    const target = document.getElementById('splitTotals');
    if (!target) return;

    const summaryTotalSpent = document.getElementById('summaryTotalSpent');
    const summaryNumPeople = document.getElementById('summaryNumPeople');
    const summaryShareAmount = document.getElementById('summaryShareAmount');

    const totals = Array.isArray(split?.totals) ? split.totals : [];
    let totalSpent = split?.total_spent;
    let shareAmount = split?.share_amount;
    let people = split?.people;

    if (totalSpent === undefined) {
      totalSpent = totals.reduce((sum, item) => sum + Number(item.amount || 0), 0);
    }
    if (people === undefined) {
      people = totals.map(item => item.person);
    }
    if (shareAmount === undefined) {
      shareAmount = people.length > 0 ? (totalSpent / people.length) : 0;
    }

    if (summaryTotalSpent) summaryTotalSpent.textContent = formatNumber(totalSpent);
    if (summaryNumPeople) summaryNumPeople.textContent = people.length;
    if (summaryShareAmount) summaryShareAmount.textContent = `Rs. ${formatNumber(shareAmount)}`;

    const recordButtons = document.querySelectorAll('.record-share-btn');
    recordButtons.forEach(btn => {
        btn.setAttribute('data-share-amount', shareAmount.toFixed(2));
    });

    if (!totals.length) {
      target.innerHTML = '<div class="split-total-card split-total-empty"><span>No entries yet</span><strong>Rs. 0.00</strong></div>';
      return;
    }
    target.innerHTML = totals.map((item) => {
      const a = Number(item.amount || 0);
      const diff = a - shareAmount;
      let statusHtml = '';
      if (diff > 0) {
        statusHtml = `<div class="small text-success mt-2 fw-semibold">Receives: Rs. ${formatNumber(diff)}</div>`;
      } else if (diff < 0) {
        statusHtml = `<div class="small text-danger mt-2 fw-semibold">Gives: Rs. ${formatNumber(Math.abs(diff))}</div>`;
      } else {
        statusHtml = `<div class="small text-muted mt-2 fw-semibold">Settled</div>`;
      }
      return `
        <div class="split-total-card">
          <span>${escapeHtml(item.person || 'Unknown')}</span>
          <strong>Rs. ${formatNumber(a)}</strong>
          ${statusHtml}
        </div>
      `;
    }).join('');
  }

  function renderEntries(entries, readOnly) {
    const body = document.getElementById('splitEntryBody');
    if (!body) return;
    const rows = Array.isArray(entries) ? entries : [];
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No split entries found.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((entry) => `
      <tr>
        <td data-label="When"><small>${formatDate(entry.timestamp || '')}</small></td>
        <td data-label="Person"><small>${escapeHtml(entry.person || '')}</small></td>
        <td data-label="For"><small>${escapeHtml(entry.description || '')}</small></td>
        <td data-label="Category"><small>${escapeHtml(entry.category || 'Uncategorized')}</small></td>
        <td data-label="Amount" class="text-end"><small>${formatNumber(entry.amount)}</small></td>
        <td data-label="Actions" class="text-end">
          <span class="badge badge-secondary">View Only</span>
        </td>
      </tr>
    `).join('');

    const parentTable = body.closest('table');
    if (parentTable && window.FinTrak && typeof window.FinTrak.initUnifiedTable === 'function') {
      window.FinTrak.initUnifiedTable(parentTable);
    }
  }

  async function refreshSplit() {
    const header = document.querySelector('.split-detail-header[data-split-id]');
    if (!header) return;
    const splitId = header.dataset.splitId;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), refreshTimeoutMs);

    try {
      const response = await fetch(`/api/splits/${encodeURIComponent(splitId)}/summary`, {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error || `Split refresh failed (${response.status})`);
      }
      renderTotalsData(data.split);
      if (document.body.dataset.viewOnly === 'true') {
        renderEntries(data.split?.entries || [], true);
      }
    } catch (error) {
      showNotice('Failed to fetch split data from the server.', 'danger');
    } finally {
      clearTimeout(timeout);
    }
  }

  document.addEventListener('DOMContentLoaded', refreshSplit);
}());
