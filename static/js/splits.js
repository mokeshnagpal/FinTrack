(function () {
  const limit = Number(window.FinTrakConstants?.split_entry_table_limit || 12);
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

  function initRecordShareButtons() {
    const recordButtons = document.querySelectorAll('.record-share-btn');
    if (!recordButtons.length) return;

    const confirmModalEl = document.getElementById('recordShareConfirmModal');
    const confirmModal = confirmModalEl && typeof bootstrap !== 'undefined' ? new bootstrap.Modal(confirmModalEl) : null;
    const confirmForm = document.getElementById('recordShareConfirmForm');
    const directForm = document.getElementById('recordShareDirectForm');
    const confirmSplitTitle = document.getElementById('confirmSplitTitle');
    const confirmOldAmount = document.getElementById('confirmOldAmount');
    const confirmNewAmount = document.getElementById('confirmNewAmount');

    recordButtons.forEach((btn) => {
      btn.addEventListener('click', (event) => {
        event.preventDefault();
        const splitId = btn.getAttribute('data-split-id');
        const txnId = btn.getAttribute('data-txn-id');
        const recordedAmount = btn.getAttribute('data-recorded-amount') || '0.00';
        const shareAmount = Number(btn.getAttribute('data-share-amount') || 0);
        const splitTitle = btn.getAttribute('data-split-title') || 'Untitled split';

        if (!splitId) {
          showNotice('Split is missing. Refresh the page and try again.', 'warning');
          return;
        }

        if (!Number.isFinite(shareAmount) || shareAmount <= 0) {
          showNotice('Split total is zero. Add entries before adding this to transactions.', 'warning');
          return;
        }

        const recordUrl = `/splits/${encodeURIComponent(splitId)}/record_txn`;
        if (txnId) {
          if (confirmSplitTitle) confirmSplitTitle.textContent = splitTitle;
          if (confirmOldAmount) confirmOldAmount.textContent = `Rs. ${recordedAmount}`;
          if (confirmNewAmount) confirmNewAmount.textContent = `Rs. ${formatNumber(shareAmount)}`;
          if (confirmForm) confirmForm.setAttribute('action', recordUrl);
          if (confirmModal) confirmModal.show();
          return;
        }

        if (directForm) {
          directForm.setAttribute('action', recordUrl);
          directForm.submit();
        }
      });
    });
  }

  function renderTotals(split) {
    const target = document.getElementById('splitTotals');
    if (!target) return;
    const rows = Array.isArray(split?.settlements) ? split.settlements : [];
    if (!rows.length) {
      target.innerHTML = '<div class="split-total-card split-total-empty"><span>No entries yet</span><strong>Rs. 0.00</strong></div>';
      return;
    }
    const shareAmount = Number(split?.share_amount || 0);
    const totalSpent = Number(split?.total_spent || 0);
    const numPeople = Number(split?.num_people || rows.length || 0);
    const shareCard = numPeople > 0 ? `
      <div class="split-total-card split-share-card">
        <span>Each share</span>
        <strong>Rs. ${formatNumber(shareAmount)}</strong>
        <small>Total Rs. ${formatNumber(totalSpent)} / ${numPeople} people</small>
      </div>
    ` : '';
    target.innerHTML = shareCard + rows.map((item) => {
      const status = item.status || 'settled';
      const balanceAbs = Math.abs(Number(item.balance_abs ?? item.balance ?? 0));
      const settlementClass = status === 'receive'
        ? 'split-settlement-receive'
        : (status === 'give' ? 'split-settlement-give' : 'split-settlement-even');
      const settlementText = status === 'receive'
        ? `Receive Rs. ${formatNumber(balanceAbs)}`
        : (status === 'give' ? `Give Rs. ${formatNumber(balanceAbs)}` : 'Settled');
      return `
      <div class="split-total-card">
        <span>${escapeHtml(item.person || 'Unknown')}</span>
        <strong>Rs. ${formatNumber(item.amount)}</strong>
        <small>Spent - share: Rs. ${formatNumber(item.amount)} - Rs. ${formatNumber(item.share_amount)}</small>
        <em class="split-settlement ${settlementClass}">${settlementText}</em>
      </div>
    `;
    }).join('');
  }

  function renderEntries(entries, readOnly) {
    const body = document.getElementById('splitEntryBody');
    if (!body) return;
    const rows = Array.isArray(entries) ? entries.slice(0, limit) : [];
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
          <span class="badge">${readOnly ? 'Read only' : 'Reload'}</span>
        </td>
      </tr>
    `).join('');
  }

  function updateRecordShareButtons(split) {
    document.querySelectorAll('.record-share-btn').forEach((btn) => {
      btn.setAttribute('data-share-amount', Number(split?.share_amount || 0).toFixed(2));
    });
  }

  async function refreshSplit() {
    const header = document.querySelector('.split-detail-header[data-split-id]');
    if (!header) return;
    const splitId = header.dataset.splitId;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), refreshTimeoutMs);

    try {
      const response = await fetch(`/api/splits/${encodeURIComponent(splitId)}/summary`, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error || `Split refresh failed (${response.status})`);
      }
      renderTotals(data.split || {});
      updateRecordShareButtons(data.split || {});
      if (document.body.dataset.viewOnly === 'true') {
        renderEntries(data.split?.entries || [], true);
      }
    } catch (error) {
      showNotice('Could not refresh split details. Try again after the service responds.', 'warning');
    } finally {
      clearTimeout(timeout);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initRecordShareButtons();
    refreshSplit();
  });
}());
