const HISTORY_DISPLAY_LIMIT = Number(window.FinTrakConstants?.balance_history_table_limit || 12);

async function fetchJSON(url, params = {}, opts = {}) {
  const query = new URLSearchParams(params).toString();
  const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  const headers = { ...(opts.headers || {}) };

  if (opts.method && opts.method.toUpperCase() !== 'GET' && token) {
    headers['X-CSRFToken'] = token;
  }

  const response = await fetch(url + (query ? `?${query}` : ''), { ...opts, headers });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function formatNumber(value) {
  return Number(value || 0).toFixed(2);
}

function rupee(value) {
  return `Rs. ${formatNumber(value)}`;
}

function formatDisplayDate(value) {
  if (window.FinTrak?.formatFriendlyDateHtml) {
    return window.FinTrak.formatFriendlyDateHtml(value);
  }
  return escapeHtml(value || '');
}

function formatDisplayNote(note) {
  return window.FinTrak && window.FinTrak.formatBalanceNote
    ? window.FinTrak.formatBalanceNote(note)
    : note;
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el && window.FinTrak?.hideModal) {
    window.FinTrak.hideModal(el);
  }
}

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

function escapeAttr(value) {
  return escapeHtml(value).replace(/"/g, '&quot;');
}

function isEmptyInput(el) {
  return !el || String(el.value || '').trim() === '';
}

function noteError(value) {
  return String(value || '').trim().length > 120 ? 'Use 120 characters or fewer for the note.' : '';
}

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
        <strong>${escapeHtml(title)}</strong>${message ? `<div class="small mt-1">${escapeHtml(message)}</div>` : ''}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto"
        data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;

  container.appendChild(toast);
  if (typeof bootstrap !== 'undefined') {
    const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
  } else {
    setTimeout(() => toast.remove(), 4000);
  }
}

async function refreshAll(currentBalanceEl, balanceTimestampEl, historyBody) {
  let data;
  let offline = false;
  try {
    data = await fetchJSON('/api/balance_current');
    if (window.FinTrak?.cache?.refreshSnapshot) {
      window.FinTrak.cache.refreshSnapshot().catch(() => {});
    }
  } catch (error) {
    const snapshot = window.FinTrak?.cache?.readSnapshot?.();
    if (!snapshot?.balance) throw error;
    data = snapshot.balance;
    offline = true;
  }
  const current = data.current || { balance: 0.0, timestamp: null };

  if (currentBalanceEl) currentBalanceEl.innerText = formatNumber(current.balance);
  if (balanceTimestampEl) {
    const label = current.timestamp ? `Updated: ${formatDisplayDate(current.timestamp)}` : 'No entries yet';
    balanceTimestampEl.innerHTML = offline ? `${label} (cached)` : label;
  }

  if (!historyBody) return;
  historyBody.innerHTML = '';

  (data.history || []).forEach((entry, index) => {
    const tr = document.createElement('tr');
    const type = String(entry.type || '').toLowerCase();
    const isLatest = index === 0;
    const canEdit = isLatest && ['add', 'sync'].includes(type) && document.body.dataset.viewOnly !== 'true';
    const editButton = canEdit
      ? `<button class="btn btn-sm btn-outline-primary balance-edit-btn"
            data-id="${escapeAttr(entry.id || '')}"
            data-type="${escapeAttr(type)}"
            data-delta="${escapeAttr(entry.delta)}"
            data-balance="${escapeAttr(entry.balance)}"
            data-note="${escapeAttr(entry.note || '')}">
            Edit
          </button>`
      : `<button class="btn btn-sm btn-outline-secondary" disabled
            title="${isLatest ? 'Edit the source transaction for transaction-linked entries.' : 'Only the latest manual balance entry can be edited.'}">
            Locked
          </button>`;

    tr.innerHTML = `<td data-label="When">${formatDisplayDate(entry.timestamp || '')}</td>
                    <td data-label="Type">${escapeHtml(entry.type || '')}</td>
                    <td data-label="Delta" class="text-end">${formatNumber(entry.delta)}</td>
                    <td data-label="Balance" class="text-end">${formatNumber(entry.balance)}</td>
                    <td data-label="Note">${escapeHtml(formatDisplayNote(entry.note || ''))}</td>
                    <td data-label="Actions" class="text-end"><div class="table-actions">${editButton}</div></td>`;
    historyBody.appendChild(tr);
  });

  const parentTable = historyBody.closest('table');
  if (parentTable && window.FinTrak && typeof window.FinTrak.initUnifiedTable === 'function') {
    window.FinTrak.initUnifiedTable(parentTable);
  }
}

function ensureEditModal() {
  let modal = document.getElementById('balanceEditModal');
  if (modal) return modal;

  modal = document.createElement('div');
  modal.id = 'balanceEditModal';
  modal.className = 'confirm-modal balance-edit-modal';
  modal.innerHTML = `
    <div class="confirm-content balance-edit-content">
      <h5 class="fw-bold mb-3">Edit Balance Entry</h5>
      <input type="hidden" id="editBalanceId">
      <input type="hidden" id="editBalanceType">
      <input type="hidden" id="editBalanceOriginalDelta">
      <input type="hidden" id="editBalanceOriginalBalance">
      <div class="mb-3">
        <label class="form-label" id="editBalanceValueLabel" for="editBalanceValue">Amount</label>
        <input id="editBalanceValue" class="form-control" type="number" step="0.01">
        <small class="text-muted d-block mt-2" id="editBalanceModeHelp"></small>
      </div>
      <div class="balance-edit-impact mb-3" id="editBalanceImpact" aria-live="polite"></div>
      <div class="mb-3">
        <label class="form-label" for="editBalanceNote">Note</label>
        <input id="editBalanceNote" class="form-control" maxlength="120">
      </div>
      <div class="d-flex gap-2 justify-content-end">
        <button type="button" class="btn btn-outline-secondary" data-balance-edit-cancel>Cancel</button>
        <button type="button" class="btn btn-primary" data-balance-edit-save>Save</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  modal.addEventListener('click', (event) => {
    if (event.target === modal || event.target.closest('[data-balance-edit-cancel]')) {
      modal.classList.remove('show');
    }
  });
  modal.querySelector('#editBalanceValue').addEventListener('input', () => updateEditImpact(modal));

  return modal;
}

function readMoneyValue(value) {
  const parsed = parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function updateEditImpact(modal) {
  const type = modal.querySelector('#editBalanceType').value;
  const rawValue = modal.querySelector('#editBalanceValue').value;
  const value = parseFloat(rawValue);
  const originalDelta = readMoneyValue(modal.querySelector('#editBalanceOriginalDelta').value);
  const originalBalance = readMoneyValue(modal.querySelector('#editBalanceOriginalBalance').value);
  const impactEl = modal.querySelector('#editBalanceImpact');

  if (!impactEl) return;
  if (rawValue === '' || Number.isNaN(value) || !Number.isFinite(value)) {
    impactEl.innerHTML = '<span class="text-muted">Enter a value to preview the balance impact.</span>';
    return;
  }

  if (type === 'sync') {
    const shiftAmount = value - originalBalance;
    const resultingDelta = originalDelta + shiftAmount;
    impactEl.innerHTML = `
      <span>New absolute balance: <strong>Rs. ${formatNumber(value)}</strong></span>
      <span>Entry change becomes: <strong>Rs. ${formatNumber(resultingDelta)}</strong></span>
      <span>Later balances shift by: <strong>Rs. ${formatNumber(shiftAmount)}</strong></span>
    `;
    return;
  }

  const shiftAmount = value - originalDelta;
  const resultingBalance = originalBalance + shiftAmount;
  impactEl.innerHTML = `
    <span>Entry change becomes: <strong>Rs. ${formatNumber(value)}</strong></span>
    <span>Entry balance becomes: <strong>Rs. ${formatNumber(resultingBalance)}</strong></span>
    <span>Later balances shift by: <strong>Rs. ${formatNumber(shiftAmount)}</strong></span>
  `;
}

function openEditModal(button) {
  const modal = ensureEditModal();
  const type = button.dataset.type;
  modal.querySelector('#editBalanceId').value = button.dataset.id || '';
  modal.querySelector('#editBalanceType').value = type || '';
  modal.querySelector('#editBalanceOriginalDelta').value = button.dataset.delta || '0';
  modal.querySelector('#editBalanceOriginalBalance').value = button.dataset.balance || '0';
  modal.querySelector('#editBalanceValueLabel').textContent = type === 'sync' ? 'New Absolute Balance' : 'New Change Amount';
  modal.querySelector('#editBalanceModeHelp').textContent = type === 'sync'
    ? 'Sync entries are edited as an absolute balance. The change amount is calculated from the previous balance.'
    : 'Add entries are edited as a change amount. Later balances move by the difference.';
  modal.querySelector('#editBalanceValue').value = type === 'sync' ? button.dataset.balance || '' : button.dataset.delta || '';
  modal.querySelector('#editBalanceNote').value = button.dataset.note || '';
  updateEditImpact(modal);
  modal.classList.add('show');
}

async function saveEditModal(currentBalanceEl, balanceTimestampEl, historyBody) {
  const modal = ensureEditModal();
  const id = modal.querySelector('#editBalanceId').value;
  const type = modal.querySelector('#editBalanceType').value;
  const value = parseFloat(modal.querySelector('#editBalanceValue').value);
  const note = modal.querySelector('#editBalanceNote').value || '';

  if (!id || Number.isNaN(value) || !Number.isFinite(value) || Math.abs(value) > 999999999) {
    showToast('Enter a valid value.', 'warning');
    return;
  }
  const editNoteError = noteError(note);
  if (editNoteError) {
    showToast(editNoteError, 'warning');
    return;
  }

  const payload = type === 'sync' ? { balance: value, note } : { delta: value, note };
  try {
    await fetchJSON(`/api/balance/${encodeURIComponent(id)}/update`, {}, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    modal.classList.remove('show');
    showToast('Balance entry updated', 'success');
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
  } catch (error) {
    console.error('balance edit failed', error);
    showToast('Edit failed', 'danger', error.message);
  }
}

async function refreshPage(currentBalanceEl, balanceTimestampEl, historyBody) {
  await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody);
}

document.addEventListener('DOMContentLoaded', async () => {
  const currentBalanceEl = document.getElementById('currentBalance');
  const balanceTimestampEl = document.getElementById('balanceTimestamp');
  const refreshBtn = document.getElementById('refreshBtn');
  const addAmount = document.getElementById('addAmount');
  const addNote = document.getElementById('addNote');
  const addBtn = document.getElementById('addBtn');
  const syncAmount = document.getElementById('syncAmount');
  const syncNote = document.getElementById('syncNote');
  const syncBtn = document.getElementById('syncBtn');
  const historyBody = document.getElementById('historyBody');

  if (addBtn && addAmount) {
    addBtn.addEventListener('click', async () => {
      if (isEmptyInput(addAmount)) {
        showToast('Enter an amount to add.', 'warning');
        return;
      }

      const amount = parseFloat(addAmount.value);
      if (Number.isNaN(amount) || !Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 999999999) {
        showToast('Enter a valid amount to add.', 'warning');
        return;
      }
      const addNoteError = noteError(addNote ? addNote.value : '');
      if (addNoteError) {
        showToast(addNoteError, 'warning');
        return;
      }

      try {
        const result = await fetchJSON('/api/balance/add', {}, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount, note: addNote ? addNote.value || '' : '' }),
        });
        showToast(`Added ${rupee(amount)}`, 'success', `New balance ${rupee(result.balance)}`);
        addAmount.value = '';
        if (addNote) addNote.value = '';
        closeModal('addBalanceModal');
        await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
      } catch (error) {
        console.error('add failed', error);
        if (window.FinTrak?.enqueueOfflineAction) {
          window.FinTrak.enqueueOfflineAction('balance_add', { amount, note: addNote ? addNote.value || '' : '' });
          showToast('Add saved locally', 'success', 'It will sync when the service wakes.');
          addAmount.value = '';
          if (addNote) addNote.value = '';
          closeModal('addBalanceModal');
        } else {
          showToast('Add failed', 'danger', error.message);
        }
      }
    });
  }

  if (syncBtn && syncAmount) {
    syncBtn.addEventListener('click', async () => {
      if (isEmptyInput(syncAmount)) {
        showToast('Enter a balance to sync.', 'warning');
        return;
      }

      const balance = parseFloat(syncAmount.value);
      if (Number.isNaN(balance) || !Number.isFinite(balance) || Math.abs(balance) > 999999999) {
        showToast('Enter a valid balance value to sync.', 'warning');
        return;
      }
      const syncNoteError = noteError(syncNote ? syncNote.value : '');
      if (syncNoteError) {
        showToast(syncNoteError, 'warning');
        return;
      }

      try {
        const result = await fetchJSON('/api/balance/sync', {}, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ balance, note: syncNote ? syncNote.value || '' : '' }),
        });
        showToast(`Balance synced to ${rupee(result.balance)}`, 'success', `Delta ${formatNumber(result.delta)}`);
        syncAmount.value = '';
        if (syncNote) syncNote.value = '';
        closeModal('syncBalanceModal');
        await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
      } catch (error) {
        console.error('sync failed', error);
        if (window.FinTrak?.enqueueOfflineAction) {
          window.FinTrak.enqueueOfflineAction('balance_sync', { balance, note: syncNote ? syncNote.value || '' : '' });
          showToast('Sync saved locally', 'success', 'It will sync when the service wakes.');
          syncAmount.value = '';
          if (syncNote) syncNote.value = '';
          closeModal('syncBalanceModal');
        } else {
          showToast('Sync failed', 'danger', error.message);
        }
      }
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => (
      refreshPage(currentBalanceEl, balanceTimestampEl, historyBody)
        .catch((error) => showToast('Refresh failed', 'danger', error.message))
    ));
  }

  if (historyBody) {
    historyBody.addEventListener('click', (event) => {
      const button = event.target.closest('.balance-edit-btn');
      if (!button) return;
      openEditModal(button);
    });
  }

  document.addEventListener('click', (event) => {
    if (!event.target.closest('[data-balance-edit-save]')) return;
    saveEditModal(currentBalanceEl, balanceTimestampEl, historyBody);
  });

  try {
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
  } catch (error) {
    console.error('Balance script initialization error', error);
    showToast('Balance script error', 'danger', error.message);
  }
});
