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
  return window.FinTrak.formatNumber(value);
}

function rupee(value) {
  return window.FinTrak.rupee(value);
}

function formatDisplayDate(value) {
  if (window.FinTrak?.formatFriendlyDateHtml) {
    return window.FinTrak.formatFriendlyDateHtml(value);
  }
  return window.FinTrak.escapeHtml(value || '');
}

function formatDisplayNote(note) {
  return window.FinTrak && window.FinTrak.formatBalanceNote
    ? window.FinTrak.formatBalanceNote(note)
    : note;
}

function normalizeBalanceMode(entry) {
  const mode = String(entry?.balance_mode || '').toLowerCase();
  if (mode === 'sync' || mode === 'add') return mode;
  return String(entry?.type || '').toLowerCase() === 'sync' ? 'sync' : 'add';
}

function modeLabel(mode) {
  return mode === 'sync' ? 'Sync' : 'Add';
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el && window.FinTrak?.hideModal) {
    window.FinTrak.hideModal(el);
  }
}

function escapeHtml(unsafe) {
  return window.FinTrak.escapeHtml(unsafe);
}

function escapeAttr(value) {
  return window.FinTrak.escapeHtml(value).replace(/"/g, '&quot;');
}

function isEmptyInput(el) {
  return !el || String(el.value || '').trim() === '';
}

function noteError(value) {
  return String(value || '').trim().length > 120 ? 'Use 120 characters or fewer for the note.' : '';
}

// Transaction modal functions
function setupTransactionModal(currentBalanceEl, balanceTimestampEl, historyBody) {
  const editBtn = document.getElementById('editTransactionBtn');
  const deleteBtn = document.getElementById('deleteTransactionBtn');
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  let currentTxnId = null;

  if (editBtn) {
    editBtn.addEventListener('click', () => {
      if (currentTxnId) {
        window.location.href = `/edit/${encodeURIComponent(currentTxnId)}`;
      }
    });
  }

  if (deleteBtn) {
    deleteBtn.addEventListener('click', () => {
      const confirmModal = document.getElementById('deleteTransactionConfirmModal');
      if (confirmModal && window.bootstrap?.Modal) {
        new window.bootstrap.Modal(confirmModal).show();
      }
    });
  }

  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', async () => {
      if (!currentTxnId) return;
      try {
        const result = await fetchJSON(`/api/transactions/${encodeURIComponent(currentTxnId)}/delete`, {}, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        if (result.ok) {
          closeModal('viewTransactionModal');
          closeModal('deleteTransactionConfirmModal');
          showToast('Transaction deleted.', 'success');
          if (historyBody && balanceTimestampEl && currentBalanceEl) {
            await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, Boolean(document.getElementById('showTxnsCheckbox')?.checked));
          }
        } else {
          showToast(result.error || 'Failed to delete transaction.', 'danger');
        }
      } catch (error) {
        console.error('Delete failed', error);
        showToast('Delete failed: ' + error.message, 'danger');
      }
    });
  }

  window.openTransactionModal = async function(txnId) {
    currentTxnId = txnId;
    const modal = document.getElementById('viewTransactionModal');
    if (!modal) {
      console.error('Transaction modal not found');
      return;
    }

    try {
      const result = await fetchJSON(`/api/transactions/${encodeURIComponent(txnId)}/view`);
      if (!result.ok || !result.transaction) {
        showToast(result.error || 'Failed to load transaction.', 'danger');
        return;
      }

      const txn = result.transaction;
      document.getElementById('txnDescription').textContent = escapeHtml(txn.description || '-');
      document.getElementById('txnAmount').textContent = rupee(txn.amount);
      document.getElementById('txnCategory').textContent = escapeHtml(txn.category || '-');
      document.getElementById('txnDate').textContent = txn.date || '-';
      document.getElementById('txnTime').textContent = txn.time || '-';

      if (window.bootstrap?.Modal) {
        new window.bootstrap.Modal(modal).show();
      } else {
        modal.classList.add('show');
        modal.style.display = 'block';
      }
    } catch (error) {
      console.error('Failed to load transaction', error);
      showToast('Failed to load transaction: ' + error.message, 'danger');
    }
  };
}


async function refreshAll(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions = false) {
  let data;
  try {
    data = await fetchJSON('/api/balance_current', { show_txns: showTransactions ? 'true' : 'false' });
  } catch (error) {
    console.error('Failed to fetch balance history', error);
    throw error;
  }
  const current = data.current || { balance: 0.0, timestamp: null };

  if (currentBalanceEl) currentBalanceEl.innerText = formatNumber(current.balance);
  if (balanceTimestampEl) {
    const label = current.timestamp ? `Updated: ${formatDisplayDate(current.timestamp)}` : 'No entries yet';
    balanceTimestampEl.innerHTML = label;
  }

  if (!historyBody) return;

  // Filter visible history (respect the showTransactions toggle)
  const visibleHistory = (data.history || []).filter((entry) => {
    const type = String(entry.type || '').toLowerCase();
    return showTransactions || type === 'add' || type === 'sync';
  });

  // Render all visible rows into the tbody; pagination/sorting handled by initUnifiedTable
  console.debug('balance.refreshAll: rendering', visibleHistory.length, 'rows, showTransactions=', showTransactions);
  historyBody.innerHTML = '';
  visibleHistory.forEach((entry) => {
    const tr = document.createElement('tr');
    const type = String(entry.type || '').toLowerCase();
    const mode = normalizeBalanceMode(entry);
    const viewOnly = document.body.dataset.viewOnly === 'true';
    const isManual = type === 'add' || type === 'sync';
    const hasActions = !viewOnly && isManual;
    const noteText = entry.note_display || entry.note || '';
    const transactionSearch = entry.transaction_search_text || entry.transaction_id || noteText;

    const actionButtons = hasActions
      ? `<button class="btn btn-sm btn-outline-primary balance-edit-btn me-1"
            data-id="${escapeAttr(entry.id || '')}"
            data-type="${escapeAttr(type)}"
            data-mode="${escapeAttr(mode)}"
            data-delta="${escapeAttr(entry.delta)}"
            data-balance="${escapeAttr(entry.balance)}"
            data-note="${escapeAttr(entry.note || '')}">
            Edit
         </button>
         <button class="btn btn-sm btn-outline-danger balance-delete-btn"
            data-id="${escapeAttr(entry.id || '')}"
            data-type="${escapeAttr(type)}"
            data-mode="${escapeAttr(mode)}"
            data-delta="${escapeAttr(entry.delta)}"
            data-balance="${escapeAttr(entry.balance)}"
            data-note="${escapeAttr(entry.note || '')}">
            Delete
         </button>`
      : (entry.transaction_id
          ? `<button class="btn btn-sm btn-outline-secondary balance-view-transaction-btn" data-txn-id="${escapeAttr(entry.transaction_id || '')}">View Txn</button>`
          : `<span class="text-muted small">${viewOnly ? 'View-only' : '-'}</span>`);

    tr.innerHTML = `<td data-label="When">${formatDisplayDate(entry.timestamp || '')}</td>
                    <td data-label="Source">${escapeHtml(entry.type || '')}</td>
                    <td data-label="Mode"><span class="badge badge-compact ${mode === 'sync' ? 'badge-sync' : 'badge-add'}">${modeLabel(mode)}</span></td>
                    <td data-label="Delta" class="text-end">${formatNumber(entry.delta)}</td>
                    <td data-label="Balance" class="text-end">${formatNumber(entry.balance)}</td>
                    <td data-label="Note">${escapeHtml(formatDisplayNote(noteText))}</td>
                    <td data-label="Actions" class="text-end"><div class="table-actions">${actionButtons}</div></td>`;
    historyBody.appendChild(tr);
  });

  const parentTable = historyBody.closest('table');
  if (parentTable && window.FinTrak && typeof window.FinTrak.initUnifiedTable === 'function') {
    console.debug('balance.refreshAll: parentTable.dataset.unifiedInitialized=', parentTable.dataset.unifiedInitialized);
    // If the unified table has already been initialized earlier, use its
    // refreshPagination method to avoid re-initializing and losing state.
    if (parentTable.dataset.unifiedInitialized === 'true' && typeof parentTable.refreshPagination === 'function') {
      console.debug('balance.refreshAll: calling parentTable.refreshPagination()');
      parentTable.refreshPagination();
    } else {
      console.debug('balance.refreshAll: calling initUnifiedTable()');
      window.FinTrak.initUnifiedTable(parentTable);
    }
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
      <input type="hidden" id="editBalanceSourceType">
      <input type="hidden" id="editBalanceOriginalDelta">
      <input type="hidden" id="editBalanceOriginalBalance">
      <div class="mb-3">
        <label class="form-label" for="editBalanceMode">Mode</label>
        <select id="editBalanceMode" class="form-select">
          <option value="add">Add / Change Amount</option>
          <option value="sync">Sync / Absolute Balance</option>
        </select>
        <small class="text-muted d-block mt-2">Changing this controls whether the value below is treated as a delta or an absolute balance.</small>
      </div>
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
  modal.querySelector('#editBalanceMode').addEventListener('change', () => {
    syncEditModeFields(modal, true);
    updateEditImpact(modal);
  });

  return modal;
}

function readMoneyValue(value) {
  const parsed = parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function updateEditImpact(modal) {
  const mode = modal.querySelector('#editBalanceMode').value;
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

  if (mode === 'sync') {
    const shiftAmount = value - originalBalance;
    const resultingDelta = originalDelta + shiftAmount;
    impactEl.innerHTML = `
      <span>New absolute balance: <strong>Rs. ${formatNumber(value)}</strong></span>
      <span>Entry change becomes: <strong>Rs. ${formatNumber(resultingDelta)}</strong></span>
      <span>Following rows are recalculated from this balance.</span>
    `;
    return;
  }

  const shiftAmount = value - originalDelta;
  const resultingBalance = originalBalance + shiftAmount;
  impactEl.innerHTML = `
    <span>Entry change becomes: <strong>Rs. ${formatNumber(value)}</strong></span>
    <span>Entry balance becomes: <strong>Rs. ${formatNumber(resultingBalance)}</strong></span>
    <span>Immediate shift before the next sync: <strong>Rs. ${formatNumber(shiftAmount)}</strong></span>
  `;
}

function syncEditModeFields(modal, resetValue = false) {
  const mode = modal.querySelector('#editBalanceMode').value;
  const valueInput = modal.querySelector('#editBalanceValue');
  modal.querySelector('#editBalanceValueLabel').textContent = mode === 'sync' ? 'Absolute Balance' : 'Change Amount';
  modal.querySelector('#editBalanceModeHelp').textContent = mode === 'sync'
    ? 'Sync mode saves this row as an absolute balance. Its change amount is calculated from the previous row.'
    : 'Add mode saves this row as a change amount. Following rows are recalculated; later sync rows stay absolute.';
  if (resetValue) {
    valueInput.value = mode === 'sync'
      ? modal.querySelector('#editBalanceOriginalBalance').value || ''
      : modal.querySelector('#editBalanceOriginalDelta').value || '';
  }
}

function openEditModal(button) {
  const modal = ensureEditModal();
  const type = button.dataset.type;
  const mode = button.dataset.mode || (type === 'sync' ? 'sync' : 'add');
  modal.querySelector('#editBalanceId').value = button.dataset.id || '';
  modal.querySelector('#editBalanceSourceType').value = type || '';
  modal.querySelector('#editBalanceMode').value = mode;
  modal.querySelector('#editBalanceOriginalDelta').value = button.dataset.delta || '0';
  modal.querySelector('#editBalanceOriginalBalance').value = button.dataset.balance || '0';
  syncEditModeFields(modal, false);
  modal.querySelector('#editBalanceValue').value = mode === 'sync' ? button.dataset.balance || '' : button.dataset.delta || '';
  modal.querySelector('#editBalanceNote').value = button.dataset.note || '';
  updateEditImpact(modal);
  modal.classList.add('show');
}

async function saveEditModal(currentBalanceEl, balanceTimestampEl, historyBody) {
  const modal = ensureEditModal();
  const id = modal.querySelector('#editBalanceId').value;
  const mode = modal.querySelector('#editBalanceMode').value;
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

  const payload = mode === 'sync' ? { mode, balance: value, note } : { mode, delta: value, note };
  try {
    await fetchJSON(`/api/balance/${encodeURIComponent(id)}/update`, {}, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    modal.classList.remove('show');
    showToast('Balance entry updated', 'success');
    const showTransactions = Boolean(document.getElementById('showTxnsCheckbox')?.checked);
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions);
  } catch (error) {
    console.error('balance edit failed', error);
    showToast('Edit failed', 'danger', error.message);
  }
}

async function refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions = false) {
  await refreshAll(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions);
}

async function deleteBalanceEntry(button, currentBalanceEl, balanceTimestampEl, historyBody) {
  const id = button.dataset.id;
  const note = button.dataset.note || 'No note';
  const type = button.dataset.type || '';
  const mode = button.dataset.mode || (type === 'sync' ? 'sync' : 'add');
  const delta = readMoneyValue(button.dataset.delta);
  
  const confirmed = await window.FinTrak?.confirm?.(`Delete this balance entry (${type}/${mode}: ${note})? Its change of Rs. ${formatNumber(delta)} will be removed and following rows recalculated.`, 'Delete');
  if (!confirmed) return;

  try {
    await fetchJSON(`/api/balance/${encodeURIComponent(id)}/delete`, {}, {
      method: 'POST'
    });
    showToast('Balance entry deleted', 'success');
    const showTransactions = Boolean(document.getElementById('showTxnsCheckbox')?.checked);
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions);
  } catch (error) {
    console.error('Balance entry deletion failed', error);
    showToast('Deletion failed', 'danger', error.message);
  }
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
  const showTxnsCheckbox = document.getElementById('showTxnsCheckbox');
  const showTransactions = () => Boolean(showTxnsCheckbox?.checked);

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
        await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions());
      } catch (error) {
        console.error('add failed', error);
        showToast('Add failed', 'danger', error.message);
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
        await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions());
      } catch (error) {
        console.error('sync failed', error);
        showToast('Sync failed', 'danger', error.message);
      }
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => (
      refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions())
        .catch((error) => showToast('Refresh failed', 'danger', error.message))
    ));
  }

  if (showTxnsCheckbox) {
    showTxnsCheckbox.addEventListener('change', () => {
      refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions())
        .catch((error) => showToast('Refresh failed', 'danger', error.message));
    });
  }


  if (historyBody) {
    historyBody.addEventListener('click', async (event) => {
      const editBtn = event.target.closest('.balance-edit-btn');
      if (editBtn) {
        openEditModal(editBtn);
        return;
      }

      const deleteBtn = event.target.closest('.balance-delete-btn');
      if (deleteBtn) {
        await deleteBalanceEntry(deleteBtn, currentBalanceEl, balanceTimestampEl, historyBody);
        return;
      }

      const viewTxnBtn = event.target.closest('.balance-view-transaction-btn');
      if (viewTxnBtn) {
        const txnId = viewTxnBtn.dataset.txnId;
        if (txnId) {
          await openTransactionModal(txnId);
        }
        return;
      }
    });
  }

  document.addEventListener('click', (event) => {
    if (!event.target.closest('[data-balance-edit-save]')) return;
    saveEditModal(currentBalanceEl, balanceTimestampEl, historyBody);
  });

  // Transaction modal setup
  setupTransactionModal(currentBalanceEl, balanceTimestampEl, historyBody);

  try {
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody, showTransactions());
  } catch (error) {
    console.error('Balance script initialization error', error);
    showToast('Balance script error', 'danger', error.message);
  }
});
