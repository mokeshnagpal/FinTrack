const HISTORY_DISPLAY_LIMIT = Number(window.FinTrakConstants?.balance_history_table_limit || 12);

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

function closeModal(id) {
  const el = document.getElementById(id);
  if (el && window.FinTrak?.hideModal) {
    window.FinTrak.hideModal(el);
  }
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

function buildTransactionSearchQuery(entry) {
  const description = String(entry.description || '').trim();
  const category = String(entry.category || '').trim();
  if (description) return description;
  if (category && category !== 'Uncategorized') return category;
  if (entry.id) return String(entry.id);
  return '';
}

function openTransactionsForEntry(entry) {
  const q = buildTransactionSearchQuery(entry);
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  const query = params.toString();
  window.location.href = query ? `/transactions?${query}` : '/transactions';
}



async function refreshAll(currentBalanceEl, balanceTimestampEl, historyBody) {
  const data = await window.FinTrak.fetchJSON('/api/balance_current');
  const current = data.current || { balance: 0.0, timestamp: null };

  if (currentBalanceEl) currentBalanceEl.innerText = formatNumber(current.balance);
  if (balanceTimestampEl) {
    const label = current.timestamp ? `Updated: ${formatDisplayDate(current.timestamp)}` : 'No entries yet';
    balanceTimestampEl.innerHTML = label;
  }

  if (!historyBody) return;
  historyBody.innerHTML = '';

  const hideTransactionsCheckbox = document.getElementById('hideTransactions');
  const hideTxns = hideTransactionsCheckbox ? hideTransactionsCheckbox.checked : false;
  if (hideTransactionsCheckbox && !hideTransactionsCheckbox.dataset.listenerBound) {
    hideTransactionsCheckbox.dataset.listenerBound = 'true';
    hideTransactionsCheckbox.addEventListener('change', () => {
      refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
    });
  }
  const history = (data.history || []).filter(entry => {
    if (hideTxns && entry.source === 'transaction') {
      return false;
    }
    return true;
  });
  const viewOnly = document.body.dataset.viewOnly === 'true';

  history.forEach((entry) => {
    const tr = document.createElement('tr');
    const source = entry.source || '';
    const isTransaction = source === 'transaction';
    const isBalance = source === 'balance';
    
    // Determine row class
    let rowClass = '';
    if (isTransaction) {
      rowClass = 'row-transaction';
    } else if (isBalance) {
      const type = String(entry.type || '').replace('balance_', '').toLowerCase();
      rowClass = type === 'sync' ? 'row-balance-sync' : 'row-balance-add';
    }
    
    if (rowClass) {
      tr.className = rowClass;
      tr.style.cursor = isTransaction ? 'pointer' : 'default';
    }

    // Build type badge
    const typeLabel = entry.type_label || 'Unknown';
    let typeBadge = `<span class="badge badge-compact badge-default">${window.FinTrak.escapeHtml(typeLabel)}</span>`;
    
    if (isBalance) {
      const type = String(entry.type || '').replace('balance_', '').toLowerCase();
      const badgeClass = type === 'sync' ? 'badge-sync' : 'badge-add';
      typeBadge = `<span class="badge badge-compact ${badgeClass}">${window.FinTrak.escapeHtml(typeLabel)}</span>`;
    } else if (isTransaction) {
      typeBadge = `<span class="badge badge-compact badge-transaction">Transaction</span>`;
    }

    // Build details
    let details = '';
    if (isTransaction) {
      const description = String(entry.description || '').trim();
      const category = String(entry.category || '').trim();
      const noteValue = String(entry.note || '').trim();
      const escapedDescription = window.FinTrak.escapeHtml(description);
      const escapedCategory = window.FinTrak.escapeHtml(category || 'Uncategorized');
      const escapedNote = window.FinTrak.escapeHtml(noteValue);

      if (description && category) {
        details = `<small>${escapedDescription} (${escapedCategory})</small>`;
      } else if (description) {
        details = `<small>${escapedDescription}</small>`;
      } else if (category) {
        details = `<small>${escapedCategory}</small>`;
      } else if (noteValue) {
        details = `<small>${escapedNote}</small>`;
      } else {
        details = `<small>Transaction</small>`;
      }
    } else if (isBalance) {
      details = `<small>${window.FinTrak.escapeHtml(formatDisplayNote(entry.note || ''))}</small>`;
    }

    // Build actions for balance entries
    let actionHTML = '';
    if (isBalance && !viewOnly) {
      const type = String(entry.type || '').replace('balance_', '').toLowerCase();
      const mode = type === 'sync' ? 'sync' : 'add';
      actionHTML = `
        <div class="table-actions">
          <button class="btn btn-sm btn-outline-primary balance-edit-btn me-1"
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
          </button>
        </div>`;
    } else if (isTransaction) {
      actionHTML = '<small class="text-muted">View in transactions →</small>';
    } else {
      actionHTML = '<span class="text-muted small">View-only</span>';
    }

    tr.innerHTML = `<td data-label="When">${formatDisplayDate(entry.timestamp_str || '')}</td>
                    <td data-label="Type">${typeBadge}</td>
                    <td data-label="Detail">${details}</td>
                    <td data-label="Amount" class="text-end">${formatNumber(entry.delta)}</td>
                    <td data-label="Balance" class="text-end">${entry.balance !== null ? formatNumber(entry.balance) : '—'}</td>
                    <td data-label="Actions" class="text-end">${actionHTML}</td>`;
    
    // Make transaction rows clickable
    if (isTransaction) {
      tr.addEventListener('click', () => {
        openTransactionsForEntry(entry);
      });
    }
    
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
    await window.FinTrak.fetchJSON(`/api/balance/${encodeURIComponent(id)}/update`, {}, {
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

async function deleteBalanceEntry(button, currentBalanceEl, balanceTimestampEl, historyBody) {
  const id = button.dataset.id;
  const note = button.dataset.note || 'No note';
  const type = button.dataset.type || '';
  const mode = button.dataset.mode || (type === 'sync' ? 'sync' : 'add');
  const delta = readMoneyValue(button.dataset.delta);
  
  const confirmed = await window.FinTrak?.confirm?.(`Delete this balance entry (${type}/${mode}: ${note})? Its change of Rs. ${formatNumber(delta)} will be removed and following rows recalculated.`, 'Delete');
  if (!confirmed) return;

  try {
    await window.FinTrak.fetchJSON(`/api/balance/${encodeURIComponent(id)}/delete`, {}, {
      method: 'POST'
    });
    showToast('Balance entry deleted', 'success');
    await refreshPage(currentBalanceEl, balanceTimestampEl, historyBody);
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
        const result = await window.FinTrak.fetchJSON('/api/balance/add', {}, {
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
        const result = await window.FinTrak.fetchJSON('/api/balance/sync', {}, {
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
        showToast('Sync failed', 'danger', error.message);
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
