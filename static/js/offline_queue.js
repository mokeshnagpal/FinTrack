(function () {
  const storageKey = 'fintrak_pending_actions';
  let syncing = false;

  function storageAvailable() {
    try {
      const testKey = `${storageKey}_test`;
      localStorage.setItem(testKey, '1');
      localStorage.removeItem(testKey);
      return true;
    } catch (error) {
      return false;
    }
  }

  const canPersistQueue = storageAvailable();

  function readQueue() {
    if (!canPersistQueue) return [];
    try {
      return JSON.parse(localStorage.getItem(storageKey) || '[]');
    } catch (error) {
      return [];
    }
  }

  function writeQueue(queue) {
    if (!canPersistQueue) return;
    localStorage.setItem(storageKey, JSON.stringify(queue));
    emitQueueChange(queue);
  }

  function emitQueueChange(queue = readQueue()) {
    window.dispatchEvent(new CustomEvent('fintrak:queuechange', {
      detail: { pending: queue.length },
    }));
    updatePendingBadge(queue.length);
  }

  function updatePendingBadge(count = readQueue().length) {
    const badge = document.getElementById('pendingNavBadge');
    if (!badge) return;
    badge.textContent = String(count);
    badge.hidden = count === 0;
  }

  function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  }

  function actionId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    return `action-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function closeFormModal(form) {
    if (window.FinTrak?.hideModal) {
      window.FinTrak.hideModal(form);
      return;
    }
    if (typeof bootstrap === 'undefined') return;
    const modal = form?.closest?.('.modal');
    if (modal) {
      bootstrap.Modal.getOrCreateInstance(modal).hide();
    }
  }

  function notify(message, type = 'info') {
    if (window.FinTrak && typeof window.FinTrak.showFlash === 'function') {
      window.FinTrak.showFlash(message, type);
      return;
    }

    let stack = document.getElementById('flashStack');
    if (!stack) {
      stack = document.createElement('div');
      stack.id = 'flashStack';
      stack.className = 'flash-stack';
      document.body.appendChild(stack);
    }
    const div = document.createElement('div');
    div.className = `flash-message ${type}`;
    div.textContent = message;
    stack.appendChild(div);
    setTimeout(() => {
      div.classList.add('flash-message-hide');
      setTimeout(() => div.remove(), 450);
    }, 3500);
  }

  function formPayload(form) {
    const data = new FormData(form);
    const payload = {
      amount: data.get('amount'),
      description: data.get('description'),
      category: data.get('category'),
      date: data.get('date'),
      time: data.get('time'),
    };
    if (data.has('person')) {
      payload.person = data.get('person');
    }
    return payload;
  }

  function validatePayload(payload, options = {}) {
    if (options.requirePerson && !String(payload.person || '').trim()) {
      return 'Select a person.';
    }
    const amount = Number(payload.amount);
    if (!amount || Number.isNaN(amount) || !Number.isFinite(amount) || amount <= 0 || amount > 999999999) {
      return 'Enter an amount greater than zero.';
    }
    const description = String(payload.description || '').trim();
    if (!description) {
      return 'Enter a description.';
    }
    if (description.length > 120) {
      return 'Use 120 characters or fewer for the description.';
    }
    if (!String(payload.category || '').trim()) {
      return 'Select a category.';
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(payload.date || ''))) {
      return 'Select a valid date.';
    }
    if (!/^\d{2}:\d{2}$/.test(String(payload.time || ''))) {
      return 'Select a valid time.';
    }
    return '';
  }

  function endpointFor(form, queueType) {
    const transactionId = form.dataset.transactionId || '';
    const splitId = form.dataset.splitId || '';
    const splitEntryId = form.dataset.splitEntryId || '';
    if (queueType === 'transaction-edit') {
      return `/api/transactions/${encodeURIComponent(transactionId)}/update`;
    }
    if (queueType === 'transaction-delete') {
      return `/api/transactions/${encodeURIComponent(transactionId)}/delete`;
    }
    if (queueType === 'split-entry-create') {
      return `/api/splits/${encodeURIComponent(splitId)}/entries/create`;
    }
    if (queueType === 'split-entry-edit') {
      return `/api/splits/${encodeURIComponent(splitId)}/entries/${encodeURIComponent(splitEntryId)}/update`;
    }
    if (queueType === 'split-entry-delete') {
      return `/api/splits/${encodeURIComponent(splitId)}/entries/${encodeURIComponent(splitEntryId)}/delete`;
    }
    return '/api/transactions/create';
  }

  function endpointForActionType(type) {
    if (type === 'balance_add') return '/api/balance/add';
    if (type === 'balance_sync') return '/api/balance/sync';
    return '';
  }

  function payloadFor(form, queueType) {
    if (queueType === 'transaction-delete' || queueType === 'split-entry-delete') {
      return {};
    }
    return formPayload(form);
  }

  function enqueue(action) {
    const queue = readQueue();
    queue.push(action);
    writeQueue(queue);
  }

  function enqueueAction(type, payload, endpoint = '') {
    const action = {
      type,
      endpoint: endpoint || endpointForActionType(type),
      payload: {
        ...(payload || {}),
        client_action_id: payload?.client_action_id || actionId(),
      },
      created_at: new Date().toISOString(),
    };
    enqueue(action);
    syncQueue({ quiet: true });
    return action;
  }

  async function postAction(action) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(action.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken(),
        },
        body: JSON.stringify(action.payload),
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const error = new Error(data.error || `Sync failed (${response.status})`);
        error.permanent = response.status >= 400 && response.status < 500 && Boolean(data.error);
        throw error;
      }
      return data;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function syncQueue(options = {}) {
    if (syncing) return { synced: 0, failed: 0, remaining: readQueue().length, skipped: true };
    syncing = true;

    const queue = readQueue();
    const remaining = [];
    let synced = 0;
    let failed = 0;

    for (const action of queue) {
      try {
        await postAction(action);
        synced += 1;
      } catch (error) {
        failed += 1;
        if (!error.permanent) {
          remaining.push(action);
        } else {
          notify('One invalid queued action was removed.', 'error');
        }
      }
    }

    writeQueue(remaining);
    syncing = false;

    if (synced > 0 && window.FinTrak?.cache?.refreshSnapshot) {
      window.FinTrak.cache.refreshSnapshot().catch((error) => {
        console.warn('browser cache snapshot refresh failed after queued sync', error);
      });
    }

    if (!options.quiet && synced > 0) {
      notify(`${synced} pending action${synced === 1 ? '' : 's'} synced.`, 'success');
    } else if (!options.quiet && failed > 0 && remaining.length > 0) {
      notify('Saved locally. Will sync when the server responds.', 'info');
    }

    return { synced, failed, remaining: remaining.length, skipped: false };
  }

  function initQueuedForms() {
    document.querySelectorAll('form[data-offline-queue]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        const queueType = form.dataset.offlineQueue;
        if (![
          'transaction-create',
          'transaction-edit',
          'transaction-delete',
          'split-entry-create',
          'split-entry-edit',
          'split-entry-delete',
        ].includes(queueType)) {
          return;
        }

        event.preventDefault();

        if (!canPersistQueue) {
          form.submit();
          return;
        }

        const submitButton = form.querySelector('button[type="submit"], button:not([type])');
        const payload = payloadFor(form, queueType);
        const isDeleteAction = queueType === 'transaction-delete' || queueType === 'split-entry-delete';
        const validationError = isDeleteAction ? '' : validatePayload(payload, {
          requirePerson: queueType.startsWith('split-entry-'),
        });
        if (validationError) {
          notify(validationError, 'error');
          return;
        }
        payload.client_action_id = actionId();

        enqueue({
          type: queueType.replace(/-/g, '_'),
          endpoint: endpointFor(form, queueType),
          payload,
          created_at: new Date().toISOString(),
        });

        if (submitButton) submitButton.blur();
        if (queueType === 'transaction-create') {
          form.reset();
          closeFormModal(form);
          notify('Transaction saved locally. Syncing in background.', 'success');
        } else if (queueType === 'transaction-edit') {
          closeFormModal(form);
          notify('Update saved locally. Syncing in background.', 'success');
          window.location.href = '/transactions';
        } else if (queueType === 'split-entry-create') {
          form.reset();
          closeFormModal(form);
          notify('Split entry saved locally. Syncing in background.', 'success');
        } else if (queueType === 'split-entry-edit') {
          closeFormModal(form);
          notify('Split entry update saved locally. Syncing in background.', 'success');
          window.location.href = form.dataset.returnUrl || window.location.pathname.replace(/\/entries\/.+\/edit$/, '');
        } else {
          const row = form.closest('tr');
          closeFormModal(form);
          if (row) row.remove();
          notify('Delete saved locally. Syncing in background.', 'success');
        }
        syncQueue();
      });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    updatePendingBadge();
    initQueuedForms();
    syncQueue();
  });

  window.addEventListener('online', syncQueue);
  window.FinTrak = window.FinTrak || {};
  window.FinTrak.syncPendingActions = syncQueue;
  window.FinTrak.pendingActionsCount = () => readQueue().length;
  window.FinTrak.readPendingActions = () => readQueue();
  window.FinTrak.enqueueOfflineAction = enqueueAction;
}());
