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
    return {
      amount: data.get('amount'),
      description: data.get('description'),
      category: data.get('category'),
      date: data.get('date'),
      time: data.get('time'),
    };
  }

  function validatePayload(payload) {
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
    if (queueType === 'transaction-edit') {
      return `/api/transactions/${encodeURIComponent(transactionId)}/update`;
    }
    if (queueType === 'transaction-delete') {
      return `/api/transactions/${encodeURIComponent(transactionId)}/delete`;
    }
    return '/api/transactions/create';
  }

  function payloadFor(form, queueType) {
    if (queueType === 'transaction-delete') {
      return {};
    }
    return formPayload(form);
  }

  function enqueue(action) {
    const queue = readQueue();
    queue.push(action);
    writeQueue(queue);
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
    if (syncing) return;
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

    if (!options.quiet && synced > 0) {
      notify(`${synced} pending transaction${synced === 1 ? '' : 's'} synced.`, 'success');
    } else if (!options.quiet && failed > 0 && remaining.length > 0) {
      notify('Saved locally. Will sync when the server responds.', 'info');
    }
  }

  function initQueuedForms() {
    document.querySelectorAll('form[data-offline-queue]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        const queueType = form.dataset.offlineQueue;
        if (!['transaction-create', 'transaction-edit', 'transaction-delete'].includes(queueType)) {
          return;
        }

        event.preventDefault();

        if (!canPersistQueue) {
          form.submit();
          return;
        }

        const submitButton = form.querySelector('button[type="submit"], button:not([type])');
        const payload = payloadFor(form, queueType);
        const validationError = queueType === 'transaction-delete' ? '' : validatePayload(payload);
        if (validationError) {
          notify(validationError, 'error');
          return;
        }
        payload.client_action_id = actionId();

        enqueue({
          type: queueType.replace('-', '_'),
          endpoint: endpointFor(form, queueType),
          payload,
          created_at: new Date().toISOString(),
        });

        if (submitButton) submitButton.blur();
        if (queueType === 'transaction-create') {
          form.reset();
          notify('Transaction saved locally. Syncing in background.', 'success');
        } else if (queueType === 'transaction-edit') {
          notify('Update saved locally. Syncing in background.', 'success');
          window.location.href = '/transactions';
        } else {
          const row = form.closest('tr');
          const modal = form.querySelector('.modal.show');
          if (modal && window.bootstrap) {
            window.bootstrap.Modal.getOrCreateInstance(modal).hide();
          }
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
}());
