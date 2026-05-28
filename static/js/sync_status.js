(function () {
  const storageKey = 'fintrak_pending_actions';
  const originalTitle = document.title;
  const elements = {
    pendingCount: document.getElementById('pendingCount'),
    syncHeadline: document.getElementById('syncHeadline'),
    syncMessage: document.getElementById('syncMessage'),
    renderState: document.getElementById('renderState'),
    renderMessage: document.getElementById('renderMessage'),
    lastCheck: document.getElementById('lastCheck'),
    queueBadge: document.getElementById('queueBadge'),
    pendingList: document.getElementById('pendingList'),
    syncNowBtn: document.getElementById('syncNowBtn'),
  };
  let renderAwake = false;
  let lastRenderedPendingCount = null;
  let syncRequestedForCurrentWake = false;

  function readQueue() {
    try {
      return JSON.parse(localStorage.getItem(storageKey) || '[]');
    } catch (error) {
      return [];
    }
  }

  function formatActionType(type) {
    return String(type || 'transaction_action').replace(/_/g, ' ');
  }

  function formatTime(value) {
    const date = value ? new Date(value) : new Date();
    if (Number.isNaN(date.getTime())) return '-';
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function setBadge(text, tone) {
    elements.queueBadge.textContent = text;
    elements.queueBadge.className = tone ? `badge ${tone}` : 'badge';
  }

  function renderEmptyPendingList() {
    elements.pendingList.textContent = '';
    const empty = document.createElement('p');
    empty.className = 'text-muted mb-0';
    empty.textContent = 'No pending actions found.';
    elements.pendingList.appendChild(empty);
  }

  function renderQueue() {
    const queue = readQueue();
    const count = queue.length;
    const previousCount = lastRenderedPendingCount;
    elements.pendingCount.textContent = String(count);
    document.title = count > 0 ? `(${count}) Pending - FinTrak` : originalTitle;

    if (count === 0) {
      elements.syncHeadline.textContent = 'You can close now';
      elements.syncMessage.textContent = renderAwake
        ? 'All pending transaction actions are synced.'
        : 'No pending transaction actions are stored in this browser.';
      setBadge('Clear', 'success');
      renderEmptyPendingList();
      lastRenderedPendingCount = count;
      return queue;
    }

    if (previousCount !== null && previousCount !== count) {
      syncRequestedForCurrentWake = false;
    }

    elements.syncHeadline.textContent = `${count} pending action${count === 1 ? '' : 's'}`;
    elements.syncMessage.textContent = renderAwake
      ? 'Render is awake. Sending pending actions now.'
      : 'Waiting for Render to wake up before sending pending actions.';
    setBadge('Pending', '');

    elements.pendingList.textContent = '';
    queue.forEach((action, index) => {
      const payload = action.payload || {};
      const description = payload.description || action.endpoint || 'Transaction action';

      const item = document.createElement('div');
      item.className = 'sync-pending-item';

      const text = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = `${index + 1}. ${formatActionType(action.type)}`;
      const subtitle = document.createElement('span');
      subtitle.textContent = String(description);
      text.append(title, subtitle);

      const time = document.createElement('small');
      time.textContent = formatTime(action.created_at);

      item.append(text, time);
      elements.pendingList.appendChild(item);
    });

    lastRenderedPendingCount = count;
    return queue;
  }

  async function checkRender() {
    elements.renderState.textContent = 'Checking';
    elements.renderMessage.textContent = 'Checking whether the server is awake.';

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch('/api/render_status', {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      renderAwake = response.ok && data.ok;
      elements.renderState.textContent = renderAwake ? 'Awake' : 'Not ready';
      elements.renderMessage.textContent = renderAwake
        ? 'The server responded. Pending actions can be sent.'
        : 'The server did not return a ready response yet.';
    } catch (error) {
      renderAwake = false;
      elements.renderState.textContent = 'Sleeping';
      elements.renderMessage.textContent = 'Waiting for Render to respond.';
      syncRequestedForCurrentWake = false;
    } finally {
      clearTimeout(timeout);
      elements.lastCheck.textContent = formatTime();
    }
  }

  async function refresh(allowSync) {
    const queue = renderQueue();
    await checkRender();
    renderQueue();

    if (allowSync && renderAwake && queue.length > 0 && !syncRequestedForCurrentWake && window.FinTrak?.syncPendingActions) {
      syncRequestedForCurrentWake = true;
      await window.FinTrak.syncPendingActions({ quiet: true });
      renderQueue();
    }
  }

  elements.syncNowBtn?.addEventListener('click', async () => {
    syncRequestedForCurrentWake = false;
    await refresh(true);
  });

  window.addEventListener('storage', (event) => {
    if (event.key === storageKey) renderQueue();
  });

  window.addEventListener('fintrak:queuechange', () => {
    syncRequestedForCurrentWake = false;
    renderQueue();
  });

  document.addEventListener('DOMContentLoaded', () => {
    renderQueue();
    refresh(true);
    setInterval(() => refresh(true), 12000);
  });
}());
