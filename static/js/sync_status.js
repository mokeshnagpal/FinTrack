(function () {
  const storageKey = 'fintrak_pending_actions';
  const originalTitle = document.title;
  const elements = {
    pendingCount: document.getElementById('pendingCount'),
    syncHeadline: document.getElementById('syncHeadline'),
    syncMessage: document.getElementById('syncMessage'),
    renderState: document.getElementById('renderState'),
    renderMessage: document.getElementById('renderMessage'),
    cacheState: document.getElementById('cacheState'),
    cacheMessage: document.getElementById('cacheMessage'),
    cacheDetailBadge: document.getElementById('cacheDetailBadge'),
    cacheDetailList: document.getElementById('cacheDetailList'),
    lastCheck: document.getElementById('lastCheck'),
    queueBadge: document.getElementById('queueBadge'),
    pendingList: document.getElementById('pendingList'),
    syncNowBtn: document.getElementById('syncNowBtn'),
  };
  let renderAwake = false;
  let lastRenderedPendingCount = null;
  let syncRequestedForCurrentWake = false;
  let cacheRefreshRequestedForCurrentWake = false;
  const pollMs = Number(window.FinTrakConstants?.sync_status_poll_seconds || 12) * 1000;
  const cacheItems = [
    { id: 'view_only_password', group: 'Firestore', label: 'View-only password hash', detail: 'Waiting for Render.' },
    { id: 'categories', group: 'Firestore', label: 'Categories', detail: 'Waiting for Render.' },
    { id: 'split_people', group: 'Firestore', label: 'Split people', detail: 'Waiting for Render.' },
    { id: 'user_auth', group: 'Firestore', label: 'Current user auth hash', detail: 'Waiting for Render.' },
    { id: 'browser_categories', group: 'Browser', label: 'Cached categories', detail: 'No local snapshot checked yet.' },
    { id: 'browser_balance', group: 'Browser', label: 'Cached balance', detail: 'No local snapshot checked yet.' },
    { id: 'browser_balance_history', group: 'Browser', label: 'Cached balance history', detail: 'No local snapshot checked yet.' },
    { id: 'browser_transactions', group: 'Browser', label: 'Cached recent transactions', detail: 'No local snapshot checked yet.' },
    { id: 'browser_live_split', group: 'Browser', label: 'Cached live split', detail: 'No local snapshot checked yet.' },
  ];
  const cacheItemState = new Map(cacheItems.map((item) => [item.id, { status: 'Waiting', detail: item.detail }]));

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

  function describeAction(action) {
    const payload = action.payload || {};
    if (payload.description) return payload.description;
    if (payload.note) {
      return window.FinTrak?.formatBalanceNote
        ? window.FinTrak.formatBalanceNote(payload.note)
        : payload.note;
    }
    if (payload.balance !== undefined) return `Balance ${payload.balance}`;
    if (payload.amount !== undefined) return `Amount ${payload.amount}`;
    return action.endpoint || 'Pending action';
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

  function setCacheDetailBadge(text, tone) {
    if (!elements.cacheDetailBadge) return;
    elements.cacheDetailBadge.textContent = text;
    elements.cacheDetailBadge.className = tone ? `badge ${tone}` : 'badge';
  }

  function renderCacheDetails() {
    if (!elements.cacheDetailList) return;
    elements.cacheDetailList.textContent = '';
    cacheItems.forEach((item) => {
      const state = cacheItemState.get(item.id) || {};
      const node = document.createElement('div');
      node.className = 'sync-cache-item';

      const statusText = state.status || 'Waiting';
      let statusClass = 'danger'; // Default Red for Not Updated / Failed / Waiting
      if (statusText === 'Updating') {
        statusClass = 'warning'; // Yellow for Updating
      } else if (statusText === 'Updated') {
        statusClass = 'success'; // Green for Updated
      }

      const groupContainer = document.createElement('div');
      groupContainer.className = 'd-flex justify-content-between align-items-center';

      const group = document.createElement('span');
      group.textContent = item.group;

      const statusBadge = document.createElement('span');
      statusBadge.className = `badge sync-status-compact ${statusClass}`;
      statusBadge.textContent = statusText;

      groupContainer.append(group, statusBadge);

      const label = document.createElement('strong');
      label.textContent = item.label;

      const detail = document.createElement('small');
      detail.textContent = state.detail || item.detail;

      node.append(groupContainer, label, detail);
      elements.cacheDetailList.appendChild(node);
    });
  }

  function setCacheItem(id, status, detail) {
    cacheItemState.set(id, { status, detail });
    renderCacheDetails();
  }

  function setServerCacheUpdating() {
    ['view_only_password', 'categories', 'split_people', 'user_auth'].forEach((id) => {
      setCacheItem(id, 'Updating', 'Checking Firestore.');
    });
    setCacheDetailBadge('Updating', '');
  }

  function setBrowserCacheUpdating(reason) {
    ['browser_categories', 'browser_balance', 'browser_balance_history', 'browser_transactions', 'browser_live_split'].forEach((id) => {
      setCacheItem(id, 'Updating', reason);
    });
    setCacheDetailBadge('Updating', '');
  }

  function applyServerCacheResult(cacheRefresh) {
    if (!cacheRefresh) return;
    const updated = new Set(Array.isArray(cacheRefresh.updated) ? cacheRefresh.updated : []);
    const errors = new Set(Array.isArray(cacheRefresh.errors) ? cacheRefresh.errors : []);

    ['view_only_password', 'categories', 'split_people', 'user_auth'].forEach((id) => {
      if (updated.has(id)) {
        setCacheItem(id, 'Updated', 'Firestore value checked.');
      } else if (errors.has(id)) {
        setCacheItem(id, 'Failed', 'Firestore check failed.');
      } else {
        setCacheItem(id, 'Skipped', 'No update returned.');
      }
    });
  }

  function applyBrowserSnapshot(snapshot) {
    if (!snapshot) return;
    const categories = Array.isArray(snapshot.categories) ? snapshot.categories.length : 0;
    const history = Array.isArray(snapshot.balance?.history) ? snapshot.balance.history.length : 0;
    const transactions = Array.isArray(snapshot.transactions) ? snapshot.transactions.length : 0;
    const currentBalance = snapshot.balance?.current?.balance;
    const liveSplit = snapshot.live_split;
    const liveSplitEntries = Array.isArray(liveSplit?.entries) ? liveSplit.entries.length : 0;

    setCacheItem('browser_categories', 'Updated', `${categories} categor${categories === 1 ? 'y' : 'ies'} cached.`);
    setCacheItem('browser_balance', 'Updated', `Current balance cached: ${currentBalance ?? '0.00'}.`);
    setCacheItem('browser_balance_history', 'Updated', `${history} balance histor${history === 1 ? 'y item' : 'y items'} cached.`);
    setCacheItem('browser_transactions', 'Updated', `${transactions} recent transaction${transactions === 1 ? '' : 's'} cached.`);
    setCacheItem('browser_live_split', 'Updated', liveSplit ? `${liveSplit.title || 'Live split'} cached with ${liveSplitEntries} entr${liveSplitEntries === 1 ? 'y' : 'ies'}.` : 'No live split selected.');
    setCacheDetailBadge('Updated', 'success');
  }

  async function refreshBrowserSnapshot(reason) {
    if (!window.FinTrak?.cache?.refreshSnapshot) return null;
    setBrowserCacheUpdating(reason);
    try {
      const snapshot = await window.FinTrak.cache.refreshSnapshot();
      applyBrowserSnapshot(snapshot);
      return snapshot;
    } catch (error) {
      console.warn('browser cache snapshot refresh failed', error);
      ['browser_categories', 'browser_balance', 'browser_balance_history', 'browser_transactions', 'browser_live_split'].forEach((id) => {
        setCacheItem(id, 'Failed', 'Browser cache snapshot could not update.');
      });
      setCacheDetailBadge('Needs retry', 'danger');
      return null;
    }
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
        ? 'All pending actions are synced.'
        : 'No pending actions are stored in this browser.';
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
      const description = describeAction(action);

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

  function renderCacheRefreshStatus(cacheRefresh) {
    if (!elements.cacheState || !elements.cacheMessage) return;

    if (!cacheRefresh) {
      elements.cacheState.textContent = 'Waiting';
      elements.cacheMessage.textContent = 'Cache check will run when Render responds.';
      return;
    }

    const updated = Array.isArray(cacheRefresh.updated) ? cacheRefresh.updated : [];
    elements.cacheState.textContent = cacheRefresh.ok ? 'Updated' : 'Needs retry';
    elements.cacheMessage.textContent = cacheRefresh.ok
      ? `Checked ${updated.length || 0} Firestore area${updated.length === 1 ? '' : 's'} before sync.`
      : 'Firestore check could not finish. It will retry on the next status check.';
    applyServerCacheResult(cacheRefresh);
  }

  async function checkRender(allowCacheRefresh) {
    elements.renderState.textContent = 'Checking';
    elements.renderMessage.textContent = 'Checking whether the server is awake.';
    if (allowCacheRefresh && !cacheRefreshRequestedForCurrentWake && elements.cacheState && elements.cacheMessage) {
      elements.cacheState.textContent = 'Checking';
      elements.cacheMessage.textContent = 'Checking Firestore updates before sync.';
      setServerCacheUpdating();
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const shouldRefreshCache = allowCacheRefresh && !cacheRefreshRequestedForCurrentWake;
      const statusUrl = shouldRefreshCache ? '/api/render_status?refresh_cache=1' : '/api/render_status';
      const response = await fetch(statusUrl, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      renderAwake = response.ok && data.ok;
      if (shouldRefreshCache) cacheRefreshRequestedForCurrentWake = renderAwake;
      elements.renderState.textContent = renderAwake ? 'Awake' : 'Not ready';
      elements.renderMessage.textContent = renderAwake
        ? 'The server responded. Firestore check ran before pending actions.'
        : 'The server did not return a ready response yet.';
      renderCacheRefreshStatus(data.cache_refresh);
      if (renderAwake) {
        await refreshBrowserSnapshot('Updating local cache after Render wake.');
      }
    } catch (error) {
      renderAwake = false;
      elements.renderState.textContent = 'Sleeping';
      elements.renderMessage.textContent = 'Waiting for Render to respond.';
      renderCacheRefreshStatus(null);
      syncRequestedForCurrentWake = false;
      cacheRefreshRequestedForCurrentWake = false;
    } finally {
      clearTimeout(timeout);
      elements.lastCheck.textContent = formatTime();
    }
  }

  let activePollInterval = null;

  function startAsleepPolling() {
    if (activePollInterval) return;
    activePollInterval = setInterval(async () => {
      await checkRender(true);
      if (renderAwake) {
        stopAsleepPolling();
        triggerSequencedSync();
      }
    }, 5000); // Check every 5 seconds when asleep
  }

  function stopAsleepPolling() {
    if (activePollInterval) {
      clearInterval(activePollInterval);
      activePollInterval = null;
    }
  }

  async function triggerSequencedSync() {
    const queue = readQueue();
    if (queue.length === 0) return;

    // Pre-flight status check immediately before running a job
    await checkRender(true);

    if (!renderAwake) {
      startAsleepPolling();
      return;
    }

    stopAsleepPolling();

    if (window.FinTrak?.syncPendingActions) {
      // 1. First, update the change when service wakes
      // This has already been run inside checkRender(true) which triggers refreshBrowserSnapshot!

      // 2. Then, run each queued job
      await window.FinTrak.syncPendingActions({ quiet: true });

      // 3. Then, update cached again when all jobs finished and queue reaches 0
      if (readQueue().length === 0) {
        await refreshBrowserSnapshot('Updating local cache after all jobs synced.');
      }
    }
  }

  elements.syncNowBtn?.addEventListener('click', async () => {
    await triggerSequencedSync();
  });

  window.addEventListener('storage', (event) => {
    if (event.key === storageKey) renderQueue();
  });

  window.addEventListener('fintrak:queuechange', () => {
    renderQueue();
    triggerSequencedSync();
  });

  document.addEventListener('DOMContentLoaded', () => {
    renderCacheDetails();
    renderQueue();

    checkRender(true).then(() => {
      const queue = readQueue();
      if (!renderAwake) {
        startAsleepPolling();
      } else if (queue.length > 0) {
        triggerSequencedSync();
      }
    });
  });
}());
