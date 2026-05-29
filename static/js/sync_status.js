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
    { id: 'view_only_password', group: 'Server', label: 'View-only password hash', detail: 'Waiting for Render.' },
    { id: 'categories', group: 'Server', label: 'Categories', detail: 'Waiting for Render.' },
    { id: 'user_auth', group: 'Server', label: 'Current user auth hash', detail: 'Waiting for Render.' },
    { id: 'browser_categories', group: 'Browser', label: 'Cached categories', detail: 'No local snapshot checked yet.' },
    { id: 'browser_balance', group: 'Browser', label: 'Cached balance', detail: 'No local snapshot checked yet.' },
    { id: 'browser_balance_history', group: 'Browser', label: 'Cached balance history', detail: 'No local snapshot checked yet.' },
    { id: 'browser_transactions', group: 'Browser', label: 'Cached recent transactions', detail: 'No local snapshot checked yet.' },
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

      const group = document.createElement('span');
      group.textContent = item.group;
      const label = document.createElement('strong');
      label.textContent = item.label;
      const detail = document.createElement('small');
      detail.textContent = `${state.status || 'Waiting'} - ${state.detail || item.detail}`;

      node.append(group, label, detail);
      elements.cacheDetailList.appendChild(node);
    });
  }

  function setCacheItem(id, status, detail) {
    cacheItemState.set(id, { status, detail });
    renderCacheDetails();
  }

  function setServerCacheUpdating() {
    ['view_only_password', 'categories', 'user_auth'].forEach((id) => {
      setCacheItem(id, 'Updating', 'Checking Firestore.');
    });
    setCacheDetailBadge('Updating', '');
  }

  function setBrowserCacheUpdating(reason) {
    ['browser_categories', 'browser_balance', 'browser_balance_history', 'browser_transactions'].forEach((id) => {
      setCacheItem(id, 'Updating', reason);
    });
    setCacheDetailBadge('Updating', '');
  }

  function applyServerCacheResult(cacheRefresh) {
    if (!cacheRefresh) return;
    const updated = new Set(Array.isArray(cacheRefresh.updated) ? cacheRefresh.updated : []);
    const errors = new Set(Array.isArray(cacheRefresh.errors) ? cacheRefresh.errors : []);

    ['view_only_password', 'categories', 'user_auth'].forEach((id) => {
      if (updated.has(id)) {
        setCacheItem(id, 'Updated', 'Server cache refreshed.');
      } else if (errors.has(id)) {
        setCacheItem(id, 'Failed', 'Server cache refresh failed.');
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

    setCacheItem('browser_categories', 'Updated', `${categories} categor${categories === 1 ? 'y' : 'ies'} cached.`);
    setCacheItem('browser_balance', 'Updated', `Current balance cached: ${currentBalance ?? '0.00'}.`);
    setCacheItem('browser_balance_history', 'Updated', `${history} balance histor${history === 1 ? 'y item' : 'y items'} cached.`);
    setCacheItem('browser_transactions', 'Updated', `${transactions} recent transaction${transactions === 1 ? '' : 's'} cached.`);
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
      ['browser_categories', 'browser_balance', 'browser_balance_history', 'browser_transactions'].forEach((id) => {
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
      ? `Checked ${updated.length || 0} cache area${updated.length === 1 ? '' : 's'} before sync.`
      : 'Cache check could not finish. It will retry on the next status check.';
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
        ? 'The server responded. Cache check ran before pending actions.'
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

  async function refresh(allowSync) {
    const queue = renderQueue();
    await checkRender(allowSync);
    renderQueue();

    if (allowSync && renderAwake && queue.length > 0 && !syncRequestedForCurrentWake && window.FinTrak?.syncPendingActions) {
      syncRequestedForCurrentWake = true;
      const result = await window.FinTrak.syncPendingActions({ quiet: true });
      if (result && result.synced > 0) {
        await refreshBrowserSnapshot('Updating local cache after queued jobs finished.');
      }
      renderQueue();
    }
  }

  elements.syncNowBtn?.addEventListener('click', async () => {
    syncRequestedForCurrentWake = false;
    cacheRefreshRequestedForCurrentWake = false;
    await refresh(true);
  });

  window.addEventListener('storage', (event) => {
    if (event.key === storageKey) renderQueue();
  });

  window.addEventListener('fintrak:queuechange', () => {
    syncRequestedForCurrentWake = false;
    cacheRefreshRequestedForCurrentWake = false;
    renderQueue();
  });

  document.addEventListener('DOMContentLoaded', () => {
    renderCacheDetails();
    renderQueue();
    refresh(true);
    setInterval(() => refresh(true), pollMs);
  });
}());
