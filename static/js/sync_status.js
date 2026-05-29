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
  }

  async function checkRender(allowCacheRefresh) {
    elements.renderState.textContent = 'Checking';
    elements.renderMessage.textContent = 'Checking whether the server is awake.';
    if (allowCacheRefresh && !cacheRefreshRequestedForCurrentWake && elements.cacheState && elements.cacheMessage) {
      elements.cacheState.textContent = 'Checking';
      elements.cacheMessage.textContent = 'Checking Firestore updates before sync.';
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
      if (renderAwake && window.FinTrak?.cache?.refreshSnapshot) {
        await window.FinTrak.cache.refreshSnapshot().catch((error) => {
          console.warn('browser cache snapshot refresh failed', error);
        });
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
      await window.FinTrak.syncPendingActions({ quiet: true });
      if (window.FinTrak?.cache?.refreshSnapshot) {
        await window.FinTrak.cache.refreshSnapshot().catch((error) => {
          console.warn('browser cache snapshot refresh failed after sync', error);
        });
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
    renderQueue();
    refresh(true);
    setInterval(() => refresh(true), pollMs);
  });
}());
