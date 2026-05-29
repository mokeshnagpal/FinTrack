(function () {
  const renderState = document.getElementById('authRenderState');
  const renderMessage = document.getElementById('authRenderMessage');
  const cacheState = document.getElementById('authCacheState');
  const cacheMessage = document.getElementById('authCacheMessage');
  const usernameInput = document.getElementById('username');
  const pollMs = Number(window.FinTrakConstants?.sync_status_poll_seconds || 12) * 1000;
  let cacheRefreshRequested = false;
  let authCacheTimer = null;

  if (!renderState || !renderMessage || !cacheState || !cacheMessage) return;

  function setWaiting() {
    renderState.textContent = 'Waking';
    renderMessage.textContent = 'Waiting for the service to respond.';
    checkAuthCache();
  }

  function setInitialStatusFromBrowserCache() {
    const hasCache = Boolean(window.FinTrak?.cache?.hasUsableSnapshot?.());
    if (!hasCache) {
      setWaiting();
      return;
    }

    renderState.textContent = 'Cached';
    renderMessage.textContent = 'Cached app data is available while service status is checked.';
    checkAuthCache();
  }

  async function checkWake() {
    const shouldRefreshCache = !cacheRefreshRequested;
    renderState.textContent = 'Checking';
    renderMessage.textContent = 'Checking whether the service is awake.';
    checkAuthCache();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const url = shouldRefreshCache ? '/api/login_wake_status?refresh_cache=1' : '/api/login_wake_status';
      const response = await fetch(url, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      const awake = response.ok && data.ok;
      cacheRefreshRequested = awake || cacheRefreshRequested;
      renderState.textContent = awake ? 'Awake' : 'Not ready';
      renderMessage.textContent = awake
        ? 'The service responded. Login is ready.'
        : 'The service did not return a ready response yet.';
      checkAuthCache();
    } catch (error) {
      cacheRefreshRequested = false;
      setWaiting();
    } finally {
      clearTimeout(timeout);
    }
  }

  async function checkAuthCache() {
    if (!usernameInput) return;
    const username = String(usernameInput.value || '').trim();
    if (!username) {
      cacheState.textContent = 'Not available';
      cacheMessage.textContent = 'Enter username to check cached login.';
      return;
    }

    cacheState.textContent = 'Checking';
    cacheMessage.textContent = 'Checking cached username and password hash.';
    try {
      const response = await fetch(`/api/login_password_cache_status?username=${encodeURIComponent(username)}`, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
      });
      const data = await response.json().catch(() => ({}));
      const available = response.ok && data.cache_available;
      cacheState.textContent = available ? 'Available' : 'Not available';
      cacheMessage.textContent = available
        ? 'Cached username and password hash are available.'
        : 'Cached login is not available for this username.';
    } catch (error) {
      cacheState.textContent = 'Unknown';
      cacheMessage.textContent = 'Cached login status could not be checked.';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    setInitialStatusFromBrowserCache();
    checkAuthCache();
    usernameInput?.addEventListener('input', () => {
      clearTimeout(authCacheTimer);
      authCacheTimer = setTimeout(checkAuthCache, 350);
    });
    checkWake();
    setInterval(checkWake, pollMs);
  });
}());
