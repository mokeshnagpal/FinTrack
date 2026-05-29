(function () {
  const renderState = document.getElementById('authRenderState');
  const renderMessage = document.getElementById('authRenderMessage');
  const cacheState = document.getElementById('authCacheState');
  const cacheMessage = document.getElementById('authCacheMessage');
  const passwordCacheState = document.getElementById('authPasswordCacheState');
  const passwordCacheMessage = document.getElementById('authPasswordCacheMessage');
  const usernameInput = document.getElementById('username');
  const pollMs = Number(window.FinTrakConstants?.sync_status_poll_seconds || 12) * 1000;
  let cacheRefreshRequested = false;
  let passwordCacheTimer = null;

  if (!renderState || !renderMessage || !cacheState || !cacheMessage) return;

  function setWaiting() {
    renderState.textContent = 'Waking';
    renderMessage.textContent = 'Waiting for the service to respond.';
    setBrowserCacheStatus();
  }

  function setBrowserCacheStatus() {
    const hasCache = Boolean(window.FinTrak?.cache?.hasUsableSnapshot?.());
    cacheState.textContent = hasCache ? 'Available' : 'Not available';
    cacheMessage.textContent = hasCache
      ? 'Usable local cache is available.'
      : 'No usable local cache is available.';
  }

  function setInitialStatusFromBrowserCache() {
    const hasCache = Boolean(window.FinTrak?.cache?.hasUsableSnapshot?.());
    if (!hasCache) {
      setWaiting();
      return;
    }

    renderState.textContent = 'Cached';
    renderMessage.textContent = 'Cached app data is available while service status is checked.';
    setBrowserCacheStatus();
  }

  async function checkWake() {
    const shouldRefreshCache = !cacheRefreshRequested;
    renderState.textContent = 'Checking';
    renderMessage.textContent = 'Checking whether the service is awake.';
    setBrowserCacheStatus();

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
      setBrowserCacheStatus();
    } catch (error) {
      cacheRefreshRequested = false;
      setWaiting();
    } finally {
      clearTimeout(timeout);
    }
  }

  async function checkPasswordCache() {
    if (!passwordCacheState || !passwordCacheMessage || !usernameInput) return;
    const username = String(usernameInput.value || '').trim();
    if (!username) {
      passwordCacheState.textContent = 'Enter username';
      passwordCacheMessage.textContent = 'Password hash cache status appears after username entry.';
      return;
    }

    passwordCacheState.textContent = 'Checking';
    passwordCacheMessage.textContent = 'Checking server password-hash cache for this username.';
    try {
      const response = await fetch(`/api/login_password_cache_status?username=${encodeURIComponent(username)}`, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
      });
      const data = await response.json().catch(() => ({}));
      const available = response.ok && data.cache_available;
      passwordCacheState.textContent = available ? 'Available' : 'Not available';
      passwordCacheMessage.textContent = available
        ? 'A cached hash exists, but login still refreshes the real hash before comparison.'
        : 'No server password cache yet. Login will read Firestore first.';
    } catch (error) {
      passwordCacheState.textContent = 'Unknown';
      passwordCacheMessage.textContent = 'Password cache status could not be checked.';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    setInitialStatusFromBrowserCache();
    checkPasswordCache();
    usernameInput?.addEventListener('input', () => {
      clearTimeout(passwordCacheTimer);
      passwordCacheTimer = setTimeout(checkPasswordCache, 350);
    });
    checkWake();
    setInterval(checkWake, pollMs);
  });
}());
