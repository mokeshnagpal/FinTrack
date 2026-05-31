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

    const form = document.querySelector('form');
    if (form) {
      form.addEventListener('submit', async (event) => {
        const usernameVal = String(usernameInput?.value || '').trim().toLowerCase();
        const passwordInput = document.getElementById('password');
        const passwordVal = String(passwordInput?.value || '').trim();

        if (!usernameVal || !passwordVal) return;

        if (!window.FinTrak?.cache?.sha256) return;

        // Save credentials temporarily
        const hash = await window.FinTrak.cache.sha256(passwordVal);
        const isViewMode = window.location.pathname.includes('/view') || window.location.pathname.includes('/view-login');
        const type = isViewMode ? 'view' : 'full';

        localStorage.setItem('fintrak_temp_auth', JSON.stringify({ username: usernameVal, hash, type }));

        const renderStateText = document.getElementById('authRenderState')?.textContent || '';
        const renderAwake = renderStateText === 'Awake';

        if (!renderAwake) {
          event.preventDefault();

          const cachedRaw = localStorage.getItem('fintrak_cached_auth');
          const cached = cachedRaw ? JSON.parse(cachedRaw) : null;

          let authenticated = false;
          if (cached) {
            if (type === 'view') {
              authenticated = (usernameVal === String(cached.view_username || '').trim().toLowerCase()) &&
                              (hash === cached.view_password_hash);
            } else {
              authenticated = (usernameVal === String(cached.username || '').trim().toLowerCase()) &&
                              (hash === cached.password_hash);
            }
          }

          if (authenticated) {
            localStorage.setItem('fintrak_offline_session', JSON.stringify({
              logged_in: true,
              username: usernameVal,
              type: type,
              created_at: new Date().toISOString()
            }));

            // Attempt session sync on local server
            try {
              const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
              await fetch('/api/login_offline', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({ username: usernameVal, type }),
              });
            } catch (err) {
              console.warn('Flask session offline sync skipped/failed', err);
            }

            const targetUrl = type === 'view' ? '/balance' : '/';
            window.location.href = targetUrl;
          } else {
            alert('Offline login is only available for the last successfully logged-in user with correct credentials.');
          }
        }
      });
    }

    checkWake();
    let wakeInterval = setInterval(async () => {
      await checkWake();
      const renderStateText = document.getElementById('authRenderState')?.textContent || '';
      if (renderStateText === 'Awake') {
        clearInterval(wakeInterval);
        wakeInterval = null;
      }
    }, 5000); // Poll every 5s when asleep
  });
}());
