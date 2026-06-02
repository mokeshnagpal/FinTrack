const CACHE_NAME = 'fintrak-shell-v1';
const NAVIGATION_FALLBACK = '/login';
const SHELL_URLS = [
  '/',
  '/login',
  '/view-login',
  '/static/css/styles.css',
  '/static/js/script.js',
  '/static/js/browser_cache.js',
  '/static/js/offline_queue.js',
  '/static/js/flash.js',
  '/static/js/auth_status.js',
  '/static/icons/site.webmanifest',
  '/static/icons/favicon-32x32.png',
  '/static/icons/favicon-16x16.png',
];

async function isValidAppNavigationResponse(response) {
  if (!response || !response.ok) return false;
  const contentType = String(response.headers.get('Content-Type') || '');
  if (!contentType.includes('text/html')) return true;

  const text = await response.clone().text();
  const isFinTrakPage = /<title>.*FinTrak.*<\/title>/i.test(text) || text.includes('class="auth-brand">FT') || text.includes('FinTrak');
  if (isFinTrakPage) return true;

  const isRenderPlaceholder = /render.*(wake|waking|sleep|asleep|loading)/i.test(text);
  if (isRenderPlaceholder) return false;

  return true;
}

async function cacheShell() {
  const cache = await caches.open(CACHE_NAME);
  await Promise.all(
    SHELL_URLS.map(async (url) => {
      try {
        const response = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
        if (response.ok || response.type === 'opaqueredirect') {
          await cache.put(url, response.clone());
        }
      } catch (error) {
        // A single missing asset should not prevent the worker from installing.
      }
    }),
  );
}

async function cachedFallback(request) {
  const cache = await caches.open(CACHE_NAME);
  return (
    (await cache.match(request)) ||
    (await cache.match(NAVIGATION_FALLBACK)) ||
    new Response(
      `<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>FinTrak - Loading</title>
  <link rel="stylesheet" href="/static/css/styles.css" />
</head>
<body>
  <div class="auth-wrapper">
    <div class="auth-card card">
      <div class="card-body">
        <div class="stack auth-stack">
          <div class="center auth-heading">
            <div class="auth-brand">FT</div>
            <div>
              <div class="page-title">FinTrak</div>
              <div class="kicker">Loading</div>
            </div>
          </div>
          <div class="auth-status-grid" aria-live="polite">
            <div class="auth-status-item">
              <span class="kicker">Service</span>
              <strong id="authRenderState">Checking</strong>
              <p id="authRenderMessage">Attempting to connect to the service...</p>
            </div>
            <div class="auth-status-item">
              <span class="kicker">Cache</span>
              <strong id="authCacheState">Checking</strong>
              <p id="authCacheMessage">Checking for cached login...</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Inline fallback status handler - keeps trying to load the real page
    const authRenderState = document.getElementById('authRenderState');
    const authRenderMessage = document.getElementById('authRenderMessage');
    const authCacheState = document.getElementById('authCacheState');
    const authCacheMessage = document.getElementById('authCacheMessage');

    function setWaiting() {
      authRenderState.textContent = 'Waking';
      authRenderMessage.textContent = 'Waiting for the service to respond.';
      checkCache();
    }

    function checkCache() {
      try {
        const cached = localStorage.getItem('fintrak_cached_auth');
        if (cached) {
          authCacheState.textContent = 'Available';
          authCacheMessage.textContent = 'Cached login is available in this browser.';
        } else {
          authCacheState.textContent = 'Not available';
          authCacheMessage.textContent = 'Enter username to check cached login.';
        }
      } catch (e) {
        authCacheState.textContent = 'Unknown';
        authCacheMessage.textContent = 'Could not check cache.';
      }
    }

    // Keep trying to fetch the real login page
    async function attemptReload() {
      try {
        const response = await fetch(window.location.href, { 
          cache: 'no-store',
          credentials: 'same-origin'
        });
        if (response.ok) {
          // Real page is now available, reload
          window.location.reload();
          return;
        }
      } catch (e) {
        // Still offline
      }
      
      authRenderState.textContent = 'Waking';
      authRenderMessage.textContent = 'Service not ready yet. Retrying in 3 seconds...';
      
      // Retry after 3 seconds
      setTimeout(attemptReload, 3000);
    }

    setWaiting();
    attemptReload();
  </script>
</body>
</html>`,
      { headers: { 'Content-Type': 'text/html; charset=utf-8' } },
    )
  );
}

self.addEventListener('install', (event) => {
  event.waitUntil(cacheShell().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== 'GET' || url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const timeout = new Promise((resolve) => {
        setTimeout(async () => resolve(await cachedFallback(request)), 2500);
      });
      const network = fetch(request)
        .then(async (response) => {
          if (!(await isValidAppNavigationResponse(response))) {
            throw new Error('Invalid app navigation response');
          }
          if (response.ok) {
            await cache.put(request, response.clone());
            if (url.pathname === '/' || url.pathname === '/login' || url.pathname === '/view-login') {
              await cache.put(url.pathname, response.clone());
            }
          }
          return response;
        })
        .catch(() => cachedFallback(request));
      return Promise.race([network, timeout]);
    })());
    return;
  }

  if (url.pathname.startsWith('/static/')) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(request);
      const network = fetch(request)
        .then(async (response) => {
          if (response.ok) await cache.put(request, response.clone());
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })());
  }
});
