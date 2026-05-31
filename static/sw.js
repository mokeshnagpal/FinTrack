const CACHE_NAME = 'fintrak-shell-v1';
const NAVIGATION_FALLBACK = '/login';
const SHELL_URLS = [
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
      '<!doctype html><title>FinTrak</title><meta name="viewport" content="width=device-width,initial-scale=1"><h1>FinTrak</h1><p>The service is waking. Reopen this page after one successful online visit to use the cached login screen.</p>',
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
