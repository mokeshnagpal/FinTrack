(function () {
  const snapshotKey = 'fintrak_cache_snapshot_v1';
  const cacheTtlSeconds = Number(window.FinTrakConstants?.browser_cache_ttl_seconds || 10 * 24 * 60 * 60);
  const refreshTimeoutMs = Number(window.FinTrakConstants?.browser_cache_refresh_timeout_ms || 8000);
  const cacheTtlMs = cacheTtlSeconds * 1000;

  function readJSON(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function writeJSON(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (error) {
      return false;
    }
  }

  function snapshotAge(snapshot) {
    const cachedAt = snapshot && snapshot.cached_at ? new Date(snapshot.cached_at).getTime() : 0;
    return cachedAt ? Date.now() - cachedAt : Infinity;
  }

  function hasUsableSnapshot() {
    const snapshot = readJSON(snapshotKey);
    return Boolean(snapshot && snapshotAge(snapshot) <= cacheTtlMs);
  }

  function readSnapshot() {
    const snapshot = readJSON(snapshotKey);
    return snapshot && snapshotAge(snapshot) <= cacheTtlMs ? snapshot : null;
  }

  function writeSnapshot(snapshot) {
    if (!snapshot || snapshot.ok === false) return false;
    return writeJSON(snapshotKey, snapshot);
  }

  async function refreshSnapshot() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), refreshTimeoutMs);
    try {
      const response = await fetch('/api/cache_snapshot', {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error || `Cache snapshot failed (${response.status})`);
      }
      writeSnapshot(data);
      window.dispatchEvent(new CustomEvent('fintrak:cachechange', { detail: data }));
      return data;
    } finally {
      clearTimeout(timeout);
    }
  }

  window.FinTrak = window.FinTrak || {};
  window.FinTrak.cache = {
    hasUsableSnapshot,
    readSnapshot,
    refreshSnapshot,
    writeSnapshot,
  };
}());
