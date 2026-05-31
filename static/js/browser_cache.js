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

  async function sha256(text) {
    if (!text) return '';
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const buffer = await crypto.subtle.digest('SHA-256', data);
    const array = Array.from(new Uint8Array(buffer));
    return array.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function commitCredentials() {
    try {
      const tempRaw = localStorage.getItem('fintrak_temp_auth');
      if (!tempRaw) return;
      const temp = JSON.parse(tempRaw);
      if (!temp || !temp.username || !temp.hash) return;

      const cachedRaw = localStorage.getItem('fintrak_cached_auth');
      let cached = cachedRaw ? JSON.parse(cachedRaw) : {};
      if (temp.type === 'view') {
        cached.view_username = temp.username;
        cached.view_password_hash = temp.hash;
      } else {
        cached.username = temp.username;
        cached.password_hash = temp.hash;
      }
      localStorage.setItem('fintrak_cached_auth', JSON.stringify(cached));
      localStorage.removeItem('fintrak_temp_auth');
    } catch (e) {
      console.warn('commitCredentials failed', e);
    }
  }

  window.FinTrak = window.FinTrak || {};
  window.FinTrak.cache = {
    hasUsableSnapshot,
    readSnapshot,
    refreshSnapshot,
    writeSnapshot,
    sha256,
    commitCredentials,
  };
}());
