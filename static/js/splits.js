(function () {
  const limit = Number(window.FinTrakConstants?.split_entry_table_limit || 12);
  const refreshTimeoutMs = 8000;

  function formatNumber(value) {
    return Number(value || 0).toFixed(2);
  }

  function formatDate(value) {
    return window.FinTrak?.formatFriendlyDate ? window.FinTrak.formatFriendlyDate(value) : value;
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"'`=/]/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '`': '&#x60;',
      '=': '&#x3D;',
      '/': '&#x2F;',
    }[char]));
  }

  function showNotice(message, type = 'warning') {
    const notice = document.getElementById('splitOfflineNotice');
    if (!notice) return;
    notice.className = `alert alert-${type}`;
    notice.textContent = message;
  }

  function renderTotals(totals) {
    const target = document.getElementById('splitTotals');
    if (!target) return;
    const rows = Array.isArray(totals) ? totals : [];
    if (!rows.length) {
      target.innerHTML = '<div class="split-total-card split-total-empty"><span>No entries yet</span><strong>Rs. 0.00</strong></div>';
      return;
    }
    target.innerHTML = rows.map((item) => `
      <div class="split-total-card">
        <span>${escapeHtml(item.person || 'Unknown')}</span>
        <strong>Rs. ${formatNumber(item.amount)}</strong>
      </div>
    `).join('');
  }

  function renderEntries(entries, readOnly) {
    const body = document.getElementById('splitEntryBody');
    if (!body) return;
    const rows = Array.isArray(entries) ? entries.slice(0, limit) : [];
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No split entries found.</td></tr>';
      return;
    }
    body.innerHTML = rows.map((entry) => `
      <tr>
        <td data-label="When"><small>${escapeHtml(formatDate(entry.timestamp || ''))}</small></td>
        <td data-label="Person"><small>${escapeHtml(entry.person || '')}</small></td>
        <td data-label="For"><small>${escapeHtml(entry.description || '')}</small></td>
        <td data-label="Category"><small>${escapeHtml(entry.category || 'Uncategorized')}</small></td>
        <td data-label="Amount" class="text-end"><small>${formatNumber(entry.amount)}</small></td>
        <td data-label="Actions" class="text-end">
          <span class="badge">${readOnly ? 'Cached' : 'Reload'}</span>
        </td>
      </tr>
    `).join('');
  }

  function cachedLiveSplit(splitId) {
    const snapshot = window.FinTrak?.cache?.readSnapshot?.();
    const liveSplit = snapshot?.live_split;
    return liveSplit && String(liveSplit.id) === String(splitId) ? liveSplit : null;
  }

  async function refreshSplit() {
    const header = document.querySelector('.split-detail-header[data-split-id]');
    if (!header) return;
    const splitId = header.dataset.splitId;
    const isLive = header.dataset.splitLive === 'true';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), refreshTimeoutMs);

    try {
      const response = await fetch(`/api/splits/${encodeURIComponent(splitId)}/summary`, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error || `Split refresh failed (${response.status})`);
      }
      renderTotals(data.split?.totals || []);
      if (document.body.dataset.viewOnly === 'true') {
        renderEntries(data.split?.entries || [], true);
      }
      if (window.FinTrak?.cache?.refreshSnapshot) {
        window.FinTrak.cache.refreshSnapshot().catch(() => {});
      }
    } catch (error) {
      const liveSplit = isLive ? cachedLiveSplit(splitId) : null;
      if (liveSplit) {
        renderTotals(liveSplit.totals || []);
        renderEntries(liveSplit.entries || [], true);
        showNotice('Render is not awake. Showing cached live split values only.', 'warning');
        return;
      }
      showNotice('Render is not awake. This saved split needs the service online to show or edit current data.', 'warning');
    } finally {
      clearTimeout(timeout);
    }
  }

  document.addEventListener('DOMContentLoaded', refreshSplit);
}());
