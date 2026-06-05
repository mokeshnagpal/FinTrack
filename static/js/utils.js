// utils.js — Shared utility functions across FinTrak
// Prevents code duplication and ensures consistency

(function () {
  window.FinTrak = window.FinTrak || {};

  /**
   * Escapes HTML special characters to prevent XSS
   * Used everywhere for sanitizing user-supplied content
   */
  window.FinTrak.escapeHtml = function (value) {
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
  };

  /**
   * Formats a number to 2 decimal places
   * Used for currency and amount displays
   */
  window.FinTrak.formatNumber = function (value) {
    return Number(value || 0).toFixed(2);
  };

  /**
   * Formats currency in Indian Rupees
   * Used in balance and split displays
   */
  window.FinTrak.rupee = function (amount) {
    return 'Rs. ' + window.FinTrak.formatNumber(amount);
  };

  /**
   * Safe console logging that checks for console availability
   * Prevents errors in environments without console
   */
  window.FinTrak.log = function (message, type = 'log') {
    if (typeof console !== 'undefined' && console[type]) {
      console[type](message);
    }
  };

  /**
   * Checks if a value is empty or whitespace
   */
  window.FinTrak.isEmpty = function (value) {
    return !value || String(value).trim() === '';
  };

  /**
   * Deep clones an object
   * Used for creating independent copies of data
   */
  window.FinTrak.deepClone = function (obj) {
    return JSON.parse(JSON.stringify(obj));
  };

  /**
   * Safely gets nested property from object
   * Returns default value if property doesn't exist
   * Example: safeGet(obj, 'user.profile.name', 'Unknown')
   */
  window.FinTrak.safeGet = function (obj, path, defaultValue = undefined) {
    try {
      const value = path.split('.').reduce((current, prop) => current?.[prop], obj);
      return value !== undefined ? value : defaultValue;
    } catch (e) {
      return defaultValue;
    }
  };
  /**
   * Unified JSON fetch with automatic CSRF token handling
   * Supports both GET with params and POST with request body
   * @param {string} url - API endpoint
   * @param {Object} params - Query parameters (for GET)
   * @param {Object} opts - Fetch options (method, headers, body, etc.)
   * @returns {Promise<Object>} Parsed JSON response
   */
  /**
   * Builds pagination window items (1, 2, 3, ..., n) always including the last page.
   */
  window.FinTrak.buildPageItems = function (currentPage, totalPages) {
    const total = Math.max(0, Number(totalPages) || 0);
    const current = Math.max(1, Math.min(Number(currentPage) || 1, total || 1));
    if (total <= 0) return [];
    if (total === 1) return [1];
    if (total <= 5) {
      return Array.from({ length: total }, (_, index) => index + 1);
    }
    if (current <= 3) {
      return [1, 2, 3, '...', total];
    }
    if (current >= total - 2) {
      return [1, '...', total - 2, total - 1, total];
    }
    return [1, '...', current - 1, current, current + 1, '...', total];
  };

  window.FinTrak.fetchJSON = async function (url, params = {}, opts = {}) {
    const query = new URLSearchParams(params).toString();
    const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    const headers = { ...(opts.headers || {}) };

    if (opts.method && opts.method.toUpperCase() !== 'GET' && token) {
      headers['X-CSRFToken'] = token;
    }

    const response = await fetch(url + (query ? `?${query}` : ''), { ...opts, headers });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.error || `Request failed (${response.status})`);
    }
    return data;
  };
})();
