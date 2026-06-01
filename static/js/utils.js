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

})();
