(function () {
  function formatDateInput(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  function buildParams(elements) {
    const periodSelect = document.getElementById('periodSelect');
    const customPeriodSelect = document.getElementById('customPeriodSelect');
    const periodVal = (customPeriodSelect && customPeriodSelect.value) || (periodSelect && periodSelect.value) || 'daily';
    return {
      period: periodVal,
      count: 30,
      from: elements.fromDate.value || '',
      to: elements.toDate.value || '',
    };
  }

  function setRange(elements, range) {
    const today = new Date();
    const from = new Date(today);

    if (range === '90d') {
      from.setDate(today.getDate() - 89);
    } else if (range === '12m') {
      from.setMonth(today.getMonth() - 11);
      from.setDate(1);
    } else if (range === 'ytd') {
      from.setMonth(0, 1);
    } else {
      from.setDate(today.getDate() - 29);
    }

    elements.fromDate.value = formatDateInput(from);
    elements.toDate.value = formatDateInput(today);
  }

  function setStatus(statusEl, message = '', type = 'info') {
    if (!statusEl) return;
    statusEl.textContent = message;
    statusEl.className = message
      ? `analytics-status analytics-status-${type} mb-3`
      : 'analytics-status mb-3';
  }

  function clearPresetActive(elements) {
    elements.presets.forEach((item) => item.classList.remove('active'));
  }

  /**
   * Wire spend/balance analytics filters (presets, dates, period, apply).
   * @returns {{ buildParams: Function, setRange: Function }}
   */
  function init(elements, options = {}) {
    const {
      onRefresh,
      defaultRange = '30d',
      autoRefreshOnChange = true,
    } = options;

    setRange(elements, defaultRange);
    if (elements.presets[0]) {
      elements.presets[0].classList.add('active');
    }

    elements.presets.forEach((button) => {
      button.addEventListener('click', async () => {
        clearPresetActive(elements);
        button.classList.add('active');
        setRange(elements, button.dataset.range);
        if (onRefresh) await onRefresh();
      });
    });

    const periodSelect = document.getElementById('periodSelect');
    const customPeriodSelect = document.getElementById('customPeriodSelect');

    if (periodSelect && customPeriodSelect) {
      periodSelect.addEventListener('change', () => {
        if (customPeriodSelect.value !== periodSelect.value) {
          customPeriodSelect.value = periodSelect.value;
          customPeriodSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
      customPeriodSelect.addEventListener('change', () => {
        if (periodSelect.value !== customPeriodSelect.value) {
          periodSelect.value = customPeriodSelect.value;
          periodSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    }

    if (elements.applyBtn && onRefresh) {
      elements.applyBtn.addEventListener('click', onRefresh);
    }

    if (autoRefreshOnChange && onRefresh) {
      if (periodSelect) {
        periodSelect.addEventListener('change', onRefresh);
      }
      if (customPeriodSelect) {
        customPeriodSelect.addEventListener('change', onRefresh);
      }
      elements.fromDate.addEventListener('change', () => {
        clearPresetActive(elements);
        onRefresh();
      });
      elements.toDate.addEventListener('change', () => {
        clearPresetActive(elements);
        onRefresh();
      });
    }

    return {
      buildParams: () => buildParams(elements),
      setRange: (range) => setRange(elements, range),
    };
  }

  window.FinTrak = window.FinTrak || {};
  window.FinTrak.analyticsControls = {
    formatDateInput,
    buildParams,
    setRange,
    setStatus,
    init,
  };
}());
