(function () {
    const root = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const icon = document.getElementById('themeIcon');
    const storageKey = 'fintrak_theme';

    function readStorage(key) {
        try {
            return localStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function writeStorage(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (error) {
            // Theme preference is non-critical when browser storage is unavailable.
        }
    }

    const saved = readStorage(storageKey);

    const sunIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="theme-svg-icon"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`;
    const moonIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="theme-svg-icon"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`;

    function setTheme(theme) {
        root.setAttribute('data-theme', theme);
        writeStorage(storageKey, theme);

        if (icon) {
            icon.innerHTML = theme === 'dark' ? sunIcon : moonIcon;
        }
        if (toggle) {
            toggle.setAttribute('aria-pressed', String(theme === 'dark'));
        }
    }

    if (saved) {
        setTheme(saved);
    } else {
        const prefersDark = window.matchMedia
            && window.matchMedia('(prefers-color-scheme: dark)').matches;
        setTheme(prefersDark ? 'dark' : 'light');
    }

    if (toggle) {
        toggle.addEventListener('click', () => {
            const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            setTheme(next);
        });
    }

    function registerServiceWorker() {
        if (!('serviceWorker' in navigator)) return;
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js').catch((error) => {
                console.warn('FinTrak service worker registration failed', error);
            });
        });
    }

    function refreshSnapshotAfterAuthenticatedLoad() {
        const path = window.location.pathname;
        if (path === '/login' || path === '/view-login') return;
        window.FinTrak?.cache?.refreshSnapshot?.().catch((error) => {
            console.warn('FinTrak browser snapshot refresh failed after page load', error);
        });
    }

    function ordinal(day) {
        if (day > 10 && day < 20) return `${day}th`;
        const last = day % 10;
        if (last === 1) return `${day}st`;
        if (last === 2) return `${day}nd`;
        if (last === 3) return `${day}rd`;
        return `${day}th`;
    }

    function parseDateParts(value) {
        if (!value) return null;
        const raw = String(value).trim().toLowerCase();
        const match = raw.match(
            /^(\d{4})-(\d{2})(?:-(\d{2}))?(?:[ t](\d{1,2}):(\d{2})(?::\d{2})?)?/,
        );
        if (match) {
            return {
                year: Number(match[1]),
                month: Number(match[2]),
                day: match[3] === undefined ? null : Number(match[3]),
                hour: match[4] === undefined ? null : Number(match[4]),
                minute: match[5] === undefined ? null : Number(match[5]),
            };
        }

        const shortIsoMatch = raw.match(
            /^'?(?:20)?(\d{2})-(\d{2})-(\d{2})(?:[ t](\d{1,2}):(\d{2})(?::\d{2})?)?/,
        );
        if (shortIsoMatch) {
            return {
                year: 2000 + Number(shortIsoMatch[1]),
                month: Number(shortIsoMatch[2]),
                day: Number(shortIsoMatch[3]),
                hour: shortIsoMatch[4] === undefined ? null : Number(shortIsoMatch[4]),
                minute: shortIsoMatch[5] === undefined ? null : Number(shortIsoMatch[5]),
            };
        }

        const textMatch = raw.match(
            /^(\d{1,2})\s+([a-z]{3,9})\s+'?(\d{2,4})(?:\s+(\d{1,2}):(\d{2})(am|pm)?)?/,
        );
        if (textMatch) {
            const monthIndex = MONTH_NAMES.findIndex((name) => name.startsWith(textMatch[2].slice(0, 3)));
            if (monthIndex >= 0) {
                let hour = textMatch[4] === undefined ? null : Number(textMatch[4]);
                const minute = textMatch[5] === undefined ? null : Number(textMatch[5]);
                const suffix = textMatch[6] || '';
                if (hour !== null && suffix === 'pm' && hour < 12) hour += 12;
                if (hour !== null && suffix === 'am' && hour === 12) hour = 0;
                const yearText = textMatch[3];
                return {
                    year: yearText.length === 2 ? 2000 + Number(yearText) : Number(yearText),
                    month: monthIndex + 1,
                    day: Number(textMatch[1]),
                    hour,
                    minute,
                };
            }
        }

        return null;
    }

    const MONTH_NAMES = [
        'january', 'february', 'march', 'april', 'may', 'june',
        'july', 'august', 'september', 'october', 'november', 'december',
    ];

    function formatFriendlyDateParts(value) {
        const parts = parseDateParts(value);
        if (!parts) return null;

        const year2 = String(parts.year).slice(-2);
        const SHORT_MONTH_NAMES = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
        const dateText = parts.day === null
            ? `${SHORT_MONTH_NAMES[parts.month - 1]} '${year2}`
            : `${parts.day} ${SHORT_MONTH_NAMES[parts.month - 1]} '${year2}`;
        if (parts.hour === null) {
            return { date: dateText, time: '' };
        }

        const suffix = parts.hour >= 12 ? 'pm' : 'am';
        const hour12 = parts.hour % 12 || 12;
        const minute = String(parts.minute).padStart(2, '0');
        return { date: dateText, time: `${hour12}:${minute}${suffix}` };
    }

    function formatFriendlyDate(value) {
        const formatted = formatFriendlyDateParts(value);
        if (!formatted) return value || '';
        return formatted.time ? `${formatted.date} ${formatted.time}` : formatted.date;
    }

    function escapeHtmlText(value) {
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
        })[char]);
    }

    function formatFriendlyDateHtml(value) {
        const formatted = formatFriendlyDateParts(value);
        if (!formatted) return escapeHtmlText(value || '');
        if (!formatted.time) return escapeHtmlText(formatted.date);
        return `${escapeHtmlText(formatted.date)}<br><span class="table-date-time">${escapeHtmlText(formatted.time)}</span>`;
    }

    const BALANCE_NOTE_LABELS = {
        del_txn: 'Deleted transaction',
        edit_txn: 'Edited transaction',
        txn: 'Transaction',
        recurring: 'Recurring',
    };

  /** Strip UUID tails from system balance notes (e.g. del_txn:uuid:uuid → label only). */
    function formatBalanceNote(note) {
        const raw = String(note || '').trim();
        if (!raw) return '';

        const txnMarker = raw.search(/_txn:/i);
        if (txnMarker >= 0) {
            const key = raw.slice(0, txnMarker + 4).toLowerCase();
            return BALANCE_NOTE_LABELS[key] || key.replace(/_/g, ' ');
        }

        if (/^txn:/i.test(raw)) {
            return BALANCE_NOTE_LABELS.txn;
        }

        if (/^recurring:/i.test(raw)) {
            return BALANCE_NOTE_LABELS.recurring;
        }

        return raw;
    }

    window.FinTrak = window.FinTrak || {};
    window.FinTrak.formatFriendlyDate = formatFriendlyDate;
    window.FinTrak.formatFriendlyDateHtml = formatFriendlyDateHtml;
    window.FinTrak.formatBalanceNote = formatBalanceNote;

    function flashStack() {
        let stack = document.getElementById('flashStack');
        if (!stack) {
            stack = document.createElement('div');
            stack.id = 'flashStack';
            stack.className = 'flash-stack';
            document.body.appendChild(stack);
        }
        return stack;
    }

    function showFlash(message, type = 'info', delay = 3500) {
        const div = document.createElement('div');
        div.className = `flash-message ${type}`;
        div.textContent = message;
        flashStack().appendChild(div);
        setTimeout(() => {
            div.classList.add('flash-message-hide');
            setTimeout(() => div.remove(), 450);
        }, delay);
        return div;
    }

    window.FinTrak.showFlash = showFlash;

    function hideModal(fromElement) {
        if (typeof bootstrap === 'undefined') return;
        const modalEl = fromElement?.closest?.('.modal') || document.querySelector('.modal.show');
        if (!modalEl) return;
        const instance = bootstrap.Modal.getInstance(modalEl) || bootstrap.Modal.getOrCreateInstance(modalEl);
        instance.hide();
    }

    window.FinTrak.hideModal = hideModal;

    function initModalFormDismiss() {
        document.querySelectorAll('.modal form').forEach((form) => {
            if (form.dataset.offlineQueue) return;
            form.addEventListener('submit', () => {
                hideModal(form);
            });
        });
    }

    function confirmDialog(message, confirmLabel = 'Confirm') {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'confirm-modal';

            const content = document.createElement('div');
            content.className = 'confirm-content';

            const title = document.createElement('h5');
            title.className = 'fw-bold mb-2';
            title.textContent = message;

            const actions = document.createElement('div');
            actions.className = 'd-flex gap-2 justify-content-end mt-3';

            const cancelButton = document.createElement('button');
            cancelButton.type = 'button';
            cancelButton.className = 'btn btn-secondary btn-sm';
            cancelButton.textContent = 'Cancel';

            const confirmButton = document.createElement('button');
            confirmButton.type = 'button';
            confirmButton.className = 'btn btn-danger btn-sm';
            confirmButton.textContent = confirmLabel;

            function close(result) {
                modal.remove();
                resolve(result);
            }

            cancelButton.addEventListener('click', () => close(false));
            confirmButton.addEventListener('click', () => close(true));
            modal.addEventListener('click', (event) => {
                if (event.target === modal) close(false);
            });

            actions.append(cancelButton, confirmButton);
            content.append(title, actions);
            modal.appendChild(content);
            document.body.appendChild(modal);
            cancelButton.focus();
        });
    }

    window.FinTrak.confirm = confirmDialog;

    function formatDateElements() {
        document.querySelectorAll('[data-format-date]').forEach((el) => {
            const raw = el.getAttribute('datetime') || el.dataset.rawDate || el.textContent;
            const formatted = formatFriendlyDateParts(raw);
            el.classList.add('table-date-cell');
            if (!formatted) {
                el.textContent = raw;
                return;
            }
            el.innerHTML = formatFriendlyDateHtml(raw);
        });
    }

    async function copyText(value) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(value);
            return;
        }

        const input = document.createElement('textarea');
        input.value = value;
        input.setAttribute('readonly', '');
        input.className = 'copy-buffer';
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        input.remove();
    }

    function initCopyButtons() {
        document.querySelectorAll('[data-copy-secret]').forEach((button) => {
            button.addEventListener('click', async () => {
                const originalText = button.textContent;
                try {
                    await copyText(button.dataset.copySecret || '');
                    button.textContent = 'Copied';
                } catch (error) {
                    button.textContent = 'Copy failed';
                }
                setTimeout(() => {
                    button.textContent = originalText;
                }, 1800);
            });
        });
    }

    function showBootstrapConfirmModal(message, onConfirm) {
        let modalEl = document.getElementById('globalConfirmModal');
        if (!modalEl) {
            modalEl = document.createElement('div');
            modalEl.id = 'globalConfirmModal';
            modalEl.className = 'modal fade';
            modalEl.setAttribute('tabindex', '-1');
            modalEl.setAttribute('aria-hidden', 'true');
            modalEl.innerHTML = `
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content shadow-lg border-0">
                        <div class="modal-header modal-header-danger">
                            <h5 class="modal-title">Confirm Action</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body text-center py-4">
                            <p class="fw-semibold mb-2 modal-message-text fs-5"></p>
                            <p class="text-muted small mb-0">This action cannot be undone.</p>
                        </div>
                        <div class="modal-footer d-flex justify-content-center gap-2 pb-3">
                            <button type="button" class="btn btn-outline-secondary px-4" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-danger px-4 confirm-btn">Delete</button>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modalEl);
        }

        modalEl.querySelector('.modal-message-text').textContent = message;

        const confirmBtn = modalEl.querySelector('.confirm-btn');
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        const bsModal = new bootstrap.Modal(modalEl);

        newConfirmBtn.addEventListener('click', () => {
            bsModal.hide();
            onConfirm();
        });

        bsModal.show();
    }

    function initConfirmForms() {
        document.querySelectorAll('form[data-confirm]').forEach((form) => {
            form.addEventListener('submit', (event) => {
                if (form.dataset.confirmed === 'true') return;

                event.preventDefault();
                showBootstrapConfirmModal(form.dataset.confirm || 'Are you sure?', () => {
                    form.dataset.confirmed = 'true';
                    form.requestSubmit();
                });
            });
        });
    }

    function initPasswordToggles() {
        const visibleIcon = `
            <svg aria-hidden="true" viewBox="0 0 24 24" focusable="false">
                <path d="M2.1 12s3.6-6 9.9-6 9.9 6 9.9 6-3.6 6-9.9 6-9.9-6-9.9-6Z"></path>
                <circle cx="12" cy="12" r="3"></circle>
            </svg>
        `;
        const hiddenIcon = `
            <svg aria-hidden="true" viewBox="0 0 24 24" focusable="false">
                <path d="M2.1 12s3.6-6 9.9-6 9.9 6 9.9 6-3.6 6-9.9 6-9.9-6-9.9-6Z"></path>
                <circle cx="12" cy="12" r="3"></circle>
                <path d="M4 4l16 16"></path>
            </svg>
        `;

        document.querySelectorAll('input[type="password"]').forEach((input) => {
            if (input.closest('.password-toggle-wrap')) return;

            const wrapper = document.createElement('div');
            wrapper.className = 'password-toggle-wrap';
            input.parentNode.insertBefore(wrapper, input);
            wrapper.appendChild(input);

            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'password-toggle-btn';
            button.setAttribute('aria-label', 'Show password');
            button.innerHTML = visibleIcon;

            button.addEventListener('click', () => {
                const isHidden = input.type === 'password';
                input.type = isHidden ? 'text' : 'password';
                button.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
                button.innerHTML = isHidden ? hiddenIcon : visibleIcon;
            });

            wrapper.appendChild(button);
        });
    }

    function initCustomSelects() {
        document.querySelectorAll('select:not(.no-enhance)').forEach((select) => {
            if (select.dataset.enhancedSelect === 'true') return;
            select.dataset.enhancedSelect = 'true';
            select.classList.add('category-native-select');

            const wrapper = document.createElement('div');
            wrapper.className = 'category-select';
            select.parentNode.insertBefore(wrapper, select.nextSibling);

            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'category-select-button';
            button.setAttribute('aria-haspopup', 'listbox');
            button.setAttribute('aria-expanded', 'false');

            const buttonText = document.createElement('span');
            buttonText.className = 'category-select-current';
            const chevron = document.createElement('span');
            chevron.className = 'category-select-chevron';
            chevron.setAttribute('aria-hidden', 'true');
            chevron.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';
            button.append(buttonText, chevron);

            const panel = document.createElement('div');
            panel.className = 'category-select-panel';
            panel.hidden = true;

            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'category-select-search';
            
            const selectName = select.getAttribute('name') || 'option';
            const cleanName = selectName.replace(/_/g, ' ');
            const capitalizedName = cleanName.charAt(0).toUpperCase() + cleanName.slice(1);
            search.placeholder = `Search ${cleanName}`;
            search.autocomplete = 'off';

            const list = document.createElement('div');
            list.className = 'category-select-list';
            list.setAttribute('role', 'listbox');

            let options = [];

            function updateOptions() {
                options = Array.from(select.options).map((option) => ({
                    value: option.value,
                    label: option.textContent.trim(),
                }));
            }
            updateOptions();

            if (options.length <= 5) {
                search.style.display = 'none';
            }

            function currentLabel() {
                const selected = options.find((option) => option.value === select.value);
                return selected ? selected.label : `Select ${cleanName}`;
            }

            function closePanel() {
                panel.hidden = true;
                button.setAttribute('aria-expanded', 'false');
                chevron.classList.remove('is-open');
            }

            function openPanel() {
                panel.hidden = false;
                button.setAttribute('aria-expanded', 'true');
                chevron.classList.add('is-open');
                search.value = '';
                updateOptions();
                search.style.display = options.length <= 5 ? 'none' : 'block';
                renderOptions('');
                search.focus();
            }

            function choose(value) {
                select.value = value;
                select.dispatchEvent(new Event('change', { bubbles: true }));
                buttonText.textContent = currentLabel();
                closePanel();
                button.focus();
            }

            function renderOptions(filter) {
                const normalizedFilter = String(filter || '').trim().toLowerCase();
                const matches = options.filter((option) => option.label.toLowerCase().includes(normalizedFilter));
                list.textContent = '';

                if (matches.length === 0) {
                    const empty = document.createElement('div');
                    empty.className = 'category-select-empty';
                    empty.textContent = 'No options found';
                    list.appendChild(empty);
                    return;
                }

                matches.forEach((option) => {
                    const item = document.createElement('button');
                    item.type = 'button';
                    item.className = 'category-select-option';
                    item.setAttribute('role', 'option');
                    item.setAttribute('aria-selected', String(option.value === select.value));
                    item.textContent = option.label;
                    item.addEventListener('click', () => choose(option.value));
                    list.appendChild(item);
                });
            }

            buttonText.textContent = currentLabel();
            button.addEventListener('click', () => {
                if (panel.hidden) openPanel();
                else closePanel();
            });
            search.addEventListener('input', () => renderOptions(search.value));
            search.addEventListener('keydown', (event) => {
                const firstOption = list.querySelector('.category-select-option');
                if (event.key === 'Enter' && firstOption) {
                    event.preventDefault();
                    firstOption.click();
                }
                if (event.key === 'Escape') {
                    event.preventDefault();
                    closePanel();
                    button.focus();
                }
            });
            document.addEventListener('click', (event) => {
                if (!wrapper.contains(event.target)) closePanel();
            });

            select.addEventListener('change', () => {
                buttonText.textContent = currentLabel();
            });

            const observer = new MutationObserver(() => {
                updateOptions();
                search.style.display = options.length <= 5 ? 'none' : 'block';
                buttonText.textContent = currentLabel();
            });
            observer.observe(select, { childList: true });

            panel.append(search, list);
            wrapper.append(button, panel);

            const hostModal = select.closest('.modal');
            if (hostModal) {
                hostModal.addEventListener('hidden.bs.modal', closePanel);
            }
        });
    }

    function initMobileNavbarDrawer() {
        const navMain = document.getElementById('navMain');
        if (!navMain) return;

        let backdrop = document.querySelector('.navbar-menu-backdrop');
        if (!backdrop) {
            backdrop = document.createElement('div');
            backdrop.className = 'navbar-menu-backdrop';
            document.body.appendChild(backdrop);
        }

        navMain.addEventListener('show.bs.collapse', () => {
            backdrop.classList.add('show');
            document.body.classList.add('body-scroll-locked');
        });

        navMain.addEventListener('hide.bs.collapse', () => {
            backdrop.classList.remove('show');
            document.body.classList.remove('body-scroll-locked');
        });

        backdrop.addEventListener('click', () => {
            const bsCollapse = bootstrap.Collapse.getInstance(navMain);
            if (bsCollapse) {
                bsCollapse.hide();
            }
        });

        navMain.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                const bsCollapse = bootstrap.Collapse.getInstance(navMain);
                if (bsCollapse) {
                    bsCollapse.hide();
                }
            });
        });
    }

    // Premium SVG icons for sorting
    const doubleArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="ms-1 sort-svg-icon sort-svg-icon-muted"><path d="m7 15 5 5 5-5M7 9l5-5 5 5"/></svg>`;
    const upArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="ms-1 text-primary sort-svg-icon"><path d="m18 15-6-6-6 6"/></svg>`;
    const downArrowSvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="ms-1 text-primary sort-svg-icon"><path d="m6 9 6 6 6-6"/></svg>`;

    function initUnifiedTable(table, options = {}) {
        if (!table) return;

        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        // Mark as initialized
        table.dataset.unifiedInitialized = 'true';

        // 1. Client-Side Sorting Setup
        const headers = table.querySelectorAll('th.sortable-header');
        headers.forEach((header, index) => {
            let iconSpan = header.querySelector('.sort-icon');
            if (!iconSpan) {
                iconSpan = document.createElement('span');
                iconSpan.className = 'sort-icon';
                header.appendChild(iconSpan);
            }
            // Start with unsorted icon unless already set
            if (!header.classList.contains('active')) {
                iconSpan.innerHTML = doubleArrowSvg;
            }

            // Remove old listeners to avoid multiple triggers on re-init
            const newHeader = header.cloneNode(true);
            header.parentNode.replaceChild(newHeader, header);

            newHeader.addEventListener('click', () => {
                const currentDir = newHeader.getAttribute('data-dir') || 'none';
                const nextDir = currentDir === 'asc' ? 'desc' : 'asc';

                // Reset all headers
                const freshHeaders = table.querySelectorAll('th.sortable-header');
                freshHeaders.forEach(h => {
                    h.removeAttribute('data-dir');
                    h.classList.remove('active');
                    const hIcon = h.querySelector('.sort-icon');
                    if (hIcon) hIcon.innerHTML = doubleArrowSvg;
                });

                newHeader.setAttribute('data-dir', nextDir);
                newHeader.classList.add('active');
                const freshIconSpan = newHeader.querySelector('.sort-icon');
                if (freshIconSpan) {
                    freshIconSpan.innerHTML = nextDir === 'asc' ? upArrowSvg : downArrowSvg;
                }

                sortRows(table, index, nextDir);
                // Reset page to 1 after sorting
                currentPage = 1;
                renderPage(1);
            });
        });

        // 2. Client-Side Pagination Setup
        const itemsPerPage = options.pageSize || 10;
        let currentPage = 1;

        // Dynamic pagination container
        let pagContainer = table.nextElementSibling;
        if (pagContainer && pagContainer.classList.contains('table-pagination-controls')) {
            pagContainer.innerHTML = '';
        } else {
            pagContainer = document.createElement('div');
            pagContainer.className = 'd-flex justify-content-between align-items-center mt-3 flex-wrap gap-2 table-pagination-controls';
            
            // Insert after table-shell if inside one, else after table itself
            const shell = table.closest('.table-shell') || table;
            shell.parentNode.insertBefore(pagContainer, shell.nextSibling);
        }

        function renderPage(page) {
            const allRows = Array.from(tbody.querySelectorAll('tr'));
            // Filter out empty state row
            const dataRows = allRows.filter(row => !row.querySelector('td[colspan]'));

            if (dataRows.length === 0) {
                pagContainer.classList.add('is-hidden');
                return;
            }

            const totalRows = dataRows.length;
            const totalPages = Math.ceil(totalRows / itemsPerPage);

            if (totalPages <= 1) {
                pagContainer.classList.add('is-hidden');
                // Show all rows
                allRows.forEach(r => r.classList.remove('table-row-hidden'));
                return;
            }

            pagContainer.classList.remove('is-hidden');
            currentPage = Math.max(1, Math.min(page, totalPages));

            const startIdx = (currentPage - 1) * itemsPerPage;
            const endIdx = startIdx + itemsPerPage;

            // Hide/Show appropriate rows
            dataRows.forEach((row, idx) => {
                row.classList.toggle('table-row-hidden', !(idx >= startIdx && idx < endIdx));
            });

            // Rebuild controls content
            const showingStart = startIdx + 1;
            const showingEnd = Math.min(endIdx, totalRows);
            
            pagContainer.innerHTML = `
                <div class="text-muted small">Showing <strong>${showingStart}</strong> to <strong>${showingEnd}</strong> of <strong>${totalRows}</strong> entries</div>
                <ul class="pagination pagination-sm mb-0">
                    <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                        <a class="page-link" href="#" data-page="${currentPage - 1}">Previous</a>
                    </li>
                    ${Array.from({ length: totalPages }, (_, i) => i + 1).map(p => `
                        <li class="page-item ${currentPage === p ? 'active' : ''}">
                            <a class="page-link" href="#" data-page="${p}">${p}</a>
                        </li>
                    `).join('')}
                    <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                        <a class="page-link" href="#" data-page="${currentPage + 1}">Next</a>
                    </li>
                </ul>
            `;

            // Bind click handlers to pagination links
            pagContainer.querySelectorAll('.page-link').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const targetPage = parseInt(link.getAttribute('data-page'));
                    if (!isNaN(targetPage) && targetPage !== currentPage) {
                        renderPage(targetPage);
                    }
                });
            });
        }

        // Expose a quick trigger to re-paginate dynamically
        table.refreshPagination = () => {
            renderPage(currentPage);
        };

        // Initial render
        renderPage(1);
    }

    window.FinTrak = window.FinTrak || {};
    window.FinTrak.initUnifiedTable = initUnifiedTable;

    function initClientTableSorting() {
        document.querySelectorAll('table:not(.server-sorted)').forEach(table => {
            initUnifiedTable(table);
        });
    }

    function sortRows(table, colIndex, direction) {
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('tr'));
        // Exclude empty state rows
        const dataRows = rows.filter(row => !row.querySelector('td[colspan]'));
        if (dataRows.length <= 1) return;

        let isDate = true;
        let isNum = true;
        
        const samples = dataRows.map(row => {
            const td = row.children[colIndex];
            if (!td) return '';
            const dateEl = td.querySelector('[data-format-date], [datetime]');
            if (dateEl) {
                return dateEl.getAttribute('datetime') || dateEl.getAttribute('data-raw-date') || dateEl.textContent.trim();
            }
            return td.textContent.trim();
        }).filter(val => val !== '');

        if (samples.length === 0) return;

        samples.forEach(val => {
            const cleaned = val.replace(/[^\d.-]/g, '');
            if (isNaN(parseFloat(cleaned)) || !isFinite(cleaned)) {
                isNum = false;
            }
            const dateParts = parseDateParts(val);
            if (!dateParts && isNaN(Date.parse(val))) {
                isDate = false;
            }
        });

        dataRows.sort((a, b) => {
            let valA = getCellValue(a.children[colIndex]);
            let valB = getCellValue(b.children[colIndex]);

            if (isNum) {
                const numA = parseFloat(valA.replace(/[^\d.-]/g, '')) || 0;
                const numB = parseFloat(valB.replace(/[^\d.-]/g, '')) || 0;
                return direction === 'asc' ? numA - numB : numB - numA;
            } else if (isDate) {
                const dateA = parseDateOrValue(valA);
                const dateB = parseDateOrValue(valB);
                return direction === 'asc' ? dateA - dateB : dateB - dateA;
            } else {
                return direction === 'asc' 
                    ? valA.localeCompare(valB, undefined, { numeric: true, sensitivity: 'base' })
                    : valB.localeCompare(valA, undefined, { numeric: true, sensitivity: 'base' });
            }
        });

        dataRows.forEach(row => tbody.appendChild(row));
    }

    function getCellValue(td) {
        if (!td) return '';
        const dateEl = td.querySelector('[data-format-date], [datetime]');
        if (dateEl) {
            return dateEl.getAttribute('datetime') || dateEl.getAttribute('data-raw-date') || dateEl.textContent.trim();
        }
        return td.textContent.trim();
    }

    function parseDateOrValue(val) {
        const parts = parseDateParts(val);
        if (parts) {
            return new Date(parts.year, parts.month - 1, parts.day || 1, parts.hour || 0, parts.minute || 0);
        }
        const parsed = Date.parse(val);
        return isNaN(parsed) ? new Date(0) : new Date(parsed);
    }

    function initQueryParamModals() {
        const params = new URLSearchParams(window.location.search);
        if (params.get('add') === 'true') {
            const addModalEl = document.getElementById('newExpenseModal') || document.querySelector('[id*="addModal"], [id*="newSplitModal"], [id*="addCategoryModal"], [id*="addPersonModal"], [id*="addTransactionModal"]');
            if (addModalEl && typeof bootstrap !== 'undefined') {
                const modal = new bootstrap.Modal(addModalEl);
                modal.show();
            }
        } else if (params.get('add_balance') === 'true') {
            const addModalEl = document.getElementById('newBalanceModal');
            if (addModalEl && typeof bootstrap !== 'undefined') {
                const modal = new bootstrap.Modal(addModalEl);
                modal.show();
            }
        } else if (params.get('add_category') === 'true') {
            const addModalEl = document.getElementById('addCategoryModal');
            if (addModalEl && typeof bootstrap !== 'undefined') {
                const modal = new bootstrap.Modal(addModalEl);
                modal.show();
            }
        } else if (params.get('add_person') === 'true') {
            const addModalEl = document.getElementById('addPersonModal');
            if (addModalEl && typeof bootstrap !== 'undefined') {
                const modal = new bootstrap.Modal(addModalEl);
                modal.show();
            }
        } else if (params.get('edit') === 'true') {
            const editId = params.get('edit_id');
            if (editId) {
                const escapedId = editId.replace(/ /g, '_').replace(/&/g, '_').replace(/\(/g, '_').replace(/\)/g, '_').replace(/\./g, '_').replace(/\//g, '_');
                const editModalEl = document.getElementById(`editTransactionModal${escapedId}`) 
                    || document.getElementById(`editSplitModal${escapedId}`)
                    || document.getElementById(`editEntryModal${escapedId}`)
                    || document.getElementById(`editExpenseModal${escapedId}`)
                    || document.getElementById(`editCategoryModal${escapedId}`);
                if (editModalEl && typeof bootstrap !== 'undefined') {
                    const modal = new bootstrap.Modal(editModalEl);
                    modal.show();
                }
            }
        } else if (params.get('edit_balance') === 'true') {
            const editId = params.get('edit_id');
            if (editId) {
                const editModalEl = document.getElementById(`editBalanceModal${editId}`);
                if (editModalEl && typeof bootstrap !== 'undefined') {
                    const modal = new bootstrap.Modal(editModalEl);
                    modal.show();
                }
            }
        } else if (params.get('edit_person') === 'true') {
            const editId = params.get('edit_id');
            if (editId) {
                const escapedId = editId.replace(/ /g, '_').replace(/&/g, '_').replace(/\(/g, '_').replace(/\)/g, '_').replace(/\./g, '_').replace(/\//g, '_');
                const editModalEl = document.getElementById(`editPersonModal${escapedId}`);
                if (editModalEl && typeof bootstrap !== 'undefined') {
                    const modal = new bootstrap.Modal(editModalEl);
                    modal.show();
                }
            }
        }
    }

    function initParticipantChecklistValidation() {
        document.addEventListener('submit', (event) => {
            const form = event.target;
            const queueType = form.dataset.offlineQueue;
            
            if (queueType === 'split-create' || queueType === 'split-edit') {
                const checked = form.querySelectorAll('input[name="people"]:checked');
                if (checked.length === 0) {
                    event.preventDefault();
                    event.stopPropagation();
                    showFlash('At least 1 participant must be selected.', 'warning');
                    return false;
                }
            }
            
            if (queueType === 'trip-create' || queueType === 'trip-edit') {
                const costTypeSelect = form.querySelector('[name="cost_type"]');
                if (costTypeSelect && costTypeSelect.value === 'split') {
                    const checked = form.querySelectorAll('input[name="people"]:checked');
                    if (checked.length === 0) {
                        event.preventDefault();
                        event.stopPropagation();
                        showFlash('At least 1 participant must be selected for the Split Account.', 'warning');
                        return false;
                    }
                }
            }
        }, true);
    }

    function autoDismissInlineAlerts() {
        document.querySelectorAll('.flash-inline').forEach((alert) => {
            setTimeout(() => {
                alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-10px)';
                setTimeout(() => alert.remove(), 450);
            }, 4000);
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        registerServiceWorker();
        window.FinTrak?.cache?.commitCredentials?.();
        refreshSnapshotAfterAuthenticatedLoad();
        formatDateElements();
        initCopyButtons();
        initConfirmForms();
        initPasswordToggles();
        initCustomSelects();
        initModalFormDismiss();
        initMobileNavbarDrawer();
        initClientTableSorting();
        initQueryParamModals();
        initParticipantChecklistValidation();
        autoDismissInlineAlerts();
        if (typeof bootstrap !== 'undefined') {
            const tooltipTriggers = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            tooltipTriggers.forEach((el) => new bootstrap.Tooltip(el));
        }
    });
}());
