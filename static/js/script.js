(function () {
    const root = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const icon = document.getElementById('themeIcon');

    const sunIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="theme-svg-icon"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>`;
    const moonIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="theme-svg-icon"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`;

    function setTheme(theme) {
        root.setAttribute('data-theme', theme);

        if (icon) {
            icon.innerHTML = theme === 'dark' ? sunIcon : moonIcon;
        }
        if (toggle) {
            toggle.setAttribute('aria-pressed', String(theme === 'dark'));
        }
    }

    const prefersDark = window.matchMedia
        && window.matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(prefersDark ? 'dark' : 'light');

    if (toggle) {
        toggle.addEventListener('click', () => {
            const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            setTheme(next);
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
        add_txn: 'Edited transaction',
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

    function showToast(title, type = 'info', message = '') {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container toast-container-elevated position-fixed top-0 end-0 p-3';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast text-bg-${type} border-0 shadow-sm mb-2`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        toast.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="toast-body">
                    <strong>${escapeHtml(title)}</strong>${message ? `<div class="small mt-1">${escapeHtml(message)}</div>` : ''}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto"
                    data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;

        container.appendChild(toast);
        if (typeof bootstrap !== 'undefined') {
            const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        } else {
            setTimeout(() => toast.remove(), 4000);
        }
        return toast;
    }

    window.FinTrak.showToast = showToast;
    window.showToast = showToast;

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

        table.dataset.unifiedInitialized = 'true';
        const pageSize = Number(table.dataset.pageSize || options.pageSize || 12);
        const itemsPerPage = Number.isFinite(pageSize) && pageSize > 0 ? pageSize : 12;

        const headers = table.querySelectorAll('th.sortable-header');
        headers.forEach((header, index) => {
            let iconSpan = header.querySelector('.sort-icon');
            if (!iconSpan) {
                iconSpan = document.createElement('span');
                iconSpan.className = 'sort-icon';
                header.appendChild(iconSpan);
            }
            if (!header.classList.contains('active')) {
                iconSpan.innerHTML = doubleArrowSvg;
            }

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
                renderPage(1);
            });
        });

        if (table.classList.contains('server-sorted') || table.classList.contains('ajax-sorted')) {
            table.refreshPagination = () => {};
            return;
        }

        const shell = table.closest('.table-shell') || table;
        let pagContainer = shell.querySelector('.table-pagination-controls');
        if (!pagContainer) {
            const existingPagination = document.getElementById('paginationContainer');
            if (existingPagination) {
                pagContainer = existingPagination;
                pagContainer.classList.add('table-pagination-controls');
                pagContainer.classList.remove('is-hidden');
                if (pagContainer.parentNode !== shell.parentNode || pagContainer.previousElementSibling !== shell) {
                    shell.parentNode.insertBefore(pagContainer, shell.nextSibling);
                }
            } else {
                pagContainer = document.createElement('div');
                pagContainer.className = 'table-pagination-controls';
                shell.parentNode.insertBefore(pagContainer, shell.nextSibling);
            }
        }
        pagContainer.classList.remove('is-hidden');
        pagContainer.innerHTML = '';

        function pageItems(currentPage, totalPages) {
            const pages = [];
            const add = (value) => {
                if (pages[pages.length - 1] !== value) pages.push(value);
            };

            add(1);
            const start = Math.max(2, currentPage - 1);
            const end = Math.min(totalPages - 1, currentPage + 1);
            if (start > 2) add('ellipsis-left');
            for (let pageNum = start; pageNum <= end; pageNum += 1) add(pageNum);
            if (end < totalPages - 1) add('ellipsis-right');
            if (totalPages > 1) add(totalPages);
            return pages;
        }

        function pageButton(label, page, disabled = false, active = false, extraClass = '') {
            const safeLabel = escapeHtmlText(label);
            return `
                <li class="page-item ${disabled ? 'disabled' : ''} ${active ? 'active' : ''} ${extraClass}">
                    <a class="page-link" href="#" data-page="${page}" aria-label="${safeLabel}">${safeLabel}</a>
                </li>
            `;
        }

        function renderPage(page) {
            const allRows = Array.from(tbody.querySelectorAll('tr'));
            const dataRows = allRows.filter(row => !row.querySelector('td[colspan]'));

            if (dataRows.length === 0) {
                pagContainer.classList.add('is-hidden');
                allRows.forEach(r => r.classList.remove('table-row-hidden'));
                return;
            }

            const totalRows = dataRows.length;
            const totalPages = Math.ceil(totalRows / itemsPerPage);
            const currentPage = Math.max(1, Math.min(page, totalPages));

            if (totalPages <= 1) {
                pagContainer.classList.add('is-hidden');
                allRows.forEach(r => r.classList.remove('table-row-hidden'));
                return;
            }

            pagContainer.classList.remove('is-hidden');

            const startIdx = (currentPage - 1) * itemsPerPage;
            const endIdx = startIdx + itemsPerPage;

            dataRows.forEach((row, idx) => {
                row.classList.toggle('table-row-hidden', !(idx >= startIdx && idx < endIdx));
            });

            const showingStart = startIdx + 1;
            const showingEnd = Math.min(endIdx, totalRows);
            const pageLinks = pageItems(currentPage, totalPages).map((item) => {
                if (String(item).startsWith('ellipsis')) {
                    return '<li class="page-item ellipsis"><span class="page-link">...</span></li>';
                }
                return pageButton(String(item), item, false, item === currentPage);
            }).join('');
            
            pagContainer.innerHTML = `
                <div class="table-pagination-summary text-muted small">Showing <strong>${showingStart}</strong>-<strong>${showingEnd}</strong> of <strong>${totalRows}</strong></div>
                <ul class="pagination pagination-sm mb-0">
                    ${pageButton('Prev', currentPage - 1, currentPage === 1, false, 'nav-btn')}
                    ${pageLinks}
                    ${pageButton('Next', currentPage + 1, currentPage === totalPages, false, 'nav-btn')}
                </ul>
            `;

            pagContainer.querySelectorAll('.page-link').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    if (link.closest('.disabled') || link.closest('.ellipsis')) return;
                    const targetPage = parseInt(link.getAttribute('data-page'));
                    if (!isNaN(targetPage) && targetPage !== currentPage) {
                        renderPage(targetPage);
                    }
                });
            });

            pagContainer.classList.remove('is-hidden');
        }

        table.refreshPagination = () => {
            pagContainer.classList.remove('is-hidden');
            renderPage(1);
        };

        renderPage(1);
    }

    window.FinTrak = window.FinTrak || {};
    window.FinTrak.initUnifiedTable = initUnifiedTable;

    function initClientTableSorting() {
        document.querySelectorAll('table:not(.server-sorted):not(.ajax-sorted)').forEach(table => {
            initUnifiedTable(table);
        });
    }

    function initServerTableSorting() {
        document.querySelectorAll('table.server-sorted').forEach(table => {
                const sortParam = table.getAttribute('data-sort-param') || 'sort';
                const dirParam = table.getAttribute('data-dir-param') || 'dir';
                const pageParam = table.getAttribute('data-page-param') || 'page';

                const params = new URLSearchParams(window.location.search);
                const currentSort = params.get(sortParam);
                const currentDir = params.get(dirParam);

                // Ensure client-side unified table behavior exists so we can sort/paginate in-memory
                initUnifiedTable(table);

                // Query headers after initUnifiedTable to avoid operating on detached nodes
                const headers = table.querySelectorAll('th.sortable-header');

                headers.forEach((header, colIndex) => {
                const colKey = header.getAttribute('data-sort-key');
                if (!colKey) return;

                header.style.cursor = 'pointer';

                let iconSpan = header.querySelector('.sort-icon');
                if (!iconSpan) {
                    iconSpan = document.createElement('span');
                    iconSpan.className = 'sort-icon';
                    header.appendChild(iconSpan);
                }

                // Initialize icon/state
                header.classList.remove('active');
                header.removeAttribute('data-dir');
                iconSpan.innerHTML = doubleArrowSvg;

                // Replace node to remove existing listeners
                const newHeader = header.cloneNode(true);
                header.parentNode.replaceChild(newHeader, header);

                newHeader.addEventListener('click', (e) => {
                    e.preventDefault();
                    const currentDir = newHeader.getAttribute('data-dir') || 'none';
                    const nextDir = currentDir === 'asc' ? 'desc' : 'asc';

                    // Reset other headers
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
                    if (freshIconSpan) freshIconSpan.innerHTML = nextDir === 'asc' ? upArrowSvg : downArrowSvg;

                    // Perform in-memory sort of visible rows (the table already contains the page-sized rows)
                    sortRows(table, colIndex, nextDir);
                    // Reset pagination to first page
                    if (typeof table.refreshPagination === 'function') table.refreshPagination();
                });
            });
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
        } else if (params.get('saved_edit') === 'true') {
            const editId = params.get('saved_edit_id');
            if (editId) {
                const escapedId = editId.replace(/ /g, '_').replace(/&/g, '_').replace(/\(/g, '_').replace(/\)/g, '_').replace(/\./g, '_').replace(/\//g, '_');
                const editModalEl = document.getElementById(`editSavedTransactionModal${escapedId}`);
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
            const participantInputs = form.querySelectorAll('input[name="people"]');
            if (!participantInputs.length) return;
            const action = String(form.getAttribute('action') || '').toLowerCase();
            
            if (action.includes('split')) {
                const checked = form.querySelectorAll('input[name="people"]:checked');
                if (checked.length === 0) {
                    event.preventDefault();
                    event.stopPropagation();
                    showFlash('At least 1 participant must be selected.', 'warning');
                    return false;
                }
            }
            
            if (action.includes('trip')) {
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

    // --- Transactions AJAX search and pagination (minimal, non-breaking) ---
    async function fetchJson(url, params = {}) {
        const q = new URLSearchParams(params).toString();
        const res = await fetch(url + (q ? `?${q}` : ''), { credentials: 'same-origin' });
        if (!res.ok) throw new Error('Request failed ' + res.status);
        return res.json();
    }

    async function postJson(url, payload = {}) {
        const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
        const headers = { 'Content-Type': 'application/json' };
        if (token) {
            headers['X-CSRFToken'] = token;
        }
        const res = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: headers,
            body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) throw new Error(data.error || 'Request failed ' + res.status);
        return data;
    }

    function getTransactionCategoryOptions(selectedValue = '') {
        const categorySelect = document.querySelector('#addTransactionModal select[name="category"], select[name="category"]');
        if (!categorySelect) return `<option value="${escapeHtml(selectedValue || 'Uncategorized')}">${escapeHtml(selectedValue || 'Uncategorized')}</option>`;
        return Array.from(categorySelect.options).map((option) => {
            const selected = String(option.value) === String(selectedValue) ? ' selected' : '';
            return `<option value="${escapeHtml(option.value)}"${selected}>${escapeHtml(option.textContent || option.value)}</option>`;
        }).join('');
    }

    function ensureAjaxTransactionEditModal() {
        let modal = document.getElementById('ajaxTransactionEditModal');
        if (modal) return modal;

        modal = document.createElement('div');
        modal.className = 'modal fade text-start';
        modal.id = 'ajaxTransactionEditModal';
        modal.tabIndex = -1;
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Edit Transaction</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form id="ajaxTransactionEditForm">
                            <input type="hidden" id="ajaxEditTxId">
                            <div class="mb-3">
                                <label class="form-label" for="ajaxEditTxAmount">Amount (Rs.)</label>
                                <input class="form-control" id="ajaxEditTxAmount" name="amount" type="number" step="0.01" min="0.01" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label" for="ajaxEditTxDescription">What was it for?</label>
                                <input class="form-control" id="ajaxEditTxDescription" name="description" maxlength="120" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label" for="ajaxEditTxCategory">Category</label>
                                <select class="form-select" id="ajaxEditTxCategory" name="category"></select>
                            </div>
                            <div class="row g-2">
                                <div class="col-sm-6">
                                    <label class="form-label" for="ajaxEditTxDate">Date (IST)</label>
                                    <input class="form-control" id="ajaxEditTxDate" name="date" type="date" required>
                                </div>
                                <div class="col-sm-6">
                                    <label class="form-label" for="ajaxEditTxTime">Time (IST)</label>
                                    <input class="form-control" id="ajaxEditTxTime" name="time" type="time" required>
                                </div>
                            </div>
                            <div class="mt-4">
                                <button class="btn btn-primary w-100" type="submit">Update Transaction</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        modal.querySelector('#ajaxTransactionEditForm').addEventListener('submit', async (event) => {
            event.preventDefault();
            const txId = modal.querySelector('#ajaxEditTxId').value;
            const payload = {
                amount: Number(modal.querySelector('#ajaxEditTxAmount').value),
                description: modal.querySelector('#ajaxEditTxDescription').value,
                category: modal.querySelector('#ajaxEditTxCategory').value,
                date: modal.querySelector('#ajaxEditTxDate').value,
                time: modal.querySelector('#ajaxEditTxTime').value,
            };

            try {
                await postJson(`/api/transactions/${encodeURIComponent(txId)}/update`, payload);
                bootstrap.Modal.getOrCreateInstance(modal).hide();
                showToast('Transaction updated', 'success');
                window.FinTrak.transactionsSearch?.fetchPage(1);
            } catch (error) {
                showToast('Update failed', 'danger', error.message);
            }
        });

        return modal;
    }

    async function openAjaxTransactionEdit(txId) {
        const modal = ensureAjaxTransactionEditModal();
        try {
            const result = await fetchJson(`/api/transactions/${encodeURIComponent(txId)}/view`);
            const txn = result.transaction || {};
            modal.querySelector('#ajaxEditTxId').value = txId;
            modal.querySelector('#ajaxEditTxAmount').value = txn.amount || '';
            modal.querySelector('#ajaxEditTxDescription').value = txn.description || '';
            modal.querySelector('#ajaxEditTxCategory').innerHTML = getTransactionCategoryOptions(txn.category || 'Uncategorized');
            modal.querySelector('#ajaxEditTxDate').value = txn.date || '';
            modal.querySelector('#ajaxEditTxTime').value = txn.time || '';
            bootstrap.Modal.getOrCreateInstance(modal).show();
        } catch (error) {
            showToast('Unable to load transaction', 'danger', error.message);
        }
    }

    async function deleteAjaxTransaction(txId) {
        const confirmed = await window.FinTrak.confirm('Delete this transaction?', 'Delete');
        if (!confirmed) return;
        try {
            await postJson(`/api/transactions/${encodeURIComponent(txId)}/delete`, {});
            showToast('Transaction deleted', 'danger');
            window.FinTrak.transactionsSearch?.fetchPage(1);
        } catch (error) {
            showToast('Delete failed', 'danger', error.message);
        }
    }

    function renderTransactionsRows(rows) {
        const table = document.getElementById('transactionsTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (!rows || rows.length === 0) {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td colspan="6" class="text-center text-muted py-4">No transactions found.</td>';
            tbody.appendChild(tr);
            return;
        }
        for (const r of rows) {
    const tr = document.createElement('tr');
    const canManage = document.body.dataset.viewOnly !== 'true';
    const isSplitTxn = Boolean(r.split_id);

    const codeValue = String(r.id || '');
    const splitUrl = String(
        r.split_url || (r.split_id ? `/splits/${encodeURIComponent(r.split_id)}` : '')
    );

    const modeBadge = isSplitTxn ? 'badge-split' : 'badge-add';
    const modeLabel = isSplitTxn ? 'Split' : 'Txn';

    let actions = '';

    if (isSplitTxn) {
        actions = `
            <div class="table-actions">
                <a class="btn btn-sm btn-outline-info" href="${escapeHtml(splitUrl)}">
                    View Split
                </a>
            </div>`;
    } else if (canManage) {
        actions = `
            <div class="table-actions">
                <button class="btn btn-sm btn-outline-primary ajax-txn-edit-btn"
                        type="button"
                        data-txn-id="${escapeHtml(r.id || '')}">
                    Edit
                </button>
                <button class="btn btn-sm btn-danger ajax-txn-delete-btn"
                        type="button"
                        data-txn-id="${escapeHtml(r.id || '')}">
                    Delete
                </button>
            </div>`;
    } else {
        actions = '<span class="badge">Read only</span>';
    }

    tr.innerHTML = `
        <td data-label="Date"><small data-format-date>${escapeHtml(r.timestamp || '')}</small></td>
        <td data-label="Mode"><span class="badge badge-compact ${modeBadge}">${modeLabel}</span></td>
        <td data-label="Description"><small>${escapeHtml(r.description || '')}</small></td>
        <td data-label="Category"><small>${escapeHtml(r.category || 'Uncategorized')}</small></td>
        <td data-label="Amount (Rs.)" class="text-end"><small>${Number(r.amount).toFixed(2)}</small></td>
        <td data-label="Actions" class="text-end">${actions}</td>
    `;

    tbody.appendChild(tr);
}
    }

    function renderSavedRows(rows) {
        const table = document.getElementById('savedTransactionsTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (!rows || rows.length === 0) {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td colspan="5" class="text-center text-muted py-4">No saved transactions found.</td>';
            tbody.appendChild(tr);
            return;
        }
        for (const r of rows) {
            const tr = document.createElement('tr');
            const codeValue = String(r.id || '');
            const actions = `<div class="table-actions">
                    <button class="btn btn-sm btn-outline-primary ajax-saved-edit-btn" type="button" data-template-id="${escapeHtml(r.id || '')}">Edit</button>
                    <button class="btn btn-sm btn-danger ajax-saved-delete-btn" type="button" data-template-id="${escapeHtml(r.id || '')}">Delete</button>
                    <button class="btn btn-sm btn-outline-success ajax-saved-submit-btn" type="button" data-template-id="${escapeHtml(r.id || '')}">Submit</button>
                  </div>`;
            tr.innerHTML = `
                <td data-label="Date saved"><small data-format-date>${escapeHtml(r.timestamp || '')}</small></td>
                <td data-label="Description"><small>${escapeHtml(r.description || '')}</small></td>
                <td data-label="Category"><small>${escapeHtml(r.category || 'Uncategorized')}</small></td>
                <td data-label="Amount (Rs.)" class="text-end"><small>${Number(r.amount).toFixed(2)}</small></td>
                <td data-label="Actions" class="text-end">${actions}</td>
            `;
            tbody.appendChild(tr);
        }
    }

    document.addEventListener('click', (event) => {
        const savedEditBtn = event.target.closest('.ajax-saved-edit-btn');
        if (savedEditBtn) {
            // For now open the server-side edit modal by navigating to transactions page with edit params
            const tid = savedEditBtn.dataset.templateId;
            const params = new URLSearchParams(window.location.search);
            params.set('saved_edit', 'true');
            params.set('saved_edit_id', tid);
            window.location.search = params.toString();
            return;
        }

        const savedDeleteBtn = event.target.closest('.ajax-saved-delete-btn');
        if (savedDeleteBtn) {
            deleteAjaxSaved(savedDeleteBtn.dataset.templateId);
            return;
        }

        const savedSubmitBtn = event.target.closest('.ajax-saved-submit-btn');
        if (savedSubmitBtn) {
            submitAjaxSaved(savedSubmitBtn.dataset.templateId);
            return;
        }

        const editBtn = event.target.closest('.ajax-txn-edit-btn');
        if (editBtn) {
            openAjaxTransactionEdit(editBtn.dataset.txnId);
            return;
        }

        const deleteBtn = event.target.closest('.ajax-txn-delete-btn');
        if (deleteBtn) {
            deleteAjaxTransaction(deleteBtn.dataset.txnId);
        }
    });

    function renderAjaxPagination(container, currentPage, totalPages) {
        if (!container) return;
        container.innerHTML = '';
        if (totalPages <= 1) return;
        const ul = document.createElement('ul');
        ul.className = 'pagination pagination-sm mb-0';

        function addButton(label, page, disabled, active) {
            const li = document.createElement('li');
            li.className = 'page-item ' + (disabled ? 'disabled' : '') + ' ' + (active ? 'active' : '');
            const btn = document.createElement('button');
            btn.className = 'page-link';
            btn.type = 'button';
            btn.dataset.page = String(page);
            btn.textContent = label;
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                if (disabled || active) return;
                const target = Number(btn.dataset.page);
                window.FinTrak.transactionsSearch && window.FinTrak.transactionsSearch.fetchPage(target);
            });
            li.appendChild(btn);
            ul.appendChild(li);
        }

        addButton('Prev', Math.max(1, currentPage - 1), currentPage === 1, false);
        const start = Math.max(1, currentPage - 2);
        const end = Math.min(totalPages, currentPage + 2);
        for (let p = start; p <= end; p++) addButton(String(p), p, false, p === currentPage);
        addButton('Next', Math.min(totalPages, currentPage + 1), currentPage === totalPages, false);

        container.appendChild(ul);
    }

    // Expose a small transactions search helper on the global FinTrak
    window.FinTrak = window.FinTrak || {};
    window.FinTrak.transactionsSearch = {
        lastQuery: '',
        lastTotal: 0,
        async search(query) {
            const serverContainer = document.getElementById('transactionsPaginationServer');
            const ajaxContainer = document.getElementById('transactionsPaginationAjax');
            try {
                const countRes = await fetchJson('/api/transactions/search/count', { query });
                const total = Number(countRes.totalRows || 0);
                this.lastQuery = query;
                this.lastTotal = total;
                const totalPages = Math.max(1, Math.ceil(total / 12));
                // show/hide pagination containers
                if (total > 0) {
                    if (serverContainer) serverContainer.classList.add('d-none');
                    if (ajaxContainer) ajaxContainer.classList.remove('d-none');
                    renderAjaxPagination(ajaxContainer, 1, totalPages);
                } else {
                    if (serverContainer) serverContainer.classList.remove('d-none');
                    if (ajaxContainer) ajaxContainer.classList.add('d-none');
                }
                // fetch first page
                await this.fetchPage(1);
            } catch (err) {
                console.error('Search error', err);
            }
        },
        async fetchPage(page) {
            const query = this.lastQuery || '';
            const ajaxContainer = document.getElementById('transactionsPaginationAjax');
            try {
                const res = await fetchJson('/api/transactions/search', { query, page, pageSize: 12 });
                const rows = res.rows || [];
                const total = Number(res.totalRows || 0);
                const totalPages = Math.max(1, Math.ceil(total / 12));
                renderTransactionsRows(rows);
                renderAjaxPagination(ajaxContainer, page, totalPages);
            } catch (err) {
                console.error('Page fetch error', err);
            }
        }
    };

    window.FinTrak.savedTransactions = {
        lastTotal: 0,
        lastPage: 1,
        async init() {
            try {
                const countRes = await fetchJson('/api/saved_transactions/count');
                const total = Number(countRes.totalRows || 0);
                this.lastTotal = total;
                const totalPages = Math.max(1, Math.ceil(total / 12));
                const serverContainer = document.getElementById('savedPaginationServer');
                const ajaxContainer = document.getElementById('savedPaginationAjax');
                if (total > 0) {
                    if (serverContainer) serverContainer.classList.add('d-none');
                    if (ajaxContainer) ajaxContainer.classList.remove('d-none');
                    renderAjaxPagination(ajaxContainer, 1, totalPages);
                } else {
                    if (serverContainer) serverContainer.classList.remove('d-none');
                    if (ajaxContainer) ajaxContainer.classList.add('d-none');
                }
                await this.fetchPage(1);
            } catch (err) {
                console.error('Saved transactions init error', err);
            }
        },
        async fetchPage(page) {
            try {
                const res = await fetchJson('/api/saved_transactions', { page, pageSize: 12 });
                const rows = res.rows || [];
                const total = Number(res.totalRows || 0);
                const totalPages = Math.max(1, Math.ceil(total / 12));
                renderSavedRows(rows);
                const ajaxContainer = document.getElementById('savedPaginationAjax');
                renderAjaxPagination(ajaxContainer, page, totalPages);
                this.lastPage = page;
            } catch (err) {
                console.error('Saved transactions page fetch error', err);
            }
        }
    };

    async function deleteAjaxSaved(templateId) {
        const confirmed = await window.FinTrak.confirm('Delete this saved template?', 'Delete');
        if (!confirmed) return;
        try {
            await postJson(`/api/saved_transactions/${encodeURIComponent(templateId)}/delete`, {});
            showToast('Saved template deleted', 'danger');
            window.FinTrak.savedTransactions.fetchPage(window.FinTrak.savedTransactions.lastPage || 1);
        } catch (error) {
            showToast('Delete failed', 'danger', error.message);
        }
    }

    async function submitAjaxSaved(templateId) {
        try {
            await postJson(`/api/saved_transactions/${encodeURIComponent(templateId)}/submit`, {});
            showToast('Saved template submitted', 'success');
            if (window.FinTrak?.transactionsSearch?.lastQuery && typeof window.FinTrak.transactionsSearch.fetchPage === 'function') {
                window.FinTrak.transactionsSearch.fetchPage(1);
            } else {
                window.location.reload();
            }
        } catch (error) {
            showToast('Submit failed', 'danger', error.message);
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        formatDateElements();
        initCopyButtons();
        initConfirmForms();
        initPasswordToggles();
        initCustomSelects();
        initModalFormDismiss();
        initMobileNavbarDrawer();
        initClientTableSorting();
        initServerTableSorting();
        initQueryParamModals();
        initParticipantChecklistValidation();
        autoDismissInlineAlerts();
        // Intercept add-transaction modal form and submit via API for immediate visibility
        try {
            const addModal = document.getElementById('addTransactionModal');
            if (addModal) {
                const addForm = addModal.querySelector('form');
                if (addForm) {
                    const submitBtn = addForm.querySelector('button[type="submit"]');
                    const requiredInputs = addForm.querySelectorAll('input[required]');

                    function toggleSubmitState() {
                        let allFilled = true;
                        requiredInputs.forEach(input => {
                            const val = input.value.trim();
                            if (!val) {
                                allFilled = false;
                            } else if (input.type === 'number') {
                                const num = parseFloat(val);
                                if (isNaN(num) || num <= 0) {
                                    allFilled = false;
                                }
                            }
                        });
                        if (submitBtn) {
                            submitBtn.disabled = !allFilled;
                        }
                    }

                    // Attach listeners
                    toggleSubmitState();
                    requiredInputs.forEach(input => {
                        input.addEventListener('input', toggleSubmitState);
                        input.addEventListener('change', toggleSubmitState);
                    });

                    addForm.addEventListener('reset', () => {
                        setTimeout(toggleSubmitState, 0);
                    });

                    addModal.addEventListener('shown.bs.modal', toggleSubmitState);

                    addForm.addEventListener('submit', async (ev) => {
                        ev.preventDefault();
                        const formData = new FormData(addForm);
                        const rawDate = String(formData.get('date') || '').trim();
                        const rawTime = String(formData.get('time') || '').trim();

                        // Fallback to local now if date/time not provided
                        const now = new Date();
                        const pad = (n) => String(n).padStart(2, '0');
                        const isoDate = rawDate || `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
                        const isoTime = rawTime || `${pad(now.getHours())}:${pad(now.getMinutes())}`;

                        const payload = {
                            amount: Number(String(formData.get('amount') || '').trim()) || 0,
                            description: String(formData.get('description') || '').trim(),
                            category: String(formData.get('category') || 'Uncategorized').trim() || 'Uncategorized',
                            date: isoDate,
                            time: isoTime,
                        };
                        try {
                            const res = await postJson('/api/transactions/create', payload);
                            showToast('Transaction added', 'success');
                            // Close modal
                            if (typeof bootstrap !== 'undefined') {
                                const bs = bootstrap.Modal.getOrCreateInstance(addModal);
                                bs.hide();
                            }
                            // Refresh transactions via AJAX helper if present and in search mode, else reload
                            if (window.FinTrak?.transactionsSearch?.lastQuery && typeof window.FinTrak.transactionsSearch.fetchPage === 'function') {
                                window.FinTrak.transactionsSearch.fetchPage(1);
                            } else {
                                window.location.reload();
                            }
                        } catch (err) {
                            showToast('Add failed', 'danger', err.message || String(err));
                        }
                    });
                }
            }
        } catch (e) {
            console.error('Init add-transaction API handler failed', e);
        }
        if (typeof bootstrap !== 'undefined') {
            const tooltipTriggers = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            tooltipTriggers.forEach((el) => new bootstrap.Tooltip(el));
        }
    });
}());
