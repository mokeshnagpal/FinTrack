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

    function setTheme(theme) {
        root.setAttribute('data-theme', theme);
        writeStorage(storageKey, theme);

        if (icon) {
            icon.textContent = theme === 'dark' ? 'Light' : 'Dark';
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
        const match = String(value).trim().match(
            /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2})(?::\d{2})?)?/,
        );
        if (!match) return null;
        return {
            year: Number(match[1]),
            month: Number(match[2]),
            day: Number(match[3]),
            hour: match[4] === undefined ? null : Number(match[4]),
            minute: match[5] === undefined ? null : Number(match[5]),
        };
    }

    function formatFriendlyDate(value) {
        const parts = parseDateParts(value);
        if (!parts) return value || '';

        const months = [
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december',
        ];
        const dateText = `${ordinal(parts.day)} ${months[parts.month - 1]} ${parts.year}`;

        if (parts.hour === null) return dateText;

        const suffix = parts.hour >= 12 ? 'pm' : 'am';
        const hour12 = parts.hour % 12 || 12;
        const minute = String(parts.minute).padStart(2, '0');
        return `${dateText} ${hour12}:${minute}${suffix}`;
    }

    window.FinTrak = window.FinTrak || {};
    window.FinTrak.formatFriendlyDate = formatFriendlyDate;

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
            el.textContent = formatFriendlyDate(raw);
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
        input.style.position = 'fixed';
        input.style.opacity = '0';
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

    function initConfirmForms() {
        document.querySelectorAll('form[data-confirm]').forEach((form) => {
            form.addEventListener('submit', async (event) => {
                if (form.dataset.confirmed === 'true') return;

                event.preventDefault();
                const confirmed = await confirmDialog(form.dataset.confirm || 'Are you sure?', 'Delete');
                if (!confirmed) return;

                form.dataset.confirmed = 'true';
                form.requestSubmit();
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

    function initCategorySelects() {
        document.querySelectorAll('select[name="category"]').forEach((select) => {
            if (select.dataset.enhancedCategory === 'true') return;
            select.dataset.enhancedCategory = 'true';
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
            chevron.textContent = 'v';
            button.append(buttonText, chevron);

            const panel = document.createElement('div');
            panel.className = 'category-select-panel';
            panel.hidden = true;

            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'category-select-search';
            search.placeholder = 'Search category';
            search.autocomplete = 'off';

            const list = document.createElement('div');
            list.className = 'category-select-list';
            list.setAttribute('role', 'listbox');

            const options = Array.from(select.options).map((option) => ({
                value: option.value,
                label: option.textContent.trim(),
            }));

            function currentLabel() {
                const selected = options.find((option) => option.value === select.value);
                return selected ? selected.label : 'Select category';
            }

            function closePanel() {
                panel.hidden = true;
                button.setAttribute('aria-expanded', 'false');
            }

            function openPanel() {
                panel.hidden = false;
                button.setAttribute('aria-expanded', 'true');
                search.value = '';
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
                    empty.textContent = 'No categories found';
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

            panel.append(search, list);
            wrapper.append(button, panel);
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
            document.body.style.overflow = 'hidden';
        });

        navMain.addEventListener('hide.bs.collapse', () => {
            backdrop.classList.remove('show');
            document.body.style.overflow = '';
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

    function initClientTableSorting() {
        document.querySelectorAll('table:not(.server-sorted)').forEach(table => {
            const headers = table.querySelectorAll('th.sortable-header');
            if (headers.length === 0) return;

            headers.forEach((header, index) => {
                header.style.cursor = 'pointer';
                
                let iconSpan = header.querySelector('.sort-icon');
                if (!iconSpan) {
                    iconSpan = document.createElement('span');
                    iconSpan.className = 'sort-icon';
                    iconSpan.innerHTML = ' &#8597;';
                    header.appendChild(iconSpan);
                }

                header.addEventListener('click', () => {
                    const currentDir = header.getAttribute('data-dir') || 'none';
                    const nextDir = currentDir === 'asc' ? 'desc' : 'asc';
                    
                    headers.forEach(h => {
                        h.removeAttribute('data-dir');
                        const hIcon = h.querySelector('.sort-icon');
                        if (hIcon) hIcon.innerHTML = ' &#8597;';
                        h.classList.remove('active');
                    });

                    header.setAttribute('data-dir', nextDir);
                    header.classList.add('active');
                    iconSpan.innerHTML = nextDir === 'asc' ? ' &uarr;' : ' &darr;';

                    sortRows(table, index, nextDir);
                });
            });
        });
    }

    function sortRows(table, colIndex, direction) {
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('tr'));
        if (rows.length <= 1 && (rows[0] && rows[0].querySelector('td[colspan]'))) return;

        let isDate = true;
        let isNum = true;
        
        const samples = rows.map(row => {
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

        rows.sort((a, b) => {
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

        rows.forEach(row => tbody.appendChild(row));
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
            return new Date(parts.year, parts.month - 1, parts.day, parts.hour || 0, parts.minute || 0);
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

    document.addEventListener('DOMContentLoaded', () => {
        formatDateElements();
        initCopyButtons();
        initConfirmForms();
        initPasswordToggles();
        initCategorySelects();
        initMobileNavbarDrawer();
        initClientTableSorting();
        initQueryParamModals();
        if (typeof bootstrap !== 'undefined') {
            const tooltipTriggers = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            tooltipTriggers.forEach((el) => new bootstrap.Tooltip(el));
        }
    });
}());
