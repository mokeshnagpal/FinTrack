(function () {
    const root = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const icon = document.getElementById('themeIcon');
    const saved = localStorage.getItem('spendtracker_theme');

    function setTheme(t) {
        root.setAttribute('data-theme', t);
        localStorage.setItem('spendtracker_theme', t);
        icon.textContent = t === 'dark' ? '☀️' : '🌙';
        toggle.setAttribute('aria-pressed', t === 'dark');
    }

    // initialize
    if (saved) setTheme(saved);
    else {
        // system preference fallback
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        setTheme(prefersDark ? 'dark' : 'light');
    }

    toggle.addEventListener('click', () => {
        const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        setTheme(next);
    });

    // enable bootstrap tooltips globally
    document.addEventListener('DOMContentLoaded', () => {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });
    });
}());