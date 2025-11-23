// flash.js — simple helper to auto-hide inline flash elements
(function () {
  // run after DOM ready
  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const flashes = document.querySelectorAll('.flash-inline, .flash-message');
    if (!flashes || flashes.length === 0) return;

    // Hide inline flashes after 3.5s with a small animation
    setTimeout(() => {
      flashes.forEach(el => {
        el.style.transition = 'opacity .4s, transform .4s';
        el.style.opacity = '0';
        el.style.transform = 'translateY(-6px)';
        setTimeout(() => el.remove(), 450);
      });
    }, 3500);
  });
})();
