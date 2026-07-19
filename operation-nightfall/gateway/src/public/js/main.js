/**
 * NovaCorp DevPortal — Client-side JavaScript
 * Adds subtle interactivity and polish to the portal.
 */

(function () {
  'use strict';

  // --- Smooth scroll for anchor links ---
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      var target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // --- Animate elements on scroll ---
  var observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px',
  };

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  document.querySelectorAll('.feature-card, .stat-item, .status-card, .timeline-item').forEach(function (el) {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    observer.observe(el);
  });

  // Add visible class styles
  var style = document.createElement('style');
  style.textContent = '.visible { opacity: 1 !important; transform: translateY(0) !important; }';
  document.head.appendChild(style);

  // --- Status page: auto-refresh countdown ---
  var statusPage = document.querySelector('.status-page');
  if (statusPage) {
    var countdown = 60;
    var refreshNotice = document.createElement('div');
    refreshNotice.style.cssText =
      'position:fixed;bottom:20px;right:20px;background:rgba(17,24,39,0.9);' +
      'border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:10px 16px;' +
      'font-size:0.75rem;color:#94a3b8;backdrop-filter:blur(10px);z-index:50;';
    refreshNotice.textContent = 'Auto-refresh in ' + countdown + 's';
    document.body.appendChild(refreshNotice);

    var timer = setInterval(function () {
      countdown--;
      if (countdown <= 0) {
        clearInterval(timer);
        window.location.reload();
      } else {
        refreshNotice.textContent = 'Auto-refresh in ' + countdown + 's';
      }
    }, 1000);
  }

  // --- Login form: subtle input animation ---
  document.querySelectorAll('.form-group input').forEach(function (input) {
    input.addEventListener('focus', function () {
      this.parentElement.querySelector('label').style.color = '#6366f1';
    });
    input.addEventListener('blur', function () {
      this.parentElement.querySelector('label').style.color = '';
    });
  });

  // --- Console easter egg (hint for observant players) ---
  console.log(
    '%c🌑 NovaCorp DevPortal v3.2.1-rc4',
    'color: #6366f1; font-size: 14px; font-weight: bold;'
  );
  console.log(
    '%cInternal platform — Unauthorized access is monitored and logged.',
    'color: #64748b; font-size: 11px;'
  );
  console.log(
    '%c💡 Tip: Check /status for real-time service health metrics',
    'color: #38bdf8; font-size: 11px;'
  );
})();
