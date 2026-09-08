/**
 * Ninsho site — the only script on it.
 *
 * Two jobs: remember a theme choice, and mark the current page in the nav.
 * Deliberately dependency-free, matching the packages the site advertises.
 * The inline snippet in each page's <head> sets the theme before first paint
 * so there is no flash; this file only handles the toggle afterwards.
 */
(function () {
  'use strict';

  var root = document.documentElement;

  function stored() {
    try {
      return localStorage.getItem('ninsho-theme');
    } catch (e) {
      // Private windows and blocked site data both throw here. A page that
      // cannot remember a preference should still render correctly.
      return null;
    }
  }

  function apply(theme) {
    if (theme === 'dark' || theme === 'light') {
      root.setAttribute('data-theme', theme);
    } else {
      root.removeAttribute('data-theme');
    }
  }

  function current() {
    var explicit = root.getAttribute('data-theme');
    if (explicit) return explicit;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = current() === 'dark' ? 'light' : 'dark';
      apply(next);
      try {
        localStorage.setItem('ninsho-theme', next);
      } catch (e) {
        // The toggle still works for this page view; it just will not persist.
      }
      toggle.setAttribute(
        'aria-label',
        next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
      );
    });
  }

  // Mark the current page so the nav says where you are.
  var here = location.pathname.split('/').pop() || 'index.html';
  Array.prototype.forEach.call(document.querySelectorAll('.nav-link'), function (a) {
    var target = a.getAttribute('href');
    if (target === here || (here === 'index.html' && target === './')) {
      a.setAttribute('aria-current', 'page');
    }
  });

  // Copy buttons on install commands.
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        var was = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function () {
          btn.textContent = was;
        }, 1400);
      });
    });
  });

  void stored;
})();
