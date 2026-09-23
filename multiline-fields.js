/* Visual enhancement only: never writes values, storage, permissions or data. */
(() => {
  'use strict';
  const states = new WeakMap();
  let queued = false;
  function fit(field) {
    if (!field.isConnected || field.getBoundingClientRect().width === 0) return;
    let state = states.get(field);
    const css = getComputedStyle(field);
    if (!state) {
      state = { minimum: parseFloat(css.minHeight) || 32, manual: parseFloat(field.style.height) || 0, width: 0 };
      states.set(field, state);
      observer?.observe(field);
    }
    const width = field.getBoundingClientRect().width;
    state.width = width;
    const border = (parseFloat(css.borderTopWidth) || 0) + (parseFloat(css.borderBottomWidth) || 0);
    field.style.height = 'auto';
    field.style.height = `${Math.ceil(Math.max(state.minimum, state.manual, field.scrollHeight + border))}px`;
  }
  function refresh() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      document.querySelectorAll('textarea').forEach(fit);
    });
  }
  const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(entries => {
    for (const { target } of entries) {
      if (target.getBoundingClientRect().width !== states.get(target)?.width) fit(target);
    }
  }) : null;
  function start() {
    refresh();
    document.addEventListener('input', event => {
      if (event.target instanceof HTMLTextAreaElement) fit(event.target);
      // Controlled React fields and surrounding content may update after input.
      refresh();
    }, true);
    document.addEventListener('change', refresh, true);
    document.addEventListener('click', refresh, true);
    window.addEventListener('resize', refresh);
    window.addEventListener('message', refresh);
    document.addEventListener('pointerdown', event => {
      const field = event.target;
      if (!(field instanceof HTMLTextAreaElement) || event.button !== 0) return;
      const rect = field.getBoundingClientRect();
      const edge = getComputedStyle(field).direction === 'rtl' ? rect.left : rect.right;
      if (Math.abs(event.clientX - edge) > 18 || rect.bottom - event.clientY > 18) return;
      const finish = () => {
        document.removeEventListener('pointerup', finish, true);
        document.removeEventListener('pointercancel', finish, true);
        const state = states.get(field);
        if (state) state.manual = field.getBoundingClientRect().height;
        refresh();
      };
      document.addEventListener('pointerup', finish, true);
      document.addEventListener('pointercancel', finish, true);
    }, true);
    new MutationObserver(records => {
      if (records.some(r => r.type === 'childList' || r.target.tagName !== 'TEXTAREA')) refresh();
    }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style', 'hidden', 'open'] });
  }
  // Native form controls can clip long values across printed pages. A text-only
  // mirror preserves all line breaks, without interpreting user content as HTML.
  function clearPrint() {
    document.querySelectorAll('.portal-print-text').forEach(node => node.remove());
    document.querySelectorAll('.portal-print-source').forEach(node => node.classList.remove('portal-print-source'));
  }
  window.addEventListener('beforeprint', () => {
    clearPrint();
    document.querySelectorAll('textarea').forEach(field => {
      const mirror = document.createElement('div');
      mirror.className = 'portal-print-text';
      mirror.textContent = field.value;
      field.after(mirror);
      field.classList.add('portal-print-source');
    });
  });
  window.addEventListener('afterprint', clearPrint);
  window.PortalMultiline = Object.freeze({ refresh });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
