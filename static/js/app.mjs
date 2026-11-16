import { t } from './i18n.mjs';
// Native forms, links, details, and dialog retain their browser behavior.
const navigation = document.querySelector('.mobile-navigation');
if (navigation) {
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && navigation.open) {
      navigation.open = false;
      navigation.querySelector('summary').focus();
    }
  });
  document.addEventListener('click', event => {
    if (navigation.open && !navigation.contains(event.target)) navigation.open = false;
  });
}

const dialog = document.querySelector('#confirm-dialog');
let pendingForm, pendingButton;
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', event => {
    if (form.dataset.confirmed === 'true') return;
    if (!dialog?.showModal) {
      if (!window.confirm(t("Move this document to deleted? You can restore it while it is retained."))) event.preventDefault();
      return;
    }
    event.preventDefault();
    pendingForm = form;
    pendingButton = event.submitter;
    dialog.showModal();
  });
});
document.querySelector('#confirm-cancel')?.addEventListener('click', () => dialog.close());
document.querySelector('#confirm-submit')?.addEventListener('click', () => {
  const form = pendingForm;
  const button = pendingButton;
  dialog.close();
  if (form) {
    form.dataset.confirmed = 'true';
    form.requestSubmit(button);
  }
});
dialog?.addEventListener('close', () => {
  pendingButton?.focus();
  pendingForm = undefined;
  pendingButton = undefined;
});
dialog?.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const buttons = [...dialog.querySelectorAll('button:not(:disabled)')];
  const first = buttons[0];
  const last = buttons.at(-1);
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});

document.querySelectorAll('form[data-progress]').forEach(form => {
  form.addEventListener('submit', event => {
    // The confirmation listener can cancel this submission first.
    if (event.defaultPrevented) return;
    const button = event.submitter;
    if (!button) return;
    button.setAttribute('aria-busy', 'true');
    button.dataset.originalText = button.textContent;
    button.textContent = form.dataset.progress || t("Saving…");
    button.disabled = true;
    form.setAttribute('aria-busy', 'true');
  });
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('button[data-original-text]').forEach(button => {
    button.textContent = button.dataset.originalText;
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.form?.removeAttribute('aria-busy');
    delete button.dataset.originalText;
  });
});

document.querySelectorAll('input[type="file"]').forEach(input => {
  input.accept = '.pdf,.jpg,.jpeg,.png,.webp';
});

// Password visibility toggle
const eyeSvg = '<svg class="icon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></svg>';
const eyeOffSvg = '<svg class="icon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" /><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" /><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" /><line x1="2" x2="22" y1="2" y2="22" /></svg>';

document.addEventListener('click', event => {
  const toggleBtn = event.target.closest('[data-password-toggle], .password-toggle-btn');
  if (!toggleBtn) return;
  event.preventDefault();

  const wrapper = toggleBtn.closest('.password-field-wrapper') || toggleBtn.parentElement;
  const input = wrapper?.querySelector('input');
  if (!input) return;

  const isPassword = input.type === 'password';
  const newType = isPassword ? 'text' : 'password';
  input.type = newType;
  input.setAttribute('type', newType);
  toggleBtn.setAttribute('aria-pressed', isPassword ? 'true' : 'false');

  const label = isPassword ? t('Hide password') : t('Show password');
  toggleBtn.setAttribute('aria-label', label);
  toggleBtn.setAttribute('title', label);
  input.focus();
});

function initPasswordToggles() {
  document.querySelectorAll('input[type="password"]').forEach(input => {
    if (input.closest('.password-field-wrapper')) {
      input.dataset.passwordToggleInit = 'true';
      return;
    }
    if (input.dataset.passwordToggleInit) return;
    input.dataset.passwordToggleInit = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'password-field-wrapper';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'password-toggle-btn';
    toggleBtn.dataset.passwordToggle = '';
    toggleBtn.setAttribute('aria-pressed', 'false');
    toggleBtn.setAttribute('aria-label', t('Show password'));
    toggleBtn.setAttribute('title', t('Show password'));
    toggleBtn.innerHTML = `<span class="icon-eye">${eyeSvg}</span><span class="icon-eye-off">${eyeOffSvg}</span>`;
    wrapper.appendChild(toggleBtn);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPasswordToggles);
} else {
  initPasswordToggles();
}

document.querySelector('.error-summary')?.focus();
