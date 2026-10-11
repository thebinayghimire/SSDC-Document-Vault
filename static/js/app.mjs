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
      if (!window.confirm('Move this document to deleted? You can restore it while it is retained.')) event.preventDefault();
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
    button.textContent = form.dataset.progress || 'Saving…';
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
document.querySelector('.error-summary')?.focus();
