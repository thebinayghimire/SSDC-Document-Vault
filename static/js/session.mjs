// Mitigates token leakage via localStorage and DOM while preserving cross-tab session termination and account-switch detection
const metadata = document.querySelector('meta[name="vault-session"]');
const currentTag = metadata?.dataset?.accountTag || '';
let checking = false;

// BroadcastChannel carries only non-sensitive event names; no tokens or tags are ever broadcast or stored
const authChannel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('ssdc-vault-session') : null;

async function checkSession() {
  if (!currentTag || checking) return;
  checking = true;
  try {
    const response = await fetch(metadata.dataset.statusUrl, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error('Session check unavailable');
    const session = await response.json();
    if (!session.authenticated || session.account_tag !== currentTag) {
      document.documentElement.hidden = true;
      location.replace(session.home_url || metadata.dataset.loginUrl);
      return;
    }
    document.documentElement.hidden = false;
  } catch {
    // A restored page stays hidden until the server can authorize it again.
    if (document.documentElement.hidden) location.reload();
  } finally {
    checking = false;
  }
}

if (metadata) {
  if (authChannel) {
    authChannel.addEventListener('message', event => {
      if (event.data === 'session_changed') {
        if (currentTag) {
          document.documentElement.hidden = true;
          checkSession();
        }
      }
    });
  }

  // Notify other tabs on navigation or state transitions
  try {
    authChannel?.postMessage('session_changed');
  } catch {
    // Ignore environments where broadcast is restricted
  }

  // Intercept sign-out to notify other tabs across the origin immediately
  document.addEventListener('submit', event => {
    const form = event.target;
    if (form && form.action && form.action.includes('/logout/')) {
      try {
        authChannel?.postMessage('session_changed');
      } catch {
        // BroadcastChannel failure should not prevent form submission
      }
    }
  });

  if (currentTag) {
    window.addEventListener('pagehide', () => {
      document.documentElement.hidden = true;
    });
    window.addEventListener('pageshow', event => {
      if (event.persisted) checkSession();
    });
    window.addEventListener('focus', checkSession);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') checkSession();
    });
  }
}
