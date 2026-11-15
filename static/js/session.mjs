// The server authorizes every request. This also clears stale account screens
// when a different tab signs out or signs in as someone else.
const metadata = document.querySelector('meta[name="vault-session"]');
const marker = metadata?.content || '';
const storageKey = 'ssdc-vault-session';
let checking = false;

async function checkSession() {
  if (!marker || checking) return;
  checking = true;
  try {
    const response = await fetch(metadata.dataset.statusUrl, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error('Session check unavailable');
    const session = await response.json();
    if (!session.authenticated || session.marker !== marker) {
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
  try {
    localStorage.setItem(storageKey, marker);
  } catch {
    // Focus and history checks still work when browser storage is unavailable.
  }
  if (marker) {
    window.addEventListener('storage', event => {
      if (event.key === storageKey && event.newValue !== marker) {
        document.documentElement.hidden = true;
        checkSession();
      }
    });
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
