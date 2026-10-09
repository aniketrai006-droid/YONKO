// In-memory session store.
//
// Security: tokens are NEVER written to localStorage/sessionStorage — a
// script-injection bug or shared device must not be able to read them from
// persistent storage. The trade-off is deliberate: a page reload signs the
// user out and they log in again (the backend access token is only valid
// for 15 minutes anyway).
//
// Account shape kept compatible with the dashboard components:
//   { email, token, refreshToken, role, mfaEnrolled, needsProfile }

let session = null;

// One-time cleanup: remove any session the previous localStorage-based
// implementation may have left behind.
try {
  localStorage.removeItem('yonko_reviewer_session');
} catch {
  // Storage can be unavailable in private mode.
}

export function getSession() {
  return session;
}

export function setSession(account) {
  session = account || null;
}

export function clearSession() {
  session = null;
}

export function authHeaders() {
  return session?.token ? { Authorization: `Bearer ${session.token}` } : {};
}
