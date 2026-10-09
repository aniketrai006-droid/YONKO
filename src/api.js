import { authHeaders, getSession } from './api/session.js';

// The FastAPI service is deployed separately from this Vite application.
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export { API_BASE_URL };

async function readError(response) {
  try {
    const body = await response.json();
    if (body?.detail) {
      return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    }
  } catch {
    // A non-JSON error response still gets a useful fallback below.
  }
  return `Request failed (${response.status} ${response.statusText || 'request error'}).`;
}

export async function analyzeFiles(files) {
  const formData = new FormData();
  Array.from(files).forEach((file) => formData.append('files', file));

  let response;
  try {
    response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: authHeaders(),
      body: formData,
    });
  } catch (error) {
    throw new Error(`Could not reach the analysis service at ${API_BASE_URL}. ${error.message}`);
  }

  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// Mirrors the backend policy in app/auth/passwords.py.
const MIN_PASSWORD_LENGTH = 12;

function validateCredentials({ email, password }) {
  const normalized = String(email || '').trim().toLowerCase();

  if (!EMAIL_PATTERN.test(normalized)) {
    throw new Error('Enter a valid official email address, for example reviewer@department.gov.in.');
  }
  if (String(password || '').length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`);
  }

  return { email: normalized, password: String(password) };
}

async function postAuth(path, payload) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    throw new Error(
      `Could not reach the account database at ${API_BASE_URL}. Start the backend and try again.`
    );
  }

  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

// Shape the JWT login response into the account object the dashboard
// components already expect ({ email, token, ... }).
function toAccount(payload) {
  return {
    email: payload.user?.email,
    role: payload.user?.role,
    mfaEnrolled: payload.user?.mfa_enrolled,
    token: payload.access_token,
    refreshToken: payload.refresh_token,
    // The JWT system has no separate profile step.
    needsProfile: false,
  };
}

export async function signUpReviewer({ email, password }) {
  const credentials = validateCredentials({ email, password });
  await postAuth('/auth/register', credentials);
  // Registration does not issue tokens — sign in to get the token pair.
  const payload = await postAuth('/auth/login', credentials);
  return toAccount(payload);
}

export async function signInReviewer({ email, password, totpCode }) {
  const credentials = validateCredentials({ email, password });
  const payload = await postAuth('/auth/login', {
    ...credentials,
    ...(totpCode ? { totp_code: String(totpCode).trim() } : {}),
  });
  return toAccount(payload);
}

export async function saveProfile({ name, dob, token }) {
  // Profile editing lives on the legacy SQLite auth system, which the JWT
  // flow no longer uses. Kept as a no-op so older call sites do not crash.
  const session = getSession();
  return {
    email: session?.email,
    token: token || session?.token,
    needsProfile: false,
  };
}

export async function signOutReviewer() {
  const session = getSession();
  try {
    if (session?.token && session?.refreshToken) {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({ refresh_token: session.refreshToken }),
      });
    }
  } catch {
    // Session is cleared locally even if the server is unreachable.
  }
}

export function reviewerFirstName(account) {
  const name = String(account?.name || '').trim();
  if (name) return name.split(/\s+/)[0];

  const letters = String(account?.email || '')
    .split('@')[0]
    .replace(/[^A-Za-z]+/g, ' ')
    .trim();
  if (letters) return letters.split(/\s+/)[0].replace(/^./, (c) => c.toUpperCase());
  return 'Reviewer';
}

export function reviewerInitials(account) {
  const name = String(account?.name || '').trim();
  if (name) {
    const parts = name.split(/\s+/);
    const first = parts[0];
    const letters =
      parts.length > 1 ? first[0] + parts[parts.length - 1][0] : first.slice(0, 2);
    return letters.toUpperCase();
  }

  const letters = String(account?.email || '')
    .split('@')[0]
    .replace(/[^A-Za-z]/g, '');
  return (letters.slice(0, 2) || 'RV').toUpperCase();
}
