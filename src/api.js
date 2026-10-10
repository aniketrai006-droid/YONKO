import { authHeaders, getSession, setSession } from './api/session.js';

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
  const session = getSession();
  if (!session?.token) {
    throw new Error('Sign in required. Analysis runs are tied to your reviewer account.');
  }

  const formData = new FormData();
  Array.from(files).forEach((file) => formData.append('files', file));

  let response;
  try {
    response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { ...authHeaders() },
      body: formData,
    });
  } catch (error) {
    throw new Error(`Could not reach the analysis service at ${API_BASE_URL}. ${error.message}`);
  }

  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function validateCredentials({ email, password }) {
  const normalized = String(email || '').trim().toLowerCase();
  const plain = String(password || '');

  if (!EMAIL_PATTERN.test(normalized)) {
    throw new Error('Enter a valid official email address, for example reviewer@department.gov.in.');
  }
  if (plain.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }
  if (!/[A-Za-z]/.test(plain)) {
    throw new Error('Password must include at least one letter.');
  }
  if (!/[0-9]/.test(plain)) {
    throw new Error('Password must include at least one digit.');
  }

  return { email: normalized, password: plain };
}

async function postAuth(path, payload, withAuth = false) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(withAuth ? authHeaders() : {}),
      },
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

export async function signUpReviewer({ email, password }) {
  const credentials = validateCredentials({ email, password });
  const account = await postAuth('/auth/signup', credentials);
  try {
    sessionStorage.setItem('yonko_just_signed_up', '1');
  } catch {
    // sessionStorage may be unavailable.
  }
  return account;
}

export async function signInReviewer({ email, password }) {
  const credentials = validateCredentials({ email, password });
  const account = await postAuth('/auth/signin', credentials);
  try {
    sessionStorage.removeItem('yonko_just_signed_up');
  } catch {
    // sessionStorage may be unavailable.
  }
  return account;
}

export async function saveProfile({ name, dob, token }) {
  const session = getSession();
  const authToken = token || session?.token;
  if (!authToken) {
    throw new Error('Account not found. Please sign in again.');
  }

  let response;
  try {
    response = await fetch(`${API_BASE_URL}/auth/profile`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ name, dob }),
    });
  } catch {
    throw new Error(
      `Could not reach the account database at ${API_BASE_URL}. Start the backend and try again.`
    );
  }

  if (!response.ok) throw new Error(await readError(response));
  const account = await response.json();
  const next = { ...account, token: account.token || authToken };
  setSession(next);
  return next;
}

export async function signOutReviewer() {
  try {
    await postAuth('/auth/logout', {}, true);
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
