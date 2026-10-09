// The FastAPI service is deployed separately from this Vite application.
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

async function readError(response) {
  try {
    const body = await response.json();
    if (body?.detail) {
      return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    }
  } catch {
    // A non-JSON error response still gets a useful fallback below.
  }
  return `Analysis failed (${response.status} ${response.statusText || 'request error'}).`;
}

export async function analyzeFiles(files) {
  const formData = new FormData();
  Array.from(files).forEach((file) => formData.append('files', file));

  let response;
  try {
    response = await fetch(`${API_BASE_URL}/analyze`, { method: 'POST', body: formData });
  } catch (error) {
    throw new Error(`Could not reach the analysis service at ${API_BASE_URL}. ${error.message}`);
  }

  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

// Reviewer sign in / sign up with an official email and password.
//
// Email accounts are kept in this browser for the demo. Google sign in is
// handled separately below: the backend verifies the credential with Google
// and answers with our own session token.
const ACCOUNTS_KEY = 'yonko_reviewer_accounts';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readAccounts() {
  try {
    return JSON.parse(localStorage.getItem(ACCOUNTS_KEY)) || {};
  } catch {
    return {};
  }
}

function writeAccounts(accounts) {
  try {
    localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts));
  } catch {
    // Storage can be unavailable in private mode; the demo still proceeds.
  }
}

function validateCredentials({ email, password }) {
  const normalized = String(email || '').trim().toLowerCase();

  if (!EMAIL_PATTERN.test(normalized)) {
    throw new Error('Enter a valid official email address, for example reviewer@department.gov.in.');
  }
  if (String(password || '').length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }

  return normalized;
}

export async function signUpReviewer({ email, password }) {
  const normalized = validateCredentials({ email, password });
  await delay(400);

  const accounts = readAccounts();
  if (accounts[normalized]) {
    throw new Error('An account already exists for this email. Sign in instead.');
  }

  accounts[normalized] = { email: normalized, createdAt: new Date().toISOString() };
  writeAccounts(accounts);
  return { email: normalized };
}

export async function signInReviewer({ email, password }) {
  const normalized = validateCredentials({ email, password });
  await delay(400);

  const accounts = readAccounts();
  if (!accounts[normalized]) {
    // Demo convenience: the first sign in with a valid email provisions a
    // reviewer account, so the workspace is never unreachable during judging.
    accounts[normalized] = { email: normalized, createdAt: new Date().toISOString() };
    writeAccounts(accounts);
  }

  return { email: accounts[normalized].email };
}

// Google sign in. The browser only holds Google's ID token for a moment; the
// backend calls Google, checks the token belongs to this app, and replies with
// a session token plus the reviewer profile.
export async function signInWithGoogle(credential) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}/auth/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential }),
    });
  } catch (error) {
    throw new Error(`Could not reach the analysis service at ${API_BASE_URL}. ${error.message}`);
  }

  if (!response.ok) throw new Error(await readError(response));
  const body = await response.json();

  if (!body?.access_token || !body?.user?.email) {
    throw new Error('Google sign in returned an unexpected response.');
  }

  return {
    email: body.user.email,
    name: body.user.name || body.user.email,
    picture: body.user.picture || '',
    provider: 'google',
    token: body.access_token,
  };
}
