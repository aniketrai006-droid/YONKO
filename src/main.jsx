import React, { useMemo, useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { runPrecheck } from './api/precheck';
import { analyzeFiles, signInReviewer, signUpReviewer } from './api';

const IMAGE_TYPES = new Set(['image/png', 'image/jpeg']);
const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg']);
const PDF_TYPE = 'application/pdf';
const ACCEPTED_EXTENSIONS = new Set([...IMAGE_EXTENSIONS, 'pdf']);
const ACCEPT_ATTRIBUTE = '.png,.jpg,.jpeg,.pdf,image/png,image/jpeg,application/pdf';
const SESSION_KEY = 'yonko_reviewer_session';

function App() {
  const [appView, setAppView] = useState('landing');
  const [reviewer, setReviewer] = useState(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(SESSION_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.email) {
          setReviewer(parsed);
        }
      }
    } catch {
      // Ignore storage read errors
    }
  }, []);

  const handleAuthenticated = (account) => {
    setReviewer(account);
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(account));
    } catch {
      // Ignore storage write errors
    }
    setAppView('workspace');
  };

  const handleSignOut = () => {
    setReviewer(null);
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch {
      // Ignore storage delete errors
    }
    setAppView('landing');
  };

  if (appView === 'landing') {
    return (
      <Landing
        reviewer={reviewer}
        onAuthenticated={handleAuthenticated}
        onSignOut={handleSignOut}
        onPrecheck={() => setAppView('precheck')}
        onGoToWorkspace={() => setAppView('workspace')}
      />
    );
  }

  if (appView === 'precheck') {
    return (
      <CitizenPrecheck
        onBack={() => setAppView(reviewer ? 'workspace' : 'landing')}
      />
    );
  }

  return (
    <Workspace
      reviewer={reviewer}
      onSignOut={handleSignOut}
      onPrecheck={() => setAppView('precheck')}
    />
  );
}

function Landing({
  reviewer,
  onAuthenticated,
  onSignOut,
  onPrecheck,
  onGoToWorkspace,
}) {
  const [accountModal, setAccountModal] = useState({ open: false, initialMode: 'signin' });

  const openAuth = (mode) => {
    setAccountModal({ open: true, initialMode: mode });
  };

  return (
    <div className="landing">
      <header className="landing-nav">
        <div className="public-brand">
          <span>⌘</span> Samanvay
        </div>
        <nav>
          <a href="#features">Features</a>
          <a href="#how-it-works">How it works</a>
        </nav>
        <div className="landing-actions">
          <button className="btn-precheck-nav" onClick={onPrecheck}>
            <span className="btn-icon">⚡</span> Try Citizen Pre-Check
          </button>
          {reviewer ? (
            <div className="logged-in-badge">
              <button className="workspace-jump-btn" onClick={onGoToWorkspace}>
                Go to Workspace <span>→</span>
              </button>
              <button className="nav-signout-btn" onClick={onSignOut} title="Sign Out">
                Sign Out
              </button>
            </div>
          ) : (
            <div className="auth-btn-group">
              <button className="nav-login-btn" onClick={() => openAuth('signin')}>
                Sign in
              </button>
              <button className="nav-cta" onClick={() => openAuth('signup')}>
                Sign up <span>→</span>
              </button>
            </div>
          )}
        </div>
      </header>

      <main>
        <section className="landing-hero">
          <div className="eyebrow-public">DOCUMENT VERIFICATION FOR PUBLIC SYSTEMS</div>
          <h1>
            Upload documents.<br />
            <em>Find conflicts early.</em>
          </h1>
          <p>
            A focused review workspace for finding differences across citizen documents before they delay an application.
          </p>
          <div className="hero-actions">
            {reviewer ? (
              <button className="hero-primary" onClick={onGoToWorkspace}>
                Open Reviewer Workspace <span>→</span>
              </button>
            ) : (
              <>
                <button className="hero-primary" onClick={() => openAuth('signin')}>
                  Sign in <span>→</span>
                </button>
                <button className="hero-signup" onClick={() => openAuth('signup')}>
                  Create account
                </button>
              </>
            )}
            <button className="btn-precheck-hero" onClick={onPrecheck}>
              <span className="btn-icon">⚡</span> Try Citizen Pre-Check
            </button>
          </div>

          <div className="hero-screen landing-float">
            <div className="screen-title">
              <span>CASE REVIEW</span>
              <b>Document bundle analysis</b>
              <i>● Evidence-ready</i>
            </div>
            <div className="screen-content">
              <div className="screen-docs">
                <small>DOCUMENT BUNDLE</small>
                {['ID card', 'Address proof', 'Income certificate'].map((doc, index) => (
                  <div key={doc}>
                    <span className={`tiny-doc d${index}`}>▧</span>
                    {doc}
                    <b>✓</b>
                  </div>
                ))}
              </div>
              <div className="screen-finding">
                <small>REVIEW WITH CONFIDENCE</small>
                <div className="alert-strip">
                  <span>AI</span>
                  <b>Compare evidence, not guesses</b>
                  <i>Ready</i>
                </div>
                <div className="visual-compare">
                  <div>
                    <small>RAW VALUE</small>
                    <b>12 Mar 2001</b>
                  </div>
                  <span>↔</span>
                  <div>
                    <small>NORMALIZED</small>
                    <b>2001-03-12</b>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Reference Image Matched Feature Section */}
        <section className="conflict-showcase" id="features">
          <div className="showcase-header">
            <span className="showcase-kicker">CONFLICT DETECTION ENGINE</span>
            <h2>Catches the conflicts that matter. Ignores the ones that don't.</h2>
            <p>
              Samanvay compares every detail across a citizen's documents, shows exactly where they disagree, and helps reviewers and applicants fix it before an application is rejected.
            </p>
          </div>

          <div className="conflict-cards-grid">
            {/* Card 1: Read any document */}
            <article className="conflict-card card-interactive">
              <div className="card-demo-box demo-box-1">
                <div className="demo-header-pills">
                  <span className="pill-dark">3 document types</span>
                  <span className="pill-blue">EN · हि · मरा languages read</span>
                  <span className="pill-gray">Synthetic data only</span>
                </div>
                <div className="flow-diagram">
                  <div className="flow-node node-input">
                    <span className="node-icon">🖼</span>
                    <span>Scan or PDF</span>
                  </div>
                  <div className="flow-arrow">➔</div>
                  <div className="flow-node node-ocr">
                    <span className="node-icon">ᵀ</span>
                    <span>Text recognition</span>
                  </div>
                  <div className="flow-arrow">➔</div>
                  <div className="flow-node node-extracted">
                    <span className="node-icon">☰</span>
                    <span>Name, date, ID and address extracted</span>
                  </div>
                </div>
              </div>
              <div className="card-body">
                <h3>Read any document</h3>
                <p>
                  Reads PDFs and phone photos in English, Hindi and Marathi, then pulls out the names, dates, ID numbers and addresses.
                </p>
              </div>
            </article>

            {/* Card 2: Ignore harmless differences */}
            <article className="conflict-card card-interactive">
              <div className="card-demo-box demo-box-2">
                <div className="diff-list">
                  <div className="diff-item diff-ignored">
                    <div className="diff-labels">
                      <b>Sunita Devi ≈ Sunita Dewi</b>
                      <small>Spelling variant</small>
                    </div>
                    <span className="badge-ignored">Ignored</span>
                  </div>
                  <div className="diff-item diff-ignored">
                    <div className="diff-labels">
                      <b>R. K. Singh ≈ Rajesh Kumar Singh</b>
                      <small>Initials</small>
                    </div>
                    <span className="badge-ignored">Ignored</span>
                  </div>
                  <div className="diff-item diff-flagged">
                    <div className="diff-labels">
                      <b>12/03/1998 ≠ 12/03/1989</b>
                      <small>Date of birth differs</small>
                    </div>
                    <span className="badge-flagged">Flagged</span>
                  </div>
                </div>
                <div className="demo-footer-badge">
                  <span>✦ Fixed rules decide, AI explains</span>
                </div>
              </div>
              <div className="card-body">
                <h3>Ignore harmless differences</h3>
                <p>
                  Spelling, transliteration, initials and abbreviations are matched automatically, so reviewers only see conflicts that are real.
                </p>
              </div>
            </article>

            {/* Card 3: See exactly where it conflicts */}
            <article className="conflict-card card-interactive">
              <div className="card-demo-box demo-box-3">
                <div className="conflict-demo-inner">
                  <div className="demo-sub-header">
                    <small>Date of birth · 2 documents compared</small>
                  </div>
                  <div className="compare-rows">
                    <div className="comp-row">
                      <span>Aadhaar</span>
                      <b>12/03/1998</b>
                    </div>
                    <div className="comp-row highlight-conflict">
                      <span>Income certificate</span>
                      <b>12/03/1989</b>
                    </div>
                  </div>
                  <div className="severity-bar">
                    <span className="sev-chip high active">High</span>
                    <span className="sev-chip medium">Medium</span>
                    <span className="sev-chip low">Low</span>
                  </div>
                  <div className="demo-actions">
                    <button className="demo-btn accept">Accept</button>
                    <button className="demo-btn dismiss">Dismiss</button>
                  </div>
                  <div className="demo-try-link" onClick={onPrecheck}>
                    Try it: review this finding <span>→</span>
                  </div>
                </div>
              </div>
              <div className="card-body">
                <h3>See exactly where it conflicts</h3>
                <p>
                  Every finding shows both documents, the exact field and a severity level, so a reviewer can accept or dismiss it in seconds.
                </p>
              </div>
            </article>

            {/* Card 4: Fix it before you apply */}
            <article className="conflict-card card-interactive">
              <div className="card-demo-box demo-box-4">
                <div className="precheck-card-demo">
                  <div className="upload-icon-circle">⬆</div>
                  <h4>Check your documents before you apply</h4>
                  <small>Drop PDF, JPG or PNG files here</small>
                  <div className="lang-pills">
                    <span className="lang-chip active">English</span>
                    <span className="lang-chip">हिंदी</span>
                    <span className="lang-chip">मराठी</span>
                  </div>
                  <div className="advice-callout-box">
                    <p>
                      Your income certificate shows a different date of birth. Ask the issuing office to correct it before you apply.
                    </p>
                  </div>
                </div>
              </div>
              <div className="card-body">
                <h3>Fix it before you apply</h3>
                <p>
                  Citizens get plain advice in their own language on which document to correct, with no login needed.
                </p>
              </div>
            </article>
          </div>
        </section>

        {/* How it works */}
        <section className="landing-how" id="how-it-works">
          <div>
            <span>HOW IT WORKS</span>
            <h2>One bundle. One clear result.</h2>
          </div>
          <div className="landing-steps">
            <p>
              <b>01</b> Sign in or create a reviewer account
            </p>
            <p>
              <b>02</b> Upload 2–10 documents
            </p>
            <p>
              <b>03</b> Review evidence and resolve findings
            </p>
          </div>
        </section>

        {/* Callout Section */}
        <section className="public-callout">
          <div>
            <span>READY FOR CASE REVIEW</span>
            <h2>Resolve document conflicts before they become delays.</h2>
            <p>Sign up or sign in to start reviewing document bundles.</p>
          </div>
          <div className="callout-actions">
            <button className="btn-precheck-nav" onClick={onPrecheck}>
              <span className="btn-icon">⚡</span> Try Citizen Pre-Check
            </button>
            {reviewer ? (
              <button className="hero-primary" onClick={onGoToWorkspace}>
                Open Workspace <span>→</span>
              </button>
            ) : (
              <button className="hero-primary" onClick={() => openAuth('signup')}>
                Sign up as Reviewer <span>→</span>
              </button>
            )}
          </div>
        </section>
      </main>

      <footer className="public-footer">
        <div className="public-brand">
          <span>⌘</span> Samanvay
        </div>
        <p>Document contradiction detection for public systems.</p>
        <span>Synthetic-data demo · English / हिन्दी / मराठी</span>
      </footer>

      {accountModal.open && (
        <AccountModal
          initialMode={accountModal.initialMode}
          onClose={() => setAccountModal({ open: false, initialMode: 'signin' })}
          onAuthenticated={onAuthenticated}
        />
      )}
    </div>
  );
}

function AccountModal({ initialMode = 'signin', onClose, onAuthenticated }) {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setPending(true);
    setError('');

    try {
      const account =
        mode === 'signup'
          ? await signUpReviewer({ email, password })
          : await signInReviewer({ email, password });

      onAuthenticated(account);
    } catch (requestError) {
      setError(
        requestError.message ||
          (mode === 'signup'
            ? 'Sign up failed. Please check your details.'
            : 'Sign in failed. Incorrect email or password.')
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="login-backdrop" onClick={onClose}>
      <section className="login-card account-card" onClick={(event) => event.stopPropagation()}>
        <button className="login-close" onClick={onClose}>
          ×
        </button>
        <div className="login-mark">⌘</div>
        <div className="login-kicker">REVIEWER PORTAL</div>

        {/* Auth Mode Tabs */}
        <div className="auth-tab-row">
          <button
            type="button"
            className={`auth-tab-btn ${mode === 'signin' ? 'active' : ''}`}
            onClick={() => {
              setMode('signin');
              setError('');
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`auth-tab-btn ${mode === 'signup' ? 'active' : ''}`}
            onClick={() => {
              setMode('signup');
              setError('');
            }}
          >
            Create Account (Sign Up)
          </button>
        </div>

        <h2>{mode === 'signup' ? 'Register as Reviewer' : 'Welcome back'}</h2>
        <p>
          {mode === 'signup'
            ? 'Sign up with your official email address and password (min 8 characters).'
            : 'Sign in with your registered reviewer account.'}
        </p>

        <form onSubmit={submit}>
          <label>
            Official email address
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="reviewer@department.gov.in"
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              minLength="8"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="At least 8 characters"
              required
            />
          </label>

          {error && (
            <div className="account-error-alert" role="alert">
              <span>⚠️</span> {error}
            </div>
          )}

          <button className="login-submit" disabled={pending} type="submit">
            {pending
              ? 'Connecting to database…'
              : mode === 'signup'
              ? 'Create Reviewer Account →'
              : 'Sign in →'}
          </button>
        </form>

        <button
          className="account-switch"
          onClick={() => {
            setMode(mode === 'signup' ? 'signin' : 'signup');
            setError('');
          }}
        >
          {mode === 'signup'
            ? 'Already registered? Sign in to your account'
            : 'New reviewer? Click here to sign up'}
        </button>
      </section>
    </div>
  );
}

function Workspace({ reviewer, onSignOut, onPrecheck }) {
  const [files, setFiles] = useState([]);
  const [result, setResult] = useState(null);
  const [selected, setSelected] = useState(null);

  const [lang, setLang] = useState('en');
  const [ignoredOpen, setIgnoredOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [showUpload, setShowUpload] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [showVerify, setShowVerify] = useState(false);

  const [ocrValue, setOcrValue] = useState('');
  const [reviewStates, setReviewStates] = useState({});
  const [loading, setLoading] = useState(false);

  const [requestError, setRequestError] = useState('');
  const [selectionError, setSelectionError] = useState('');
  const [toast, setToast] = useState('');

  const findings = result?.findings || [];
  const summary = result?.summary;
  const documentsProcessed = result?.documents_processed ?? 0;
  const current = findings.find((item) => item.id === selected) || findings[0];

  const visibleFindings = useMemo(() => {
    return findings.filter((item) => {
      const matchesQuery = `${item.field} ${item.reason} ${item.evidence
        .map((evidence) => `${evidence.document_type} ${evidence.raw_value}`)
        .join(' ')}`
        .toLowerCase()
        .includes(query.toLowerCase());

      const matchesSeverity =
        severityFilter === 'ALL'
          ? true
          : severityFilter === 'HARMLESS'
          ? item.decision === 'harmless_variant'
          : item.severity?.toUpperCase() === severityFilter;

      return matchesQuery && matchesSeverity;
    });
  }, [findings, query, severityFilter]);

  const canAnalyze = files.length >= 2 && files.length <= 10 && !selectionError && !loading;

  const notify = (message) => {
    setToast(message);
    window.setTimeout(() => setToast(''), 2800);
  };

  const chooseFiles = (fileList) => {
    const next = Array.from(fileList || []);
    const seen = new Set();
    const invalid = next.find((file) => !isValidImage(file));
    const duplicate = next.find((file) => {
      const name = file.name.toLowerCase();
      if (seen.has(name)) return true;
      seen.add(name);
      return false;
    });

    if (invalid) return setSelectionError(`${invalid.name} must be a non-empty PNG, JPG, JPEG, or PDF file.`);
    if (duplicate) return setSelectionError(`Duplicate filename: ${duplicate.name}.`);
    if (next.length < 2 || next.length > 10) return setSelectionError('Choose between 2 and 10 files.');

    setFiles(next);
    setSelectionError('');
    setRequestError('');
  };

  const analyze = async () => {
    if (!canAnalyze) return;
    setLoading(true);
    setRequestError('');

    try {
      const response = await analyzeFiles(files);
      const mapped = (response.findings || []).map((item, index) => ({
        ...item,
        id: `${item.field}-${index}`,
      }));
      setResult({ ...response, findings: mapped });
      setSelected(mapped[0]?.id || null);
      setReviewStates({});
      setShowUpload(false);
      notify('Analysis complete! Documents analyzed by backend.');
    } catch (error) {
      setRequestError(error.message || 'Analysis could not be completed.');
    } finally {
      setLoading(false);
    }
  };

  const setLocalReview = (status) => {
    if (!current) return;
    setReviewStates((all) => ({ ...all, [current.id]: status }));
    notify(`Finding marked ${status} locally.`);
  };

  const reviewerEmail = reviewer?.email || 'Reviewer';
  const reviewerInitials = reviewerEmail.substring(0, 2).toUpperCase();
  const t = workspaceText[lang];
  const harmlessFindings = findings.filter((item) => item.decision === 'harmless_variant');

  const resetBundle = () => {
    setResult(null);
    setSelected(null);
    setFiles([]);
    setReviewStates({});
    setQuery('');
    setSeverityFilter('ALL');
    setIgnoredOpen(false);
    setRequestError('');
    notify(`${t.again} · ${t.emptyTitle}`);
  };

  return (
    <div className="shell">
      {/* Clean, essential Sidebar */}
      <aside className="sidebar">
        <div className="profile">
          <div className="profile-photo">{reviewerInitials}</div>
          <div className="profile-info">
            <b>{reviewerEmail}</b>
            <small>{t.reviewer}</small>
          </div>
        </div>

        <div className="side-rule" />

        <nav className="primary-nav-clean">
          <button className="side-link active">
            <span className="side-icon">▣</span> {t.analysis}
            {documentsProcessed > 0 && <span className="doc-count-badge">{documentsProcessed}</span>}
          </button>
          <button className="side-link btn-sidebar-precheck" onClick={onPrecheck}>
            <span className="side-icon">⚡</span> {t.precheck}
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="db-status-tag">
            <span className="status-dot green">●</span> SQLite DB Connected
          </div>
          <button className="signout-side-btn" onClick={onSignOut}>
            <span>🚪</span> {t.signOut}
          </button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Samanvay</span>
            <b>/</b>
            <strong>{t.workspace}</strong>
          </div>

          <div className="header-actions">
            <div className="language-picker workspace-language" aria-label={t.langLabel}>
              {[
                ['en', 'English'],
                ['hi', 'हिंदी'],
                ['mr', 'मराठी'],
              ].map(([key, label]) => (
                <button
                  key={key}
                  className={lang === key ? 'active' : ''}
                  aria-pressed={lang === key}
                  onClick={() => setLang(key)}
                >
                  {label}
                </button>
              ))}
            </div>
            <button className="btn-precheck-nav" onClick={onPrecheck}>
              <span className="btn-icon">⚡</span> {t.precheck}
            </button>
            <div className="user-profile-header">
              <div className="user-mini" title={reviewerEmail}>
                {reviewerInitials}
              </div>
              <button className="header-signout-btn" onClick={onSignOut}>
                {t.signOut}
              </button>
            </div>
          </div>
        </header>

        <div className="page">
          <div className="page-title">
            <div>
              <h1>
                {t.title} <span className="info">?</span>
              </h1>
              <p>{t.subtitle}</p>
            </div>
            <div className="title-actions">
              <button className="primary-outline" onClick={() => setShowUpload(true)}>
                {t.addDocs}
              </button>
            </div>
          </div>

          {/* Quick Toolbar & Severity Filters */}
          <div className="toolbar">
            <div className="search">
              <span>⌕</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t.search}
              />
            </div>
            <div className="filter-chips">
              {[
                ['ALL', t.allFindings],
                ['HIGH', t.high],
                ['MEDIUM', t.medium],
                ['LOW', t.low],
                ['HARMLESS', t.harmless],
              ].map(([key, label]) => (
                <button
                  key={key}
                  className={`chip-btn ${severityFilter === key ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="dropzone">
            <span className="drop-icon">▧</span>
            <b>{t.drop}</b>
            <button onClick={() => setShowUpload(true)}>{t.browse}</button>
            <small>{t.dropHelp}</small>
          </div>

          {requestError && (
            <div className="request-message error-message" role="alert">
              {requestError}
            </div>
          )}

          {result?.warnings?.length > 0 && (
            <div className="request-message warning-message">
              <b>Backend warnings</b>
              <ul>
                {result.warnings.map((warning, index) => (
                  <li key={`${warning}-${index}`}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          {summary ? (
            <>
              {/* Document table card */}
              <section className="table-card">
                <div className="table-heading">
                  <div>
                    <h2>
                      {t.bundle} <span>{documentsProcessed}</span>
                    </h2>
                    <p>
                      {documentsProcessed} {t.bundleNote}
                    </p>
                  </div>
                  <div className="bundle-status">
                    <i /> {t.complete}
                  </div>
                </div>

                <div className="document-table">
                  <div className="table-row table-header">
                    <span>Document name</span>
                    <span>Format</span>
                    <span>Extracted fields</span>
                    <span>OCR status</span>
                    <span>Operation</span>
                  </div>
                  {files.map((file, index) => (
                    <div className="table-row" key={`${file.name}-${index}`}>
                      <span className="document-name">
                        <i className={`doc-symbol symbol-${index % 3}`}>▤</i>
                        <b>{file.name}</b>
                      </span>
                      <span>
                        <em className="type-tag">{file.name.split('.').pop()?.toUpperCase() || 'IMAGE'}</em>
                      </span>
                      <span className="field-text">Parsed into finding evidence</span>
                      <span>
                        <em className="complete-tag">✓ Complete</em>
                      </span>
                      <span className="row-actions">
                        <button
                          title="View evidence details"
                          onClick={() => current && setShowEvidence(true)}
                        >
                          ↗
                        </button>
                      </span>
                    </div>
                  ))}
                </div>

                <div className="table-footer">
                  <span>
                    {files.length} uploaded file{files.length === 1 ? '' : 's'}
                  </span>
                </div>
              </section>

              {/* Summary stats section */}
              <section className="summary-card">
                <div className="summary-heading">
                  <div>
                    <span className="summary-kicker">{t.summaryKicker}</span>
                    <h2>{t.summaryTitle}</h2>
                    <p>{t.summaryNote}</p>
                  </div>
                  <span className="summary-status">{t.complete}</span>
                </div>
                <div className="summary-stats">
                  <Stat label={t.docsProcessed} value={documentsProcessed} />
                  <Stat label={t.conflicts} value={summary.conflict_count} />
                  <Stat label={t.variants} value={summary.harmless_variant_count} />
                  <Stat label={t.needsReview} value={summary.review_count} />
                  <Stat label={t.highest} value={summary.highest_severity} highlight />
                </div>
              </section>

              {/* Lower grid with findings list and inspector */}
              <div className="lower-grid">
                <section className="findings-card">
                  <div className="card-heading">
                    <div>
                      <h2>
                        {t.findings} <span>{visibleFindings.length}</span>
                      </h2>
                      <p>{t.findingsNote}</p>
                    </div>
                  </div>

                  {visibleFindings.length ? (
                    visibleFindings.map((item) => (
                      <button
                        key={item.id}
                        className={`finding-line ${selected === item.id ? 'selected' : ''}`}
                        onClick={() => setSelected(item.id)}
                      >
                        <span className={`severity-mark ${item.severity?.toLowerCase() || 'low'}`} />
                        <span className="finding-field">
                          <b>{item.field}</b>
                          <small>
                            {item.evidence?.map((e) => e.document_type).join(' vs ') || 'No evidence'}
                          </small>
                        </span>
                        <span className="finding-values">
                          {item.evidence
                            ?.map((e) => e.raw_value)
                            .filter(Boolean)
                            .join(' → ')}
                        </span>
                        <em className={`status-tag ${item.decision}`}>
                          {reviewStates[item.id] || decisionLabel(item.decision)}
                        </em>
                        <span>›</span>
                      </button>
                    ))
                  ) : (
                    <p className="empty-state">{t.emptyFilter}</p>
                  )}
                </section>

                {current && (
                  <aside className="review-card">
                    <div className="card-heading">
                      <div>
                        <h2>{t.selected}</h2>
                        <p>{t.selectedNote}</p>
                      </div>
                    </div>
                    <span className={`severity-label ${current.severity?.toLowerCase() || 'low'}`}>
                      {current.severity}
                    </span>
                    <h3>{current.field}</h3>
                    <p className="explanation">{current.reason}</p>

                    <div className="compare-box">
                      {current.evidence?.map((item, index) => (
                        <EvidenceValue
                          key={`${item.source_path || item.document_type}-${index}`}
                          evidence={item}
                        />
                      ))}
                    </div>

                    {current.recommended_action && (
                      <div className="fix-box">
                        <b>✓ {t.fix}</b>
                        <span>{current.recommended_action}</span>
                      </div>
                    )}

                    <div className="review-card-actions">
                      <button onClick={() => setShowEvidence(true)}>{t.viewEvidence}</button>
                      <button
                        onClick={() => {
                          setOcrValue(current.evidence?.[0]?.raw_value || '');
                          setShowVerify(true);
                        }}
                      >
                        {t.verifyOcr}
                      </button>
                    </div>

                    <div className="decision">
                      <button onClick={() => setLocalReview('dismissed')}>{t.dismiss}</button>
                      <button onClick={() => setLocalReview('accepted')}>{t.accept}</button>
                    </div>

                    <small className="local-note">{t.localNote}</small>
                  </aside>
                )}
              </div>

              {/* Harmless variations the detector deliberately ignored */}
              <section className="ignored-box">
                <button
                  onClick={() => setIgnoredOpen(!ignoredOpen)}
                  aria-expanded={ignoredOpen}
                >
                  <span>
                    {t.ignoredTitle} <small>{t.ignoredNote}</small>
                  </span>
                  <b>{ignoredOpen ? '⌃' : '⌄'}</b>
                </button>
                {ignoredOpen && (
                  <div>
                    {harmlessFindings.length ? (
                      harmlessFindings.map((item, index) => (
                        <p key={`${item.field}-${index}`}>
                          <b>{item.field}:</b>{' '}
                          {item.evidence
                            ?.map((evidence) => evidence.raw_value || evidence.normalized_value)
                            .filter(Boolean)
                            .join(' · ')}{' '}
                          <span>— {item.reason}</span>
                        </p>
                      ))
                    ) : (
                      <p>{t.ignoredEmpty}</p>
                    )}
                  </div>
                )}
              </section>

              {/* Report and restart actions */}
              <div className="result-actions">
                <button onClick={() => window.print()}>↓ {t.download}</button>
                <button onClick={resetBundle}>{t.again} →</button>
              </div>
            </>
          ) : (
            <div className="empty-tab">
              <div className="empty-icon">＋</div>
              <h2>{t.emptyTitle}</h2>
              <p>{t.emptyText}</p>
              <button className="primary-button" onClick={() => setShowUpload(true)}>
                {t.emptyBtn}
              </button>
            </div>
          )}
        </div>
      </main>

      {/* Modal dialogs */}
      {showUpload && (
        <div className="modal-backdrop" onClick={() => !loading && setShowUpload(false)}>
          <div className="upload-modal" onClick={(event) => event.stopPropagation()}>
            <button className="modal-close" disabled={loading} onClick={() => setShowUpload(false)}>
              ×
            </button>
            <div className="modal-kicker">{t.newBundle}</div>
            <h2>{t.uploadTitle}</h2>
            <p>{t.uploadText}</p>
            <div className="modal-drop">
              <b>{t.uploadDrop}</b>
              <label>
                {t.uploadBrowse}
                <input
                  type="file"
                  multiple
                  accept={ACCEPT_ATTRIBUTE}
                  onChange={(event) => chooseFiles(event.target.files)}
                />
              </label>
              <small>PNG, JPG, JPEG or PDF · 2–10 files</small>
            </div>
            {files.length > 0 && (
              <p className="selection-copy">
                {files.length} {t.selectedFiles} {files.map((file) => file.name).join(', ')}
              </p>
            )}
            {selectionError && (
              <p className="selection-error" role="alert">
                {selectionError}
              </p>
            )}
            <button
              className="primary-button full"
              disabled={!canAnalyze}
              onClick={analyze}
            >
              {loading ? 'Analyzing documents…' : 'Upload and analyze'}
            </button>
          </div>
        </div>
      )}

      {showEvidence && current && (
        <div className="modal-backdrop" onClick={() => setShowEvidence(false)}>
          <div className="evidence-modal" onClick={(event) => event.stopPropagation()}>
            <button className="modal-close" onClick={() => setShowEvidence(false)}>
              ×
            </button>
            <div className="modal-kicker">EVIDENCE VIEW · {current.field}</div>
            <h2>Source evidence details</h2>
            <p>Confidence score and bounding box definitions from backend OCR engine.</p>
            <div className="evidence-grid">
              {current.evidence?.map((item, index) => (
                <EvidenceDetails
                  key={`${item.source_path || item.document_type}-${index}`}
                  evidence={item}
                />
              ))}
            </div>
          </div>
        </div>
      )}

      {showVerify && current && (
        <div className="modal-backdrop" onClick={() => setShowVerify(false)}>
          <div className="verify-modal" onClick={(event) => event.stopPropagation()}>
            <button className="modal-close" onClick={() => setShowVerify(false)}>
              ×
            </button>
            <div className="modal-kicker">VERIFY OCR · SESSION ONLY</div>
            <h2>Confirm extracted value</h2>
            <p>Correct any OCR text output locally for this finding.</p>
            <label>Extracted {current.field}</label>
            <input value={ocrValue} onChange={(event) => setOcrValue(event.target.value)} />
            <div className="modal-actions">
              <button onClick={() => setShowVerify(false)}>Cancel</button>
              <button
                className="primary-button"
                onClick={() => {
                  setShowVerify(false);
                  notify('OCR edit saved for session.');
                }}
              >
                Save OCR edit
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast">✓ {toast}</div>}
    </div>
  );
}

function isValidImage(file) {
  const extension = file.name.split('.').pop()?.toLowerCase();
  return (
    file.size > 0 &&
    ACCEPTED_EXTENSIONS.has(extension) &&
    (IMAGE_TYPES.has(file.type) || file.type === PDF_TYPE)
  );
}

function decisionLabel(decision) {
  return (
    {
      conflict: 'conflict',
      harmless_variant: 'harmless variant',
      review: 'needs review',
      insufficient_evidence: 'insufficient evidence',
    }[decision] ||
    decision ||
    'unknown'
  );
}

function Stat({ label, value, highlight = false }) {
  return (
    <div>
      <small>{label}</small>
      <b className={highlight ? 'summary-high' : ''}>{value}</b>
    </div>
  );
}

function EvidenceValue({ evidence }) {
  return (
    <div className="source">
      <span>▤ {evidence.document_type || 'Document'}</span>
      <b>{evidence.raw_value || evidence.normalized_value || 'No value returned'}</b>
      <small>
        {evidence.source_confidence != null
          ? `${evidence.source_confidence}% confidence`
          : 'Confidence unavailable'}
      </small>
    </div>
  );
}

function EvidenceDetails({ evidence }) {
  return (
    <div className="evidence-doc">
      <div>
        <b>{evidence.document_type || 'Document'}</b>
        <small>{evidence.raw_value || evidence.normalized_value || 'No value returned'}</small>
      </div>
      <small className="bbox-text">
        confidence: {evidence.source_confidence ?? 'unavailable'} · bbox: [
        {(evidence.source_bbox || []).join(', ')}]
      </small>
      {evidence.normalization_warnings?.length > 0 && (
        <small className="bbox-text">
          warnings: {evidence.normalization_warnings.join('; ')}
        </small>
      )}
    </div>
  );
}

const workspaceText = {
  en: {
    langLabel: 'Language',
    analysis: 'Document Analysis',
    precheck: 'Citizen Pre-Check',
    reviewer: 'Verified Reviewer',
    signOut: 'Sign Out',
    workspace: 'Reviewer Workspace',
    title: 'Document Bundle Analysis',
    subtitle: 'Upload document images or PDFs and review contradiction findings generated by backend OCR & parsing.',
    addDocs: '＋ Add documents',
    search: 'Search findings, fields or values...',
    allFindings: 'All Findings',
    high: 'High Severity',
    medium: 'Medium Severity',
    low: 'Low Severity',
    harmless: 'Harmless Variants',
    drop: 'Drop your documents here, or',
    browse: 'click to browse',
    dropHelp: 'PNG, JPG, JPEG or PDF · 2–10 files per bundle',
    bundle: 'Uploaded Document Bundle',
    bundleNote: 'images processed successfully.',
    complete: 'Analysis complete',
    summaryKicker: 'BUNDLE ANALYSIS',
    summaryTitle: 'Citizen bundle summary',
    summaryNote: 'Analysis metrics returned by backend.',
    docsProcessed: 'Documents processed',
    conflicts: 'Conflicts',
    variants: 'Harmless variants',
    needsReview: 'Needs review',
    highest: 'Highest severity',
    findings: 'Findings',
    findingsNote: 'Select a finding to inspect source evidence and review decision.',
    emptyFilter: 'No findings match the current filter.',
    selected: 'Selected finding',
    selectedNote: 'Backend explanation and review action',
    viewEvidence: 'View evidence',
    verifyOcr: 'Verify OCR',
    dismiss: 'Dismiss finding',
    accept: 'Accept finding',
    localNote: 'Local decision mode · saved in session',
    fix: 'How to fix it',
    ignoredTitle: 'Differences we ignored',
    ignoredNote: 'These common variations do not need to be corrected.',
    ignoredEmpty: 'No harmless variations were found in this bundle.',
    download: 'Download report (PDF)',
    again: 'Check again',
    emptyTitle: 'Analyze a document bundle',
    emptyText: 'Select 2–10 PNG, JPG, JPEG, or PDF files of citizen documents to compare.',
    emptyBtn: 'Choose files to analyze',
    newBundle: 'NEW DOCUMENT BUNDLE',
    uploadTitle: 'Upload documents',
    uploadText: 'Upload 2–10 PNG, JPG, JPEG, or PDF files to run backend contradiction detection.',
    uploadDrop: 'Drop image or PDF files here',
    uploadBrowse: 'Browse from your computer',
    selectedFiles: 'selected:',
  },
  hi: {
    langLabel: 'भाषा',
    analysis: 'दस्तावेज़ विश्लेषण',
    precheck: 'नागरिक प्री-चेक',
    reviewer: 'सत्यापित समीक्षक',
    signOut: 'साइन आउट',
    workspace: 'समीक्षक कार्यक्षेत्र',
    title: 'दस्तावेज़ बंडल विश्लेषण',
    subtitle: 'दस्तावेज़ चित्र या PDF अपलोड करें और बैकएंड OCR व पार्सिंग से बने विरोधाभास परिणाम देखें।',
    addDocs: '＋ दस्तावेज़ जोड़ें',
    search: 'निष्कर्ष, फ़ील्ड या मान खोजें...',
    allFindings: 'सभी निष्कर्ष',
    high: 'उच्च गंभीरता',
    medium: 'मध्यम गंभीरता',
    low: 'कम गंभीरता',
    harmless: 'हानिरहित भिन्नताएँ',
    drop: 'अपने दस्तावेज़ यहाँ खींचें, या',
    browse: 'ब्राउज़ करें',
    dropHelp: 'PNG, JPG या PDF · बंडल में 2–10 फ़ाइलें',
    bundle: 'अपलोड किया गया दस्तावेज़ बंडल',
    bundleNote: 'चित्र सफलतापूर्वक संसाधित हुए।',
    complete: 'विश्लेषण पूर्ण',
    summaryKicker: 'बंडल विश्लेषण',
    summaryTitle: 'नागरिक बंडल सारांश',
    summaryNote: 'बैकएंड से प्राप्त विश्लेषण मापदंड।',
    docsProcessed: 'संसाधित दस्तावेज़',
    conflicts: 'विरोधाभास',
    variants: 'हानिरहित भिन्नताएँ',
    needsReview: 'समीक्षा आवश्यक',
    highest: 'उच्चतम गंभीरता',
    findings: 'निष्कर्ष',
    findingsNote: 'स्रोत प्रमाण और समीक्षा निर्णय देखने के लिए कोई निष्कर्ष चुनें।',
    emptyFilter: 'मौजूदा फ़िल्टर से कोई निष्कर्ष मेल नहीं खाता।',
    selected: 'चयनित निष्कर्ष',
    selectedNote: 'बैकएंड व्याख्या और समीक्षा कार्रवाई',
    viewEvidence: 'प्रमाण देखें',
    verifyOcr: 'OCR सत्यापित करें',
    dismiss: 'निष्कर्ष खारिज करें',
    accept: 'निष्कर्ष स्वीकारें',
    localNote: 'स्थानीय निर्णय मोड · सत्र में सहेजा गया',
    fix: 'इसे कैसे ठीक करें',
    ignoredTitle: 'वे अंतर जिन्हें हमने अनदेखा किया',
    ignoredNote: 'इन सामान्य भिन्नताओं को ठीक करने की आवश्यकता नहीं है।',
    ignoredEmpty: 'इस बंडल में कोई हानिरहित भिन्नता नहीं मिली।',
    download: 'रिपोर्ट डाउनलोड करें (PDF)',
    again: 'फिर से जाँचें',
    emptyTitle: 'दस्तावेज़ बंडल का विश्लेषण करें',
    emptyText: 'तुलना के लिए नागरिक दस्तावेज़ों के 2–10 PNG, JPG या PDF फ़ाइलें चुनें।',
    emptyBtn: 'विश्लेषण हेतु फ़ाइलें चुनें',
    newBundle: 'नया दस्तावेज़ बंडल',
    uploadTitle: 'दस्तावेज़ अपलोड करें',
    uploadText: 'विरोधाभास पहचान चलाने के लिए 2–10 PNG, JPG या PDF फ़ाइलें अपलोड करें।',
    uploadDrop: 'यहाँ फ़ाइलें छोड़ें',
    uploadBrowse: 'अपने कंप्यूटर से ब्राउज़ करें',
    selectedFiles: 'चयनित:',
  },
  mr: {
    langLabel: 'भाषा',
    analysis: 'कागदपत्र विश्लेषण',
    precheck: 'नागरिक प्री-चेक',
    reviewer: 'प्रमाणित समीक्षक',
    signOut: 'साइन आउट',
    workspace: 'समीक्षक कार्यक्षेत्र',
    title: 'कागदपत्र गट विश्लेषण',
    subtitle: 'कागदपत्र चित्रे किंवा PDF अपलोड करा आणि बॅकएंड OCR व पार्सिंगचे विरोधाभास निकाल पहा.',
    addDocs: '＋ कागदपत्रे जोडा',
    search: 'निष्कर्ष, क्षेत्र किंवा मूल्य शोधा...',
    allFindings: 'सर्व निष्कर्ष',
    high: 'उच्च तीव्रता',
    medium: 'मध्यम तीव्रता',
    low: 'कमी तीव्रता',
    harmless: 'निरुपद्रवी फरक',
    drop: 'तुमची कागदपत्र येथे ओढा, किंवा',
    browse: 'ब्राउझ करा',
    dropHelp: 'PNG, JPG किंवा PDF · गटात 2–10 फाईल्स',
    bundle: 'अपलोड केलेला कागदपत्र गट',
    bundleNote: 'चित्रे यशस्वीरित्या प्रक्रिया झाली.',
    complete: 'विश्लेषण पूर्ण',
    summaryKicker: 'गट विश्लेषण',
    summaryTitle: 'नागरिक गट सारांश',
    summaryNote: 'बॅकएंडकडून मिळालेले विश्लेषण मापदंड.',
    docsProcessed: 'प्रक्रिया झालेली कागदपत्रे',
    conflicts: 'विरोधाभास',
    variants: 'निरुपद्रवी फरक',
    needsReview: 'समीक्षा आवश्यक',
    highest: 'सर्वाधिक तीव्रता',
    findings: 'निष्कर्ष',
    findingsNote: 'स्रोत पुरावा आणि समीक्षा निर्णय पाहण्यासाठी निष्कर्ष निवडा.',
    emptyFilter: 'सध्याच्या फिल्टरशी कोणताही निष्कर्ष जुळत नाही.',
    selected: 'निवडलेला निष्कर्ष',
    selectedNote: 'बॅकएंड स्पष्टीकरण आणि समीक्षा कृती',
    viewEvidence: 'पुरावा पहा',
    verifyOcr: 'OCR पडताळा',
    dismiss: 'निष्कर्ष दुर्लक्ष करा',
    accept: 'निष्कर्ष स्वीकारा',
    localNote: 'स्थानिक निर्णय मोड · सत्रात जतन केले',
    fix: 'हे कसे दुरुस्त करावे',
    ignoredTitle: 'आम्ही दुर्लक्ष केलेले फरक',
    ignoredNote: 'हे सामान्य फरक दुरुस्त करण्याची गरज नाही.',
    ignoredEmpty: 'या गटात कोणतेही निरुपद्रवी फरक आढळले नाही.',
    download: 'अहवाल डाउनलोड करा (PDF)',
    again: 'पुन्हा तपासा',
    emptyTitle: 'कागदपत्र गट विश्लेषण करा',
    emptyText: 'तुलनेसाठी नागरिक कागदपत्रांची 2–10 PNG, JPG किंवा PDF फाईल्स निवडा.',
    emptyBtn: 'विश्लेषणासाठी फाईल्स निवडा',
    newBundle: 'नवीन कागदपत्र गट',
    uploadTitle: 'कागदपत्रे अपलोड करा',
    uploadText: 'विरोधाभास ओळख चालवण्यासाठी 2–10 PNG, JPG किंवा PDF फाईल्स अपलोड करा.',
    uploadDrop: 'येथे फाईल्स सोडा',
    uploadBrowse: 'तुमच्या संगणकावरून ब्राउझ करा',
    selectedFiles: 'निवडलेले:',
  },
};

const precheckText = {
  en: {
    back: 'Back to home',
    title: 'Check your documents before you apply',
    intro:
      'Upload your documents to find possible conflicts and learn what to correct before submitting your application.',
    language: 'English',
    step1: 'Upload documents',
    step2: 'Checking details',
    step3: 'Your report',
    notice: 'Demo uses synthetic documents only. Do not upload real documents.',
    drop: 'Drag and drop your documents here',
    browse: 'Browse files',
    formats: 'PDF, JPG or PNG · Up to 5 files',
    type: 'Document type',
    remove: 'Remove',
    check: 'Check my documents',
    minimum: 'Add at least 2 documents to continue',
    types: ['ID proof', 'Address proof', 'Income certificate', 'Other'],
    processingTitle: 'Checking your documents',
    reading: 'Reading documents',
    comparing: 'Comparing details',
    preparing: 'Preparing your report',
    results: 'Your pre-check report',
    summary: 'problems to fix',
    ignored: 'harmless differences ignored',
    fix: 'How to fix it',
    ignoredTitle: 'Differences we ignored',
    ignoredText: 'These common variations do not need to be corrected.',
    download: 'Download report (PDF)',
    again: 'Check again',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    valueFrom: 'From',
    uploadMore: 'Add another document',
  },
  hi: {
    back: 'होम पर वापस जाएँ',
    title: 'आवेदन से पहले अपने दस्तावेज़ जाँचें',
    intro:
      'अपने दस्तावेज़ अपलोड करें, संभावित अंतर देखें और आवेदन जमा करने से पहले जानें कि क्या ठीक करना है।',
    language: 'हिंदी',
    step1: 'दस्तावेज़ अपलोड करें',
    step2: 'विवरण जाँच रहे हैं',
    step3: 'आपकी रिपोर्ट',
    notice: 'डेमो में केवल सिंथेटिक दस्तावेज़ों का उपयोग होता है। असली दस्तावेज़ अपलोड न करें।',
    drop: 'अपने दस्तावेज़ यहाँ खींचें और छोड़ें',
    browse: 'फ़ाइल चुनें',
    formats: 'PDF, JPG या PNG · अधिकतम 5 फ़ाइलें',
    type: 'दस्तावेज़ प्रकार',
    remove: 'हटाएँ',
    check: 'मेरे दस्तावेज़ जाँचें',
    minimum: 'आगे बढ़ने के लिए कम से कम 2 दस्तावेज़ जोड़ें',
    types: ['पहचान प्रमाण', 'पता प्रमाण', 'आय प्रमाणपत्र', 'अन्य'],
    processingTitle: 'आपके दस्तावेज़ जाँचे जा रहे हैं',
    reading: 'दस्तावेज़ पढ़ रहे हैं',
    comparing: 'विवरण की तुलना कर रहे हैं',
    preparing: 'रिपोर्ट तैयार कर रहे हैं',
    results: 'आपकी प्री-चेक रिपोर्ट',
    summary: 'समस्याएँ ठीक करनी हैं',
    ignored: 'हानिरहित अंतर अनदेखे किए गए',
    fix: 'इसे कैसे ठीक करें',
    ignoredTitle: 'वे अंतर जिन्हें हमने अनदेखा किया',
    ignoredText: 'इन सामान्य अंतरों को ठीक करने की आवश्यकता नहीं है।',
    download: 'रिपोर्ट डाउनलोड करें (PDF)',
    again: 'फिर से जाँचें',
    high: 'उच्च',
    medium: 'मध्यम',
    low: 'कम',
    valueFrom: 'से',
    uploadMore: 'एक और दस्तावेज़ जोड़ें',
  },
  mr: {
    back: 'मुख्यपृष्ठावर परत जा',
    title: 'अर्ज करण्यापूर्वी कागदपत्रे तपासा',
    intro:
      'कागदपत्रे अपलोड करा, संभाव्य विसंगती शोधा आणि अर्ज सादर करण्यापूर्वी काय दुरुस्त करायचे ते जाणून घ्या.',
    language: 'मराठी',
    step1: 'कागदपत्रे अपलोड करा',
    step2: 'तपशील तपासत आहे',
    step3: 'तुमचा अहवाल',
    notice: 'डेमोमध्ये फक्त कृत्रिम कागदपत्रे वापरली जातात. खरी कागदपत्रे अपलोड करू नका.',
    drop: 'तुमची कागदपत्रे येथे ओढा आणि सोडा',
    browse: 'फाईल निवडा',
    formats: 'PDF, JPG किंवा PNG · जास्तीत जास्त 5 फाईल्स',
    type: 'कागदपत्राचा प्रकार',
    remove: 'काढून टाका',
    check: 'माझी कागदपत्रे तपासा',
    minimum: 'पुढे जाण्यासाठी किमान 2 कागदपत्रे जोडा',
    types: ['ओळखीचा पुरावा', 'पत्त्याचा पुरावा', 'उत्पन्न प्रमाणपत्र', 'इतर'],
    processingTitle: 'तुमची कागदपत्रे तपासली जात आहेत',
    reading: 'कागदपत्रे वाचत आहे',
    comparing: 'तपशीलांची तुलना करत आहे',
    preparing: 'अहवाल तैयार करत आहे',
    results: 'तुमचा प्री-चेक अहवाल',
    summary: 'समस्या दुरुस्त करायच्या आहेत',
    ignored: 'निरुपद्रवी फरक दुर्लक्षित केले',
    fix: 'हे कसे दुरुस्त करावे',
    ignoredTitle: 'आम्ही दुर्लक्ष केलेले फरक',
    ignoredText: 'हे सामान्य फरक दुरुस्त करण्याची गरज नाही.',
    download: 'अहवाल डाउनलोड करा (PDF)',
    again: 'पुन्हा तपासा',
    high: 'उच्च',
    medium: 'मध्यम',
    low: 'कमी',
    valueFrom: 'मधून',
    uploadMore: 'आणखी एक कागदपत्र जोडा',
  },
};

function CitizenPrecheck({ onBack }) {
  const [lang, setLang] = useState('en');
  const [step, setStep] = useState(1);
  const [files, setFiles] = useState([]);
  const [result, setResult] = useState(null);
  const [ignoredOpen, setIgnoredOpen] = useState(false);
  const t = precheckText[lang];

  const addFiles = (list) => {
    const incoming = Array.from(list)
      .slice(0, 5 - files.length)
      .map((file) => ({
        id: `${file.name}-${file.lastModified}`,
        file,
        type: 0,
        preview: file.type.startsWith('image/') ? URL.createObjectURL(file) : null,
      }));
    setFiles((old) => [...old, ...incoming]);
  };

  const check = async () => {
    if (files.length < 2) return;
    setStep(2);
    const response = await runPrecheck(files);
    setResult(response);
    setStep(3);
  };

  const reset = () => {
    setFiles([]);
    setResult(null);
    setStep(1);
    setIgnoredOpen(false);
  };

  return (
    <div className="precheck">
      <header className="precheck-nav">
        <button onClick={onBack}>← {t.back}</button>
        <div className="public-brand">
          <span>⌘</span> Samanvay
        </div>
        <div className="language-picker" aria-label="Select language">
          {[
            ['en', 'English'],
            ['hi', 'हिंदी'],
            ['mr', 'मराठी'],
          ].map(([key, label]) => (
            <button
              key={key}
              className={lang === key ? 'active' : ''}
              onClick={() => setLang(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </header>
      <main className="precheck-main">
        <div className="precheck-progress" aria-label="Progress">
          {[
            [1, t.step1],
            [2, t.step2],
            [3, t.step3],
          ].map(([number, label]) => (
            <React.Fragment key={number}>
              <div className={step >= number ? 'done' : ''}>
                <b>{step > number ? '✓' : number}</b>
                <span>{label}</span>
              </div>
              {number < 3 && <i className={step > number ? 'done' : ''} />}
            </React.Fragment>
          ))}
        </div>

        {step === 1 && (
          <section className="precheck-upload">
            <span className="precheck-eyebrow">SAMANVAY CITIZEN PRE-CHECK</span>
            <h1>{t.title}</h1>
            <p>{t.intro}</p>
            <div className="synthetic-notice">ⓘ {t.notice}</div>
            <label
              className="citizen-drop"
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => {
                event.preventDefault();
                addFiles(event.dataTransfer.files);
              }}
            >
              <span>⇧</span>
              <b>{t.drop}</b>
              <em>{t.formats}</em>
              <strong>
                {t.browse}
                <input
                  type="file"
                  multiple
                  accept=".pdf,.jpg,.jpeg,.png"
                  onChange={(event) => addFiles(event.target.files)}
                />
              </strong>
            </label>
            {files.length > 0 && (
              <div className="upload-file-list">
                {files.map((item) => (
                  <div className="citizen-file" key={item.id}>
                    {item.preview ? (
                      <img src={item.preview} alt="" />
                    ) : (
                      <span className="pdf-file">PDF</span>
                    )}
                    <div>
                      <b>{item.file.name}</b>
                      <small>{Math.ceil(item.file.size / 1024)} KB</small>
                    </div>
                    <select
                      aria-label={t.type}
                      value={item.type}
                      onChange={(event) =>
                        setFiles((all) =>
                          all.map((file) =>
                            file.id === item.id
                              ? { ...file, type: Number(event.target.value) }
                              : file
                          )
                        )
                      }
                    >
                      {t.types.map((type, index) => (
                        <option key={type} value={index}>
                          {type}
                        </option>
                      ))}
                    </select>
                    <button
                      aria-label={t.remove}
                      onClick={() =>
                        setFiles((all) => all.filter((file) => file.id !== item.id))
                      }
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
            <button className="check-button" disabled={files.length < 2} onClick={check}>
              {t.check} →
            </button>
            <small className="minimum">
              {files.length < 2 ? t.minimum : `${files.length} / 5`}
            </small>
          </section>
        )}

        {step === 2 && (
          <section className="processing">
            <div className="processing-mark">⌘</div>
            <h1>{t.processingTitle}</h1>
            <p>{t.intro}</p>
            <div className="processing-steps">
              {[t.reading, t.comparing, t.preparing].map((label, index) => (
                <div key={label} className={index === 0 ? 'working' : ''}>
                  <span>{index === 0 ? '◌' : index + 1}</span>
                  {label}
                </div>
              ))}
            </div>
          </section>
        )}

        {step === 3 && result && (
          <section className="precheck-results">
            <span className="precheck-eyebrow">SAMANVAY CITIZEN PRE-CHECK</span>
            <h1>{t.results}</h1>
            <div className="result-summary">
              <div>
                <b>{result.findings.length}</b>
                <span>{t.summary}</span>
              </div>
              <i />
              <div>
                <b>{result.ignored.length}</b>
                <span>{t.ignored}</span>
              </div>
            </div>
            <div className="citizen-findings">
              {result.findings.map((finding) => (
                <article key={finding.id} className="citizen-finding">
                  <div className="finding-top">
                    <span className={`citizen-severity ${finding.severity}`}>
                      {t[finding.severity]}
                    </span>
                    <h2>{fieldLabel(finding.field, lang)}</h2>
                  </div>
                  <div className="citizen-values">
                    {finding.values.map((value) => (
                      <div key={value.document}>
                        <small>
                          {t.valueFrom} {value.document}
                        </small>
                        <b>{value.value}</b>
                      </div>
                    ))}
                  </div>
                  <p>{finding.explanation[lang]}</p>
                  <div className="fix-box">
                    <b>✓ {t.fix}</b>
                    <span>{finding.fix[lang]}</span>
                  </div>
                </article>
              ))}
            </div>
            <section className="ignored-box">
              <button
                onClick={() => setIgnoredOpen(!ignoredOpen)}
                aria-expanded={ignoredOpen}
              >
                <span>
                  {t.ignoredTitle}
                  <small>{t.ignoredText}</small>
                </span>
                <b>{ignoredOpen ? '⌃' : '⌄'}</b>
              </button>
              {ignoredOpen && (
                <div>
                  {result.ignored.map((item) => (
                    <p key={item.field}>
                      <b>{fieldLabel(item.field, lang)}:</b> {item.values.join(' · ')}{' '}
                      <span>— {item.reason[lang]}</span>
                    </p>
                  ))}
                </div>
              )}
            </section>
            <div className="result-actions">
              <button onClick={() => window.print()}>↓ {t.download}</button>
              <button onClick={reset}>{t.again} →</button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

function fieldLabel(field, lang) {
  const labels = {
    date_of_birth: ['Date of Birth', 'जन्म तिथि', 'जन्मतारीख'],
    address: ['Address', 'पता', 'पत्ता'],
    name: ['Name', 'नाम', 'नाव'],
    parent_name: ['Parent name', 'माता/पिता का नाम', 'पालकाचे नाव'],
  };
  return labels[field]?.[{ en: 0, hi: 1, mr: 2 }[lang]] || field;
}

createRoot(document.getElementById('root')).render(<App />);
