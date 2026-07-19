/**
 * NovaCorp Internal DevPortal — API Gateway
 * 
 * Public-facing Express application with Nunjucks templating.
 * 
 * VULNERABILITY (INTENTIONAL — CTF CHALLENGE):
 *   The /status endpoint renders user-supplied "service" parameter
 *   directly into a Nunjucks template string without sanitization,
 *   enabling Server-Side Template Injection (SSTI).
 * 
 *   This leaks environment variables including INTERNAL_API_KEY,
 *   which is Step 1 of the exploit chain.
 */

const express = require('express');
const nunjucks = require('nunjucks');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const INTERNAL_API_URL = process.env.INTERNAL_API_URL || 'http://internal-api:3001';
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || 'intk_a7f3b9c2e1d4068597fabcde12345678';
const SESSION_SECRET = process.env.SESSION_SECRET || 'g4t3w4y_s3ss10n_s3cr3t_n0v4';
const REDIS_URL = process.env.REDIS_URL || 'redis://:R3d1s_N0v4_2024!@redis:6379';

// ============================================================
// Redis client for session validation
// ============================================================
const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    if (times > 10) return null;
    return Math.min(times * 200, 2000);
  },
  lazyConnect: true,
});

redis.on('error', (err) => {
  console.error('[Gateway] Redis error:', err.message);
});

redis.connect().catch((err) => {
  console.error('[Gateway] Redis connection failed:', err.message);
});

// ============================================================
// Nunjucks configuration
// ============================================================
const njkEnv = nunjucks.configure(path.join(__dirname, 'views'), {
  autoescape: true,
  express: app,
  noCache: false,
  trimBlocks: true,
  lstripBlocks: true,
});

// Add custom filters to make the app look realistic
njkEnv.addFilter('timeago', (date) => {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
});

njkEnv.addFilter('truncate', (str, len) => {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
});

// ============================================================
// Middleware
// ============================================================
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for CTF — allows inline scripts
  crossOriginEmbedderPolicy: false,
}));

app.use(morgan('combined'));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser(SESSION_SECRET));

// Rate limiting — generous for CTF but prevents abuse
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Please slow down.' },
});
app.use(limiter);

// Static files
app.use('/static', express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  etag: true,
}));

// ============================================================
// Helper: validate session token against Redis
// ============================================================
async function validateSession(token) {
  if (!token) return null;
  try {
    const sessionData = await redis.get(`session:${token}`);
    if (sessionData) {
      return JSON.parse(sessionData);
    }
  } catch (err) {
    console.error('[Gateway] Session validation error:', err.message);
  }
  return null;
}

// ============================================================
// Auth middleware
// ============================================================
async function requireAuth(req, res, next) {
  const token = req.cookies.session_token || req.headers['x-session-token'];
  const user = await validateSession(token);
  if (!user) {
    return res.redirect('/login?error=unauthorized');
  }
  req.user = user;
  next();
}

// ============================================================
// ROUTES
// ============================================================

// --- Landing Page ---
app.get('/', (req, res) => {
  res.render('index.njk', {
    title: 'NovaCorp DevPortal',
    year: new Date().getFullYear(),
  });
});

// --- Login Page ---
app.get('/login', (req, res) => {
  res.render('login.njk', {
    title: 'Sign In — NovaCorp DevPortal',
    error: req.query.error || null,
    year: new Date().getFullYear(),
  });
});

// --- Login Handler ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.redirect('/login?error=missing_fields');
  }

  try {
    // Proxy authentication to internal API
    const response = await axios.post(`${INTERNAL_API_URL}/api/v1/auth/login`, {
      username,
      password,
    }, {
      headers: { 'X-Internal-Key': INTERNAL_API_KEY },
      timeout: 5000,
    });

    if (response.data && response.data.session_token) {
      res.cookie('session_token', response.data.session_token, {
        httpOnly: true,
        maxAge: 3600000, // 1 hour
        sameSite: 'strict',
      });
      return res.redirect('/dashboard');
    }
  } catch (err) {
    const msg = err.response?.data?.error || 'auth_failed';
    return res.redirect(`/login?error=${encodeURIComponent(msg)}`);
  }

  return res.redirect('/login?error=auth_failed');
});

// --- Dashboard (authenticated) ---
app.get('/dashboard', requireAuth, async (req, res) => {
  let projects = [];
  try {
    const response = await axios.get(`${INTERNAL_API_URL}/api/v1/projects`, {
      headers: {
        'X-Internal-Key': INTERNAL_API_KEY,
        'X-User-Id': req.user.id,
      },
      timeout: 5000,
    });
    projects = response.data.projects || [];
  } catch (err) {
    console.error('[Gateway] Failed to fetch projects:', err.message);
  }

  res.render('dashboard.njk', {
    title: 'Dashboard — NovaCorp DevPortal',
    user: req.user,
    projects,
    year: new Date().getFullYear(),
  });
});

// --- Logout ---
app.post('/logout', async (req, res) => {
  const token = req.cookies.session_token;
  if (token) {
    try {
      await redis.del(`session:${token}`);
    } catch (err) {
      console.error('[Gateway] Logout error:', err.message);
    }
  }
  res.clearCookie('session_token');
  res.redirect('/');
});

// ============================================================
// STATUS PAGE — VULNERABLE TO SSTI
// ============================================================
// 
// The /status endpoint accepts a "service" query parameter and
// renders it directly into a Nunjucks template string.
// 
// Normal usage:   /status?service=api-gateway
// SSTI payload:   /status?service={{range.constructor("return process.env")()}}
// 
// This is the entry point (Step 1) of the exploit chain.
// Players discover INTERNAL_API_KEY from the environment.
// ============================================================
app.get('/status', (req, res) => {
  const service = req.query.service || 'all';
  const timestamp = new Date().toISOString();

  // Simulated service statuses
  const services = {
    'api-gateway': { name: 'API Gateway', status: 'operational', latency: '12ms', uptime: '99.97%' },
    'auth-service': { name: 'Auth Service', status: 'operational', latency: '8ms', uptime: '99.99%' },
    'database': { name: 'PostgreSQL Primary', status: 'operational', latency: '3ms', uptime: '99.95%' },
    'cache': { name: 'Redis Cluster', status: 'operational', latency: '1ms', uptime: '100%' },
    'storage': { name: 'Object Storage', status: 'degraded', latency: '145ms', uptime: '98.2%' },
    'ml-pipeline': { name: 'ML Pipeline', status: 'maintenance', latency: 'N/A', uptime: '95.1%' },
  };

  // ============================================================
  // VULNERABILITY: User input 'service' is interpolated directly
  // into a Nunjucks template string without sanitization.
  // The autoescape only protects against XSS, not SSTI.
  // ============================================================
  const templateString = `
    {% extends "status.njk" %}
    {% block status_content %}
    <div class="status-query">
      <p class="query-label">Service filter: <code>${service}</code></p>
      <p class="query-time">Checked at: ${timestamp}</p>
    </div>
    {% endblock %}
  `;

  try {
    const rendered = nunjucks.renderString(templateString, {
      title: 'System Status — NovaCorp DevPortal',
      services,
      timestamp,
      year: new Date().getFullYear(),
    });
    res.send(rendered);
  } catch (err) {
    // Return a generic error — don't leak template engine details
    // (but observant players will notice it's a template error)
    res.status(500).render('status.njk', {
      title: 'System Status — NovaCorp DevPortal',
      services,
      timestamp,
      error: 'An internal error occurred while rendering the status page.',
      year: new Date().getFullYear(),
    });
  }
});

// --- API Proxy (authenticated users can interact with internal API) ---
app.all('/api/v1/*', requireAuth, async (req, res) => {
  const targetPath = req.originalUrl;
  try {
    const response = await axios({
      method: req.method,
      url: `${INTERNAL_API_URL}${targetPath}`,
      headers: {
        'X-Internal-Key': INTERNAL_API_KEY,
        'X-User-Id': req.user.id,
        'X-User-Role': req.user.role,
        'Content-Type': req.headers['content-type'] || 'application/json',
      },
      data: req.body,
      timeout: 10000,
      validateStatus: () => true,
    });

    res.status(response.status).json(response.data);
  } catch (err) {
    console.error('[Gateway] API proxy error:', err.message);
    res.status(502).json({ error: 'Internal service unavailable' });
  }
});

// --- Health endpoint (not exposed to players, used by Docker) ---
app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', service: 'gateway', timestamp: new Date().toISOString() });
});

// --- 404 handler ---
app.use((req, res) => {
  res.status(404).render('index.njk', {
    title: '404 — NovaCorp DevPortal',
    error: 'Page not found',
    year: new Date().getFullYear(),
  });
});

// --- Error handler ---
app.use((err, req, res, _next) => {
  console.error('[Gateway] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// Start server
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Gateway] NovaCorp DevPortal running on port ${PORT}`);
  console.log(`[Gateway] Internal API: ${INTERNAL_API_URL}`);
});
