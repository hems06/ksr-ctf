/**
 * NovaCorp Internal API — Microservice
 * 
 * Internal-only Express API serving the DevPortal gateway.
 * 
 * VULNERABILITIES (INTENTIONAL — CTF CHALLENGE):
 * 
 *   1. SSRF via /api/v1/webhooks/test (Step 2)
 *      The webhook testing feature makes HTTP requests to
 *      user-supplied URLs without proper SSRF protection.
 *      This allows access to internal Redis via the redis://
 *      protocol handler (actually via HTTP to Redis's TCP port).
 *      
 *   2. Blind SQL Injection via /api/v1/admin/search (Step 3)
 *      The admin search endpoint concatenates user input into
 *      a SQL query without parameterization.
 *      
 *   3. Deserialization RCE via /api/v1/admin/export (Step 4)
 *      The export endpoint deserializes user-controlled data
 *      using node-serialize, which allows arbitrary code
 *      execution via IIFE payloads.
 */

const express = require('express');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const https = require('https');
const serialize = require('node-serialize');
const Redis = require('ioredis');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || 'intk_a7f3b9c2e1d4068597fabcde12345678';
const JWT_SECRET = process.env.JWT_SECRET || 's3cr3t_jwt_n0v4c0rp_k3y_d0_n0t_l34k';
const FLAG_VALUE = process.env.FLAG_VALUE || 'flag{n1ghtf4ll_ch41n_compl3t3_2024}';

// ============================================================
// Database connection
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://novacorp_app:N0v4C0rp_Pg_2024!@postgres:5432/novacorp',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[Internal-API] Unexpected pool error:', err.message);
});

// ============================================================
// Redis connection
// ============================================================
const redis = new Redis(process.env.REDIS_URL || 'redis://:R3d1s_N0v4_2024!@redis:6379', {
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    if (times > 10) return null;
    return Math.min(times * 200, 2000);
  },
  lazyConnect: true,
});

redis.on('error', (err) => {
  console.error('[Internal-API] Redis error:', err.message);
});

redis.connect().catch((err) => {
  console.error('[Internal-API] Redis connection failed:', err.message);
});

// ============================================================
// Write the flag file at startup
// ============================================================
const fs = require('fs');
try {
  fs.writeFileSync('/tmp/flag.txt', FLAG_VALUE + '\n');
  console.log('[Internal-API] Flag written to /tmp/flag.txt');
} catch (err) {
  console.error('[Internal-API] Could not write flag file:', err.message);
}

// ============================================================
// Middleware
// ============================================================
app.use(morgan('combined'));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// --- Internal API key validation ---
// All requests must include the X-Internal-Key header
function requireInternalKey(req, res, next) {
  const key = req.headers['x-internal-key'];
  if (!key || key !== INTERNAL_API_KEY) {
    return res.status(403).json({ error: 'Invalid internal API key' });
  }
  next();
}

app.use('/api', requireInternalKey);

// --- Extract user info from headers (set by gateway) ---
function extractUser(req, res, next) {
  req.userId = req.headers['x-user-id'] || null;
  req.userRole = req.headers['x-user-role'] || 'developer';
  next();
}

app.use('/api', extractUser);

// --- Require admin role ---
function requireAdmin(req, res, next) {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================

app.post('/api/v1/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, role, password_hash FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Simple hash comparison (bcrypt would be used in production)
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    if (hash !== user.password_hash) {
      // Log failed attempt
      await pool.query(
        'INSERT INTO audit_logs (action, details, ip_address) VALUES ($1, $2, $3)',
        ['login_failed', JSON.stringify({ username }), req.ip]
      );
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session in Redis
    const sessionToken = `sess_${uuidv4().replace(/-/g, '')}`;
    const sessionData = JSON.stringify({
      id: user.id,
      username: user.username,
      role: user.role,
      created_at: new Date().toISOString(),
    });

    await redis.set(`session:${sessionToken}`, sessionData, 'EX', 3600);

    // Audit log
    await pool.query(
      'INSERT INTO audit_logs (action, user_id, details, ip_address) VALUES ($1, $2, $3, $4)',
      ['login_success', user.id, JSON.stringify({ username: user.username }), req.ip]
    );

    res.json({
      session_token: sessionToken,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('[Internal-API] Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// PROJECT ROUTES
// ============================================================

app.get('/api/v1/projects', async (req, res) => {
  try {
    let query = 'SELECT * FROM projects ORDER BY updated_at DESC';
    let params = [];

    // Non-admin users only see their own projects
    if (req.userRole !== 'admin' && req.userId) {
      query = 'SELECT * FROM projects WHERE owner_id = $1 ORDER BY updated_at DESC';
      params = [req.userId];
    }

    const result = await pool.query(query, params);
    res.json({ projects: result.rows });
  } catch (err) {
    console.error('[Internal-API] Projects fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// ============================================================
// WEBHOOK ROUTES — VULNERABLE TO SSRF (Step 2)
// ============================================================
// 
// The webhook test endpoint makes an HTTP request to a
// user-supplied URL. There is a blocklist check, but it
// only blocks common cloud metadata IPs and uses string
// matching that can be bypassed with:
//   - Alternative IP representations (0x7f000001, 017700000001)
//   - DNS rebinding
//   - Redirect chains
//   - Using the service name 'redis' directly (Docker DNS)
// 
// The player uses this to send raw Redis commands via HTTP:
//   POST /api/v1/webhooks/test
//   { "url": "http://redis:6379/" }
// 
// Redis responds to HTTP requests with error messages that
// contain data, allowing the player to dump session keys
// and steal the admin session token.
// ============================================================

app.post('/api/v1/webhooks/test', async (req, res) => {
  const { url, method, headers: customHeaders, body } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // "Security" blocklist — intentionally incomplete
  const blockedPatterns = [
    '169.254.169.254',     // AWS metadata
    'metadata.google.internal', // GCP metadata
    '100.100.100.200',     // Alibaba metadata
    'localhost',           // Basic localhost block
    '0.0.0.0',             // Null route
  ];

  const urlLower = url.toLowerCase();

  for (const pattern of blockedPatterns) {
    if (urlLower.includes(pattern)) {
      return res.status(403).json({
        error: 'Blocked: URL matches security blocklist',
        detail: 'Internal and metadata endpoints are restricted.',
      });
    }
  }

  // Note: 127.0.0.1 is NOT in the blocklist (oversight).
  // Note: Docker internal hostnames like 'redis', 'postgres'
  //       are NOT blocked (realistic misconfiguration).

  try {
    const parsedUrl = new URL(url);
    const requestMethod = (method || 'GET').toUpperCase();

    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: requestMethod,
      headers: {
        'User-Agent': 'NovaCorp-Webhook/1.0',
        ...(customHeaders || {}),
      },
      timeout: 5000,
    };

    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const proxyResponse = await new Promise((resolve, reject) => {
      const proxyReq = protocol.request(requestOptions, (proxyRes) => {
        let responseData = '';
        proxyRes.on('data', (chunk) => {
          responseData += chunk;
          // Limit response size
          if (responseData.length > 65536) {
            proxyReq.destroy();
            reject(new Error('Response too large'));
          }
        });
        proxyRes.on('end', () => {
          resolve({
            status: proxyRes.statusCode,
            headers: proxyRes.headers,
            body: responseData,
          });
        });
      });

      proxyReq.on('error', reject);
      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        reject(new Error('Request timed out'));
      });

      if (body && ['POST', 'PUT', 'PATCH'].includes(requestMethod)) {
        proxyReq.write(typeof body === 'string' ? body : JSON.stringify(body));
      }

      proxyReq.end();
    });

    // Audit log
    await pool.query(
      'INSERT INTO audit_logs (action, user_id, details, ip_address) VALUES ($1, $2, $3, $4)',
      ['webhook_test', req.userId, JSON.stringify({ url, status: proxyResponse.status }), req.ip]
    ).catch(() => {}); // Don't fail the request if audit fails

    res.json({
      success: true,
      response: {
        status: proxyResponse.status,
        headers: proxyResponse.headers,
        body: proxyResponse.body.substring(0, 4096), // Truncate for display
        truncated: proxyResponse.body.length > 4096,
      },
    });
  } catch (err) {
    res.status(502).json({
      success: false,
      error: 'Webhook test failed',
      detail: err.message,
    });
  }
});

// ============================================================
// ADMIN ROUTES — REQUIRE ADMIN ROLE
// ============================================================

// --- Admin Search — VULNERABLE TO BLIND SQL INJECTION (Step 3) ---
// 
// The search query parameter is concatenated directly into
// the SQL query without parameterization. The vulnerability
// is BLIND (no direct output), so players must use time-based
// or boolean-based extraction techniques.
// 
// Payload example (time-based blind):
//   /api/v1/admin/search?q=x' AND (SELECT CASE WHEN 
//     (SELECT substring(secret_value,1,1) FROM secrets WHERE 
//     secret_name='flag_encryption_key')='a' THEN pg_sleep(2) 
//     ELSE pg_sleep(0) END)-- -
// 
// Players extract the flag_encryption_key from the secrets table,
// which they'll need in Step 4 (or they can skip directly to RCE).
// ============================================================

app.get('/api/v1/admin/search', requireAdmin, async (req, res) => {
  const query = req.query.q || '';
  
  if (!query) {
    return res.status(400).json({ error: 'Search query required (parameter: q)' });
  }

  try {
    // VULNERABILITY: Direct string concatenation in SQL query
    const sqlQuery = `
      SELECT id, username, role, created_at 
      FROM users 
      WHERE username LIKE '%${query}%' OR role LIKE '%${query}%'
      ORDER BY created_at DESC
      LIMIT 20
    `;

    const result = await pool.query(sqlQuery);

    // Audit log
    await pool.query(
      'INSERT INTO audit_logs (action, user_id, details, ip_address) VALUES ($1, $2, $3, $4)',
      ['admin_search', req.userId, JSON.stringify({ query: query.substring(0, 100) }), req.ip]
    ).catch(() => {});

    res.json({
      query: query,
      count: result.rows.length,
      results: result.rows,
    });
  } catch (err) {
    // Return generic error — don't reveal SQL details
    // (but the error handling itself is a clue that something is wrong)
    console.error('[Internal-API] Search error:', err.message);
    res.status(500).json({
      error: 'Search failed',
      // Subtle hint: the error message structure changes on SQL errors
      detail: 'An error occurred while processing your search query.',
    });
  }
});

// --- Admin Users List ---
app.get('/api/v1/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, role, created_at FROM users ORDER BY id'
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error('[Internal-API] Users list error:', err.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// --- Admin Audit Logs ---
app.get('/api/v1/admin/audit', requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const result = await pool.query(
      'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    res.json({ logs: result.rows });
  } catch (err) {
    console.error('[Internal-API] Audit logs error:', err.message);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ============================================================
// ADMIN EXPORT — VULNERABLE TO DESERIALIZATION RCE (Step 4)
// ============================================================
// 
// The export endpoint accepts a Base64-encoded "template" that
// is deserialized using node-serialize. The node-serialize
// library (CVE-2017-5941) allows arbitrary code execution
// via serialized JavaScript functions with IIFE notation.
// 
// Payload construction:
//   1. Create a serialized object with an IIFE:
//      {"rce":"_$$ND_FUNC$$_function(){require('child_process')
//       .execSync('cat /tmp/flag.txt').toString()}()"}
//   2. Base64-encode it
//   3. Send as the "template" parameter
// 
// The server deserializes the payload, executing the function
// and returning the flag in the response.
// ============================================================

app.post('/api/v1/admin/export', requireAdmin, async (req, res) => {
  const { format, template, filters } = req.body;

  if (!format) {
    return res.status(400).json({ error: 'Export format required (json, csv, custom)' });
  }

  try {
    // Fetch data to export
    const result = await pool.query(
      'SELECT id, username, role, created_at FROM users ORDER BY id'
    );
    const users = result.rows;

    let exportData;

    if (format === 'json') {
      exportData = JSON.stringify(users, null, 2);
    } else if (format === 'csv') {
      const header = 'id,username,role,created_at';
      const rows = users.map(u => `${u.id},${u.username},${u.role},${u.created_at}`);
      exportData = [header, ...rows].join('\n');
    } else if (format === 'custom' && template) {
      // VULNERABILITY: Deserialize user-supplied template data
      // using the vulnerable node-serialize library.
      // The template is expected to be a Base64-encoded serialized
      // object that defines the export format.
      try {
        const decoded = Buffer.from(template, 'base64').toString('utf-8');
        
        // "Validation" — checks that it looks like JSON
        // But node-serialize's $$ND_FUNC$$ notation passes this check
        if (!decoded.startsWith('{')) {
          return res.status(400).json({ error: 'Invalid template format. Expected JSON object.' });
        }

        // VULNERABLE CALL: node-serialize.unserialize()
        const templateObj = serialize.unserialize(decoded);

        // Build export using the deserialized template
        exportData = JSON.stringify({
          title: templateObj.title || 'User Export',
          generated_at: new Date().toISOString(),
          format: templateObj.format || 'custom',
          data: users,
          // If the deserialized object has a computed property,
          // its return value will appear here
          metadata: templateObj,
        }, null, 2);
      } catch (deserializeErr) {
        return res.status(400).json({
          error: 'Template deserialization failed',
          detail: deserializeErr.message,
        });
      }
    } else {
      return res.status(400).json({ error: 'Invalid format. Use json, csv, or custom.' });
    }

    // Audit log
    await pool.query(
      'INSERT INTO audit_logs (action, user_id, details, ip_address) VALUES ($1, $2, $3, $4)',
      ['admin_export', req.userId, JSON.stringify({ format }), req.ip]
    ).catch(() => {});

    res.json({
      success: true,
      format,
      size: exportData.length,
      data: exportData,
    });
  } catch (err) {
    console.error('[Internal-API] Export error:', err.message);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({
      status: 'ok',
      service: 'internal-api',
      timestamp: new Date().toISOString(),
      dependencies: { postgres: 'ok', redis: 'ok' },
    });
  } catch (err) {
    res.status(503).json({
      status: 'degraded',
      error: err.message,
    });
  }
});

// ============================================================
// 404 and Error Handlers
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.originalUrl,
    documentation: 'Contact devops@novacorp.internal for API documentation',
  });
});

app.use((err, req, res, _next) => {
  console.error('[Internal-API] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// Start server
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Internal-API] Running on port ${PORT}`);
});
