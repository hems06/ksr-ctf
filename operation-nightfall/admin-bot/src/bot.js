/**
 * NovaCorp Admin Bot — Session Refresher
 * 
 * This bot simulates an admin user by periodically refreshing
 * the admin session token in Redis. This ensures that when
 * players perform SSRF against Redis in Step 2, there is
 * always a valid admin session to steal.
 * 
 * The bot writes:
 *   session:<ADMIN_SESSION_TOKEN> -> { id: 1, username: "admin", role: "admin" }
 * 
 * This session token is what players extract from Redis
 * to gain admin access to the Internal API.
 */

const Redis = require('ioredis');

const REDIS_URL = process.env.REDIS_URL || 'redis://:R3d1s_N0v4_2024!@redis:6379';
const ADMIN_SESSION_TOKEN = process.env.ADMIN_SESSION_TOKEN || 'sess_adm1n_7f3b9c2e1d40685_n0v4c0rp';
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || '1';
const REFRESH_INTERVAL = parseInt(process.env.REFRESH_INTERVAL_MS) || 30000;

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: null,
  retryStrategy(times) {
    if (times > 50) return null;
    return Math.min(times * 500, 5000);
  },
  lazyConnect: true,
});

redis.on('error', (err) => {
  console.error('[Admin-Bot] Redis error:', err.message);
});

async function refreshAdminSession() {
  const sessionData = JSON.stringify({
    id: parseInt(ADMIN_USER_ID),
    username: 'admin',
    role: 'admin',
    created_at: new Date().toISOString(),
    refreshed_by: 'admin-bot',
  });

  try {
    // Set the admin session with a 5-minute TTL
    // (bot refreshes every 30s, so it's always valid)
    await redis.set(
      `session:${ADMIN_SESSION_TOKEN}`,
      sessionData,
      'EX',
      300
    );

    console.log(`[Admin-Bot] Refreshed admin session (TTL: 300s)`);
  } catch (err) {
    console.error('[Admin-Bot] Failed to refresh session:', err.message);
  }
}

async function main() {
  console.log('[Admin-Bot] Starting admin session refresher');
  console.log(`[Admin-Bot] Token: ${ADMIN_SESSION_TOKEN.substring(0, 12)}...`);
  console.log(`[Admin-Bot] Interval: ${REFRESH_INTERVAL}ms`);

  try {
    await redis.connect();
    console.log('[Admin-Bot] Connected to Redis');
  } catch (err) {
    console.error('[Admin-Bot] Initial connection failed:', err.message);
    console.log('[Admin-Bot] Will retry on next refresh cycle');
  }

  // Initial refresh
  await refreshAdminSession();

  // Periodic refresh
  setInterval(refreshAdminSession, REFRESH_INTERVAL);

  // Also maintain a "hint" key that lists active sessions
  // This is what players will discover via SSRF to Redis
  setInterval(async () => {
    try {
      await redis.set('admin:last_active', new Date().toISOString(), 'EX', 300);
      
      // Store a list of known session prefixes (breadcrumb for players)
      await redis.set(
        'system:active_sessions_info',
        JSON.stringify({
          note: 'Active session tokens are stored as session:<token>',
          admin_token_prefix: ADMIN_SESSION_TOKEN.substring(0, 15),
          total_active: 1,
          last_refresh: new Date().toISOString(),
        }),
        'EX',
        300
      );
    } catch (err) {
      // Silently ignore
    }
  }, REFRESH_INTERVAL);
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[Admin-Bot] Shutting down...');
  await redis.quit();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[Admin-Bot] Interrupted, shutting down...');
  await redis.quit();
  process.exit(0);
});

main().catch((err) => {
  console.error('[Admin-Bot] Fatal error:', err);
  process.exit(1);
});
