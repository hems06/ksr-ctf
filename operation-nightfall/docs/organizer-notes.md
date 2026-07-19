# Operation Nightfall — Organizer Notes

## Quick Start Deployment

```bash
# 1. Clone and enter directory
cd operation-nightfall/

# 2. Generate unique flag
cp .env.example .env
python scripts/generate_flag.py --write

# 3. Build and deploy
docker compose up -d --build

# 4. Verify
bash scripts/healthcheck.sh
python scripts/solve.py --target http://localhost:8080

# 5. Expose port 8080 to players
```

---

## Challenge Metadata

| Property | Value |
|---|---|
| Title | Operation Nightfall |
| Category | Web Exploitation |
| Difficulty | Hard / Insane |
| Expected Solve Rate | <10% |
| Expected Solve Time | 90–180 minutes |
| Points | 1000 (Dynamic scoring) |
| Flag Format | `flag{...}` |

---

## Scoring Recommendation

Use **dynamic scoring** with the following parameters:

| Parameter | Value |
|---|---|
| Initial Points | 1000 |
| Minimum Points | 200 |
| Decay Rate | 15 (points drop after 15 solves) |

**Hint penalties:**
- Hint 1: Free (direction toward status page)
- Hint 2: -50 points (SSTI confirmation)
- Hint 3: -100 points (internal services)
- Hint 4: -150 points (credentials + SSRF)
- Hint 5: -200 points (CVE reference for final step)

---

## Resource Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 1.5 GB | 3 GB |
| Disk | 2 GB | 5 GB |
| Network | Internal + 1 exposed port | Same |

### Per-Service Breakdown

- **PostgreSQL:** ~200 MB RAM
- **Redis:** ~64 MB RAM (capped)
- **Gateway:** ~100 MB RAM
- **Internal API:** ~100 MB RAM
- **Admin Bot:** ~50 MB RAM

---

## Architecture & Security

### Network Isolation

```
Public Network (exposed):
  └─ Gateway (:8080)

Internal Network (isolated):
  ├─ Gateway (also on internal)
  ├─ Internal API (:3001)
  ├─ Admin Bot
  ├─ PostgreSQL (:5432)
  └─ Redis (:6379)
```

- Only port **8080** is exposed externally
- Internal services use Docker's bridge network with `internal: true`
- All containers run as **non-root** with `read_only: true` filesystem
- `no-new-privileges` security option prevents privilege escalation
- tmpfs mounts for writable areas (limited to 64MB)

### Sandboxing

- Each service runs in its own container with minimal privileges
- The flag file is written to `/tmp/flag.txt` at startup (writable tmpfs)
- PostgreSQL data is in a Docker volume (not accessible from other containers)
- Redis has a password and memory limit

---

## Anti-Cheat Considerations

### Flag Sharing Prevention
- **Randomize flags** per deployment using `scripts/generate_flag.py`
- If running per-team instances, each team gets a unique flag
- Monitor submission patterns for identical flags from different IPs

### Monitoring & Logging
- All services log to stdout (viewable via `docker compose logs`)
- The Internal API logs all webhook tests, admin searches, and exports to the `audit_logs` table
- Monitor for:
  - Rapid SSTI payload attempts (indicates automated tooling)
  - SSRF requests to unexpected hosts
  - SQLi patterns in search queries
  - Base64-encoded deserialization payloads in export requests

### Log Monitoring Commands

```bash
# Watch all logs
docker compose logs -f

# Watch specific service
docker compose logs -f gateway
docker compose logs -f internal-api

# Check audit logs in database
docker compose exec postgres psql -U novacorp_app -d novacorp \
  -c "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20;"
```

### Preventing Accidental Shortcuts

1. **No direct flag access:** The flag is in `/tmp/flag.txt` inside the `internal-api` container, which is on the internal network only
2. **No path traversal:** Express's `express.static` only serves from the `public/` directory
3. **No direct Redis access:** Redis is on the internal network with password auth
4. **No direct PostgreSQL access:** Database is on the internal network only
5. **API key required:** All internal API endpoints require the `X-Internal-Key` header
6. **Role-based access:** Admin endpoints require `role: admin` in the session

---

## Common Rabbit Holes

Players may waste time on:

1. **Trying XSS instead of SSTI** — The status page has CSP disabled, but XSS is not the intended path
2. **Brute-forcing login** — Rate limiting is in place; the credentials are in the HTML source
3. **Trying to access internal services directly** — They're on an isolated network
4. **Looking for file upload/path traversal** — No such vulnerabilities exist
5. **Trying to crack JWT tokens** — The JWT secret is in the environment, but JWT isn't the attack vector
6. **Attempting SSRF to cloud metadata** — The blocklist blocks metadata endpoints; Redis is the target

---

## Unintended Solves & Mitigations

### Potential Unintended: Direct process.env via SSTI
**Status:** Intended. The SSTI leaking env vars IS Step 1.

### Potential Unintended: Using sqlmap for Step 3
**Status:** Acceptable. sqlmap works but is slower than manual extraction. The SQLi step is optional anyway.

### Potential Unintended: RCE via SSTI instead of deserialization
**Mitigation:** Nunjucks SSTI in this configuration allows reading env vars but doesn't provide direct command execution due to the template rendering context. The `range.constructor` trick returns values but can't execute system commands.

### Potential Unintended: Skipping Step 3 (SQLi)
**Status:** By design. Step 3 is optional — players can go directly from Step 2 (admin access) to Step 4 (RCE). This rewards faster solvers.

---

## Challenge Testing Checklist

Before going live, verify:

- [ ] `docker compose up -d --build` completes without errors
- [ ] `scripts/healthcheck.sh` passes all checks
- [ ] `scripts/solve.py` successfully captures the flag
- [ ] SSTI payload `{{7*7}}` returns `49` on `/status`
- [ ] Developer login works with `developer:N0v4D3v2024`
- [ ] Webhook SSRF to `redis:6379` returns data
- [ ] Admin search is vulnerable to SQLi
- [ ] Custom export accepts node-serialize payload
- [ ] Flag file exists at `/tmp/flag.txt` in internal-api container
- [ ] Internal services are NOT accessible from outside Docker
- [ ] Rate limiting is active (120 req/min)
- [ ] Multiple concurrent players don't interfere with each other
- [ ] Cleanup script works: `scripts/cleanup.sh`
- [ ] Fresh redeploy works after cleanup

---

## Expected Solver Methodology

1. **Reconnaissance** (10-15 min)
   - Browse the portal, inspect page source
   - Discover `/status` endpoint with service filter
   - Notice version numbers, technology hints

2. **SSTI Discovery** (15-20 min)
   - Test the service filter with template syntax
   - Confirm Nunjucks SSTI
   - Extract environment variables

3. **Pivoting to Internal Network** (20-30 min)
   - Find developer credentials in HTML comments
   - Login and explore the dashboard/API
   - Discover webhook testing feature
   - Identify SSRF potential

4. **Session Theft** (15-20 min)
   - Use SSRF to communicate with Redis
   - Enumerate session keys
   - Steal admin session token

5. **Privilege Escalation** (10-15 min)
   - Use admin session to access admin endpoints
   - Discover admin search (SQLi) and export features

6. **RCE** (15-30 min)
   - Identify node-serialize in the export feature
   - Research CVE-2017-5941
   - Craft deserialization payload
   - Read flag file

---

## Cleanup

```bash
# Full cleanup
bash scripts/cleanup.sh

# Or manually
docker compose down -v --rmi local
```

---

## Credits & Inspiration

- Uber SSTI (HackerOne #125980)
- Capital One SSRF breach
- NPM node-serialize CVE-2017-5941
- OWASP Testing Guide v4
- PortSwigger Web Security Academy
