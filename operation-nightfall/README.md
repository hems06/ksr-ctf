# 🌑 Operation Nightfall

> **A Hard/Insane-tier Web Exploitation CTF Challenge**  
> *Designed for KSR CTF — ₹1.75 Lakh Prize Pool*

---

## Overview

**Operation Nightfall** is a flagship Jeopardy-style CTF challenge that simulates a penetration test against **NovaCorp's Internal DevPortal** — a realistic fintech developer platform built with modern technologies.

Players must chain **4 distinct vulnerabilities** across a multi-service architecture to capture the flag:

```
SSTI → SSRF → Blind SQLi → Deserialization RCE
```

| Property | Value |
|---|---|
| Category | Web Exploitation |
| Difficulty | Hard / Insane |
| Expected Solve Rate | <10% |
| Expected Solve Time | 90–180 minutes |
| Points | 1000 (Dynamic) |
| Flag Format | `flag{...}` |

## Architecture

```
┌──────────────┐     ┌───────────────┐     ┌────────────┐
│   Player     │────▶│  Gateway      │────▶│ Internal   │
│   Browser    │     │  :8080        │     │ API :3001  │
└──────────────┘     │  (Nunjucks)   │     │ (Express)  │
                     └───────┬───────┘     └──┬────┬────┘
                             │                │    │
                     ┌───────▼───────┐  ┌─────▼─┐ ┌▼────────┐
                     │  Redis :6379  │  │ Pg    │ │ Flag    │
                     │  (Sessions)   │  │ :5432 │ │ /tmp/   │
                     └───────────────┘  └───────┘ └─────────┘
                             ▲
                     ┌───────┴───────┐
                     │  Admin Bot    │
                     │  (Session     │
                     │   Refresher)  │
                     └───────────────┘
```

## Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose v2
- Python 3.8+ (for scripts)
- 2 CPU cores, 1.5 GB RAM minimum

### Deploy

```bash
# 1. Configure
cp .env.example .env
python scripts/generate_flag.py --write

# 2. Build and launch
docker compose up -d --build

# 3. Verify
bash scripts/healthcheck.sh

# 4. Test with automated solver
python scripts/solve.py --target http://localhost:8080
```

The challenge will be available at **http://localhost:8080**.

### Tear Down

```bash
bash scripts/cleanup.sh
```

## File Structure

```
operation-nightfall/
├── docker-compose.yml          # Multi-service orchestration
├── .env.example                # Environment template
├── README.md                   # This file
│
├── gateway/                    # Public-facing Express + Nunjucks app
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── app.js              # Main app (SSTI vulnerability)
│       ├── views/              # Nunjucks templates
│       │   ├── base.njk
│       │   ├── index.njk
│       │   ├── status.njk      # Status page template
│       │   ├── login.njk       # Login (hidden credentials in HTML)
│       │   └── dashboard.njk
│       └── public/
│           ├── css/style.css
│           └── js/main.js
│
├── internal-api/               # Internal microservice
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       └── app.js              # SSRF + SQLi + RCE vulnerabilities
│
├── admin-bot/                  # Admin session refresher
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       └── bot.js
│
├── db-init/
│   └── init.sql                # Database schema + seed data
│
├── scripts/
│   ├── healthcheck.sh          # Service verification
│   ├── generate_flag.py        # Per-deployment flag randomization
│   ├── cleanup.sh              # Full teardown
│   └── solve.py                # Automated exploit chain solver
│
├── challenge-files/
│   └── README.md               # Player-facing description
│
└── docs/
    ├── writeup.md              # Official write-up
    └── organizer-notes.md      # Deployment & organizer guide
```

## Documentation

- **[Player Description](challenge-files/README.md)** — What players see
- **[Official Write-up](docs/writeup.md)** — Complete exploit chain walkthrough
- **[Organizer Notes](docs/organizer-notes.md)** — Deployment, scoring, anti-cheat, monitoring

## Exploit Chain Summary

1. **SSTI** — Status page service filter is interpolated into Nunjucks template → leak `INTERNAL_API_KEY` from `process.env`
2. **SSRF** — Webhook test endpoint allows requests to Docker-internal Redis → steal admin session token
3. **Blind SQLi** — Admin search endpoint concatenates SQL → extract `flag_encryption_key` from secrets table
4. **Deserialization RCE** — Admin export endpoint uses vulnerable `node-serialize` → execute `cat /tmp/flag.txt`

## License

This challenge is designed for educational purposes in CTF competitions. All vulnerabilities are intentional and documented.

---

*Created for KSR CTF by the challenge design team.*
