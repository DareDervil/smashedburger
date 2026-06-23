# smashedburger

smashedburger is a proof-of-concept security consultant agent built on Claude (Anthropic). The user chats naturally about CVEs and software packages; the agent calls structured external sources, assembles the data, and returns grounded security briefings — vendor advisories, CVSS analysis, exploit probability, supply-chain compromise verdicts, IOC-backed detection guidance — while passively building a model of the user's environment as a side-effect of normal use.

Built to learn how large language models work, how to build agents, and to experiment with security tooling. It is not a commercial product, has not been security-audited, and is not hardened for production use.

For a full description of the agent loop, grounded verification pass, learning loop, and self-observability, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Features

- **CVE briefings** — CVSS breakdown, EPSS exploit probability, patch versions, workarounds, mitigations, detection guidance, CISA KEV status
- **Vendor advisories** — Palo Alto Networks, Cisco PSIRT, Fortinet, Citrix, Broadcom/VMware, Red Hat, Ubuntu, Microsoft MSRC, GitHub Advisory Database
- **Supply-chain analysis** — OSV vulnerability history, malicious-package detection, Socket.dev behavioral risk scores, package registry health signals
- **War Room** — CVE-centric dashboard with severity badges, Exploit-DB counts, KEV status, IOC list, per-CVE news monitor, actionable checklist
- **IOC extraction** — structured pull of IPs, domains, file hashes, YARA/Sigma rules from Exa-grounded threat intelligence sources
- **Local attack graph** — D3.js force-directed graph of CVEs, infrastructure, and weakness classes; blast radius on CVE click with animated threat propagation; CWE tooltips from MITRE REST API
- **Infrastructure model** — vendors and products passively discovered from CVE.org CPE data as conversations happen; fed back as context for future turns
- **News monitoring** — dated Exa searches per tracked CVE on a due-based schedule
- **Learning recommendations** — daily analysis of past conversations surfaces curated educational reading (OWASP, PortSwigger, FIRST.org, Snyk Learn)
- **Self-observability** — token/latency telemetry instrumented at three points; twice-daily Opus advisory pass surfaces optimization suggestions

---

## Local setup

### Prerequisites

- Python 3.12 or later
- API keys — see the table below

### Install

```bash
git clone https://github.com/daredervil/smashedburger.git
cd smashedburger

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Configure

Generate a `SECRET_KEY` and create your `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
cp .env.example .env
# Paste the output above as SECRET_KEY, then fill in your API keys
```

The minimum set to get the app running:

```
ANTHROPIC_API_KEY=...
EXA_API_KEY=...
SECRET_KEY=<generated above>
SECURE_COOKIES=0        # required for local HTTP
LOG_LEVEL=DEBUG         # optional, verbose output
```

### Run

```bash
python main.py
```

The app starts on `http://localhost:5000`. Go to `/auth/register` to create your account. Without SMTP configured, your 2FA code is printed directly to the terminal — copy it from there when prompted.

> **Tailwind CSS:** a compiled `static/tailwind.css` is included. If you modify Tailwind classes in the templates, rebuild it with Node.js installed:
> ```bash
> ./node_modules/.bin/tailwindcss -i tailwind.input.css -o static/tailwind.css --minify
> ```

### Reset locally

**Full wipe (delete the file):**

```bash
# Stop the app first, then:
rm smashedburger.db
python main.py      # schema is recreated on startup
```

**Soft reset (keep schema and user account):**

```bash
python3 scripts/reset_db.py           # prompts for confirmation
python3 scripts/reset_db.py --confirm # skips prompt
python3 scripts/reset_db.py --confirm --wipe-users  # also clears auth tables
```

Go to `/auth/register` after a full wipe to create a new account. Never delete the database file while the app is running.

---

## Environment variables

| Variable | Status | What breaks without it |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Required** | App is non-functional — every LLM call fails |
| `EXA_API_KEY` | **Required for full functionality** | IOC search, news monitoring, learning recommendations, and package intel are all disabled |
| `SECRET_KEY` | **Required** | App refuses to start — a random fallback would silently invalidate all sessions on every restart |
| `SECURE_COOKIES` | **Required locally** | Set to `0` for local HTTP. Defaults to `1` (HTTPS only). |
| `GROQ_API_KEY` | Optional | Grounded verification pass is skipped; briefings are not cross-checked against tool outputs |
| `VIRUSTOTAL_API_KEY` | Optional | File hash lookups in the War Room are disabled |
| `SOCKET_API_KEY` | Optional | Socket.dev supply-chain scores are skipped |
| `CISCO_API_KEY` + `CISCO_CLIENT_SECRET` | Optional | Cisco PSIRT advisories are disabled |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Optional | 2FA and password-reset codes are printed to the console instead of emailed |
| `DB_PATH` | Optional | SQLite file location; defaults to `smashedburger.db` in the project directory |
| `LOG_LEVEL` | Optional | Logging verbosity: `DEBUG` or `INFO` (default). |
| `ENABLED_SOURCES` | Optional | Comma-separated list of source names to load; all sources loaded by default |

> **SMTP:** set `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASS` to your mail provider's outbound SMTP credentials. `SMTP_PORT` defaults to `587` (STARTTLS). `SMTP_FROM` defaults to `SMTP_USER` if omitted.

---

## Fly.io deployment

Fly.io offers a [free plan](https://fly.io/docs/about/pricing/) suitable for small projects — one shared-CPU machine and 3 GB of persistent volume storage are included at no cost, which is enough to run this app. A `Dockerfile` and `fly.toml` are included. The app runs on port 8080 with gunicorn + gevent.

Install the Fly CLI before starting: https://fly.io/docs/hands-on/install-flyctl/

### First deploy

```bash
# 1. Create the app — registers a name on Fly and writes fly.toml locally.
#    --no-deploy skips the automatic first build so you can set secrets first.
#    If prompted about an existing fly.toml, keep the existing one.
fly launch --no-deploy

# 2. Create a persistent volume for the SQLite database
fly volumes create smashedburger_data --size 1

# 3. Generate a SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# 4. Set secrets — encrypted and injected into every machine start.
#    SECURE_COOKIES must be 1 on Fly.io (HTTPS only). Do not set it to 0.
fly secrets set \
  ANTHROPIC_API_KEY=... \
  EXA_API_KEY=... \
  SECRET_KEY=<generated above> \
  SECURE_COOKIES=1

# Optional — features degrade gracefully without these:
# fly secrets set GROQ_API_KEY=... VIRUSTOTAL_API_KEY=...
# fly secrets set SOCKET_API_KEY=...
# fly secrets set CISCO_API_KEY=... CISCO_CLIENT_SECRET=...

# 5. Deploy
fly deploy

# 6. Verify
fly logs
curl https://<your-app>.fly.dev/healthz
```

Once deployed, go to `/auth/register` to create your account. Without SMTP configured, 2FA codes appear in `fly logs` — run `fly logs` in a separate terminal after submitting your login to retrieve the code.

Secrets persist across restarts, redeploys, and scale events until explicitly removed with `fly secrets unset`. To see what is set (names only, never values): `fly secrets list`.

### Redeploy after code changes

```bash
fly deploy
```

### Reset on Fly.io

**Soft reset — wipe all data but keep the volume, schema, and your user account:**

Do not delete the SQLite file on a volume-backed deployment — it can leave the volume in a bad state. Use the reset script instead, which clears all tables while preserving the schema:

```bash
fly ssh console
cd /app
python3 scripts/reset_db.py --confirm
exit
fly apps restart <your-app-name>
```

To also wipe user accounts (forces re-registration):

```bash
python3 scripts/reset_db.py --confirm --wipe-users
```

**Full teardown — destroy everything and start from scratch:**

```bash
# 1. Scale to 0 so the machine releases the volume
fly scale count 0

# 2. Get the volume ID
fly volumes list

# 3. Destroy the volume
fly volumes destroy <volume-id>

# 4. Destroy the app (removes the machine, the app name, and all secrets)
fly apps destroy <app-name>

# 5. Start over from step 1 of First deploy above.
#    Secrets do not survive app destruction — you must set them again.
```

In all cases, go to `/auth/register` after the app is running to create a new account. Never delete the database file while the app is running.

---

## Disclaimer

This is a proof-of-concept project built for learning purposes. It carries no warranty and has not been audited for security or reliability. External APIs are outside the author's control and can be slow or unavailable. Do not use smashedburger as a substitute for professional security tooling or human judgement.

---

## License

Licensed under the [Apache License 2.0](LICENSE). You are free to use, modify, and distribute this software. Derivative works must credit the original author and carry prominent notices of changes.
