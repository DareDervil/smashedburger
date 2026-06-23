"""Flask app: routes + source assembly. Per-source logic lives in sources/
; shared runtime state in context.py; the Haiku layer in extraction.py.
"""
import logging
import os, uuid, json, re, time, secrets as _secrets
from urllib.parse import urlparse

import dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context

import log_config
log_config.configure_logging()
logger = logging.getLogger(__name__)

import auth as _auth
import db
import context as ctx
import extraction
import learning
import monitoring
import news
import obs
import sources
import telemetry
import verification
from extraction import client
from chat import CVEChat
from tools import search_iocs, query_virustotal

_ = dotenv.load_dotenv()

app = Flask(__name__)

# ── Max request body size ─────────────────────────────────────────────────────
# Flask rejects any request body larger than this before it reaches route code.
# Stops memory exhaustion from oversized JSON payloads or accidental large uploads.
# 512 KB is generous for any legitimate chat message; adjust if file upload is added.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB

# Fix 3: SECRET_KEY must be set explicitly — a random fallback silently invalidates
# all sessions on every restart (bad in prod) and gives false security in dev.
# Generate once with: python -c "import secrets; print(secrets.token_hex(32))"
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY env var is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Fix 5: SECURE_COOKIES defaults to True — require explicit opt-out for dev/HTTP.
# Set SECURE_COOKIES=0 in .env when running locally without HTTPS.
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SECURE_COOKIES", "1").lower() not in ("0", "false")
# Fix 1: sessions expire after 12 hours of inactivity.
# Without this, a Flask session cookie lasts until the browser closes — but modern
# browsers restore sessions on reopen, so in practice sessions were permanent.
from datetime import timedelta
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.register_blueprint(_auth.auth_bp)

# ── Rate limiting (Flask-Limiter) ─────────────────────────────────────────────
# Rate limiting is a server-side middleware that counts requests per client IP
# over a rolling time window and rejects excess requests with HTTP 429.
# It stops brute-force login attacks, LLM cost abuse, and API hammering.
# Storage is in-memory — limits reset on restart, which is fine for a small deployment.
# For multi-process (gunicorn workers > 1) swap to redis:// storage.
#
# Threat model:
#   /auth/login          — brute-force password guessing       → 10/minute
#   /auth/register       — account farming / spam              → 5/hour
#   /auth/verify-2fa     — 2FA code brute-force                → 10/minute
#   /auth/forgot-password — email enumeration / spam           → 5/hour
#   /send                — LLM cost abuse                      → 20/minute
#   everything else      — general abuse safety net            → 300/minute
# Rate limiting is a server-side middleware that counts requests per client IP
# over a rolling time window and rejects excess requests with HTTP 429.
# It stops brute-force login attacks, LLM cost abuse, and API hammering.
# Storage is in-memory — limits reset on restart, which is fine for a small deployment.
# For multi-process (gunicorn workers > 1) swap to redis:// storage.
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,        # limit per client IP
    default_limits=["300 per minute"],  # global safety net for all routes
    # TEACHABLE-3: Redis as shared rate-limit storage across multiple processes.
    # In-memory storage means each gunicorn worker keeps its own counter — a user
    # can hit /send 20× per worker and bypass the per-minute cap entirely.
    # Redis is a single shared store all workers read/write, so limits hold correctly.
    # Falls back to in-memory if REDIS_URL is not set (safe for local dev without Redis).
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)

# Apply tight limits to auth endpoints after blueprint registration.
# Flask-Limiter can target blueprint view functions by their fully-qualified name.
limiter.limit("10 per minute") (app.view_functions["auth.login"])
limiter.limit("5 per hour")    (app.view_functions["auth.register"])
limiter.limit("10 per minute") (app.view_functions["auth.verify_2fa"])
limiter.limit("5 per hour")    (app.view_functions["auth.forgot_password"])

db.init_db()

# ── Error handlers for middleware rejections ───────────────────────────────────
@app.errorhandler(429)
def too_many_requests(e):
    """Rate limit exceeded — return JSON so the frontend can handle it cleanly."""
    logger.warning("rate-limit hit: %s %s from %s", request.method, request.path, request.remote_addr)
    return jsonify({"error": "Too many requests — slow down and try again shortly."}), 429

@app.errorhandler(413)
def request_too_large(e):
    """Request body exceeded MAX_CONTENT_LENGTH (512 KB)."""
    logger.warning("oversized request: %s %s from %s", request.method, request.path, request.remote_addr)
    return jsonify({"error": "Request too large."}), 413

# ── Source assembly (ISSUE-A1: remove a source = delete its file in sources/,
#    or exclude it via ENABLED_SOURCES="name1,name2" in .env) ─────────────────
_enabled = {s.strip() for s in os.getenv("ENABLED_SOURCES", "").split(",") if s.strip()} or None
SOURCE_MODULES = sources.load(_enabled)
tools, TOOL_REGISTRY, _TOOL_BULLETS = sources.assemble(SOURCE_MODULES)


# ── System prompt ─────────────────────────────────────────────────────────────

_PROMPT_INTRO = """\
You are a senior security consultant. Your role is to reason over vulnerability data and produce \
actionable guidance — not to relay raw data back to the user."""

_PROMPT_BODY = """\
## Package analysis

When the user asks about a software package (formats like "npm:lodash@4.17.20", \
"pip:requests==2.25.0", or conversational — "is left-pad safe?", "check ua-parser-js"), call \
**query_package_vulns** and **query_package_registry** together (pass the version to \
query_package_vulns if given). Structure the verdict in this order:

1. **Compromise check first** — is_malware records mean the package itself shipped malware \
(hijacked release, injected code). State the affected versions, whether the user's version is \
hit, and treat it as an incident: removal, credential rotation, and audit guidance — not just \
"upgrade".
2. **Vulnerabilities** — summarise by severity. Mention CVE aliases inline but do NOT \
auto-call parse_nvd_cve — offer a full briefing on request (same discipline as \
search_cves_by_product).
3. **Health signals** — deprecated, yanked, 404 (typosquat warning), stale last-publish, \
single maintainer. These are supply-chain risks even with zero CVEs.

If a version was given, state applicability precisely against the affected ranges and name the \
nearest fixed version. If the user indicates they actually use the package, call \
add_to_infrastructure (vendor = ecosystem name 'npm' or 'PyPI', product = package name, \
version if stated, category = software_library).

**Package intel** — After the structured lookups, optionally call **search_package_intel** \
to surface fresh compromise write-ups, incident narratives, or vendor advisories not yet in OSV \
(e.g. a typosquat campaign post, a Snyk/Socket blog entry, a researcher disclosure). Cite the \
genuinely relevant URLs inline as markdown links so they appear as source tiles — do not dump \
all results; abstain entirely if nothing in the snippets is clearly about this package \
(provenance discipline: a wrong cite is worse than no cite).

## Briefing protocol

When the user submits a CVE ID (even as a bare ID with no other text), treat it as a full \
briefing request. Call parse_nvd_cve and query_epss, then produce a structured assessment \
covering all of the following sections:

**Threat Summary** — What the vulnerability is, affected components, attack vector, and whether \
it is being actively exploited in the wild.

**Severity Assessment** — CVSS score and vector breakdown. EPSS score and what it means in \
practice. Combined verdict: how urgently does this need attention?

**Patch** — Specific versioned fixes where known from NVD or advisory data. Package names, \
build numbers, KB articles. If no specific version is available from NVD alone, say so and \
recommend fetching advisories.

**Workarounds** — Temporary measures the operator can apply immediately if patching is not \
possible. Be specific: exact commands, service names, configuration files, policy paths.

**Mitigations** — Configuration changes that reduce the attack surface without fully \
remediating. ACLs, registry keys, firewall rules, feature flags, Group Policy settings.

**Administrative Controls** — Operational measures: access reviews, privilege audits, \
change freeze recommendations, vendor notification, incident response preparation.

**Detection** — What to look for after the fact. Specific log sources, event IDs, process \
names, network signatures, file paths, registry keys, or SIEM queries that would indicate \
exploitation attempts or successful compromise.

## Reasoning standard

Reason over all available data before responding. When advisory data is present, synthesise \
it with CVSS and EPSS — do not list raw advisory fields. When advisory data is absent, reason \
from first principles: the vulnerability class, affected component, and attack vector are \
usually sufficient to infer credible workarounds and detection guidance.

Every response to a CVE query must include something concrete in each of the five action \
categories (patch, workaround, mitigation, admin, detect), even if it is brief. \
Never respond with "no information available" for an action category — if structured data \
is absent, reason from the vulnerability class and produce a best-effort recommendation, \
clearly marked as inferred.

Be conversational and direct. Do not repeat the user's question. Do not pad responses with \
caveats about limitations unless they are operationally relevant.

## Infrastructure discovery

While responding, passively track what the user reveals about their environment. When they use \
ownership language — "our", "we use", "we run", "we have", "we're patching", "our Cisco router", \
"our Apache server" — call **add_to_infrastructure** with what is known. Vendor is always required; \
product and version only when explicitly stated. Do not infer versions. Do not call this tool for \
hypothetical examples or generic descriptions of a vulnerability's affected products. After calling \
it, continue your reply naturally — a brief aside ("I've noted that in your infrastructure") is \
enough; do not dwell on it.

## Eliciting infrastructure and environment context

At the end of your reply, when knowing more about the user's setup would materially sharpen \
the advice, ask up to 2 questions — 3 maximum if there are genuinely distinct unknowns that \
each affect the guidance differently. Never ask more than 3. Do not ask about anything already \
stated in the conversation or present in the known infrastructure record.

**Infrastructure questions** — what they run:
- Which version of the affected product they are running.
- Whether the vulnerable component is embedded inside another product they use.
- Whether they have already applied mitigations or compensating controls.

**Environment questions** — how they operate:
- Network exposure: is the service internet-facing, in a DMZ, or internal-only?
- Deployment model: cloud, on-prem, containerised, hybrid?
- Detection and monitoring: do they have logging, a SIEM, EDR on the affected host?
- Patch cadence: how quickly can they realistically deploy a fix?
- Compliance context: are they subject to PCI, HIPAA, SOC2, or similar — which affects \
  risk tolerance and reporting obligations.
- Team context: who owns this system and how quickly can they act?

Bad triggers (do not ask):
- You already have the answer in the conversation or infrastructure record.
- The CVE is purely informational and the user has not suggested any operational concern.
- They are clearly researching, not managing a live environment.

Phrase questions as natural closing lines, not a checklist. Group related questions into one \
sentence where possible. Examples: \
"Do you know which version you're running, and is this service internet-facing?" or \
"Is this host monitored — do you have EDR or logging on it?" or \
"Are you under any compliance framework that would affect your patching timeline?" \
Keep each question short and specific.

## Extracting topology and network facts

Call **add_topology_fact** whenever the user states — explicitly or implicitly — how \
components relate to each other or what controls protect them. Do not wait for a direct \
question; extract passively, the same way you call add_to_infrastructure.

**Relationship triggers** — call with fact_type="relationship":
- "Log4j runs inside our Tomcat app" → source=product:apache:log4j, target=product:apache:tomcat, type=runs_on
- "Tomcat sits on Ubuntu" → source=product:apache:tomcat, target=os:canonical:ubuntu, type=runs_on
- "our API is exposed via the internet" → source=product:<vendor>:<product>, target=zone:internet, type=exposed_via
- "our Spring Boot app depends on Log4j" → type=depends_on
- Implicit: "we run Log4j in Spring Boot" → infer runs_on relationship

**Network control triggers** — call with fact_type="network_control":
- "only ports 80 and 443 are open" → constraint_type=port_restriction, detail="80,443"
- "we're behind a WAF" → constraint_type=waf
- "that segment is air-gapped" → constraint_type=air_gap
- "it sits in a DMZ" → constraint_type=dmz
- "there's a firewall in front" → constraint_type=firewall

**Node ID scheme** — always use: product:<vendor>:<product>, os:<vendor>:<product>, zone:<name>. \
Lowercase, no spaces (use underscores). zone values: internet, dmz, internal, vpn. \
Derive vendor and product from what you already know about their infra.

Call add_to_infrastructure first if the component isn't already recorded, then \
add_topology_fact. These two tools together build the attack graph — topology facts without \
the base infra record are orphaned and useless.

## When to consult the advisor

When the user's question requires security judgement over their specific situation — not facts \
retrievable from source data — call **ask_advisor** before composing your reply.

Call it when the user asks about:

- **Risk**: "How risky is this?", "How bad is this really?", "Should we be worried?", \
  "What's our exposure here?", "Is this serious for us?"

- **Priority**: "Is this urgent?", "What should we patch first?", "Where do we stand?", \
  "How does this rank against our other open issues?"

- **Exposure and reachability**: "Are we exposed?", "Does this affect our setup?", \
  "Could this hit us?", "Is this code path reachable in our environment?", \
  "We don't use that feature — are we still affected?", "We're behind a WAF — does that help?"

- **Advice**: "What would you do?", "What do you recommend?", "What's your take?", \
  "What should our next step be?", "How should we approach this?"

- **Their environment or infrastructure specifically**: any question containing "for us", \
  "in our case", "given our setup", "in our environment", "for our stack", "in our situation", \
  "given what we run", "for our infrastructure"

Also call it when the user makes a statement that implicitly asks for judgement — even without \
an explicit question. "We're running this in production" following a CVE briefing, or \
"We don't have EDR on those hosts", or "We haven't patched this yet" are all implicit \
"how bad is this for us?" — treat them as advisor triggers.

Do not call it for:
- Pure fact questions: CVSS score, patch version, exploit status, affected version ranges
- General explanations of a vulnerability class or attack technique
- Questions fully answerable from the tool results already fetched this turn
- Conversational acknowledgements or follow-up clarifications with no judgement dimension"""

SYSTEM_PROMPT = [
    {
        "type": "text",
        "text": _PROMPT_INTRO + "\n\n## Tools\n\n" + "\n".join(_TOOL_BULLETS) + "\n\n" + _PROMPT_BODY,
        "cache_control": {"type": "ephemeral"},
    }
]

chats: dict[str, CVEChat] = {}
conv_links: dict[str, dict] = {}    # conv_id → {url: link_obj}
conv_actions: dict[str, dict] = {}  # conv_id → {action_id: action_obj}


# ── Reply-cited links → Pane A (cross-source, so lives here not in sources/) ──

_MD_LINK_RE  = re.compile(r"\[([^\]]+)\]\((https?://[^\s)]+)\)")
_BARE_URL_RE = re.compile(r"https?://[^\s)\]>,\"']+")

# Domain → existing SOURCE_META badge for reply-cited links
_DOMAIN_SOURCE = {
    "github.com":                       "github",
    "nvd.nist.gov":                     "nvd",
    "osv.dev":                          "osv",
    "access.redhat.com":                "redhat",
    "ubuntu.com":                       "ubuntu",
    "msrc.microsoft.com":               "msrc",
    "www.cisa.gov":                     "cisa",
    "www.npmjs.com":                    "npm",
    "pypi.org":                         "pypi",
    "fortiguard.fortinet.com":          "fortinet",
    "support.citrix.com":               "citrix",
    "security.paloaltonetworks.com":    "palo_alto",
    "support.broadcom.com":             "broadcom",
    "sec.cloudapps.cisco.com":          "cisco",
}

_NEWS_DOMAINS = ("bleepingcomputer.com", "thehackernews.com", "theregister.com",
                 "krebsonsecurity.com", "arstechnica.com", "darkreading.com",
                 "securityweek.com", "aikido.dev", "socket.dev", "snyk.io",
                 "doublepulsar.com", "medium.com")

_ADVISORY_URL_HINTS = ("/advisories/", "/vulnerability/", "/psirt", "/errata/",
                       "/security/cve", "securityadvisories", "/usn-", "/article/ctx")


def _classify_reply_link(url: str) -> tuple[str, str]:
    """(source, type) for a URL Sonnet cited. Source badge = recognised domain
    (falls back to the bare domain, rendered grey); type = advisory/news/reference."""
    netloc = urlparse(url).netloc.lower()
    bare = netloc.removeprefix("www.")
    source = _DOMAIN_SOURCE.get(netloc) or _DOMAIN_SOURCE.get("www." + bare) or bare
    low = url.lower()
    if any(h in low for h in _ADVISORY_URL_HINTS):
        ltype = "advisory"
    elif any(bare.endswith(d) for d in _NEWS_DOMAINS) or "/blog" in low:
        ltype = "news"
    else:
        ltype = "reference"
    return source, ltype


def _extract_reply_links(reply: str, known_urls: set) -> list:
    """Extract URLs Sonnet cited in its reply (markdown links + bare URLs) so
    every link discussed in chat lands in Pane A — both pipelines. Tool-extracted
    tiles are richer, so URLs already known are skipped."""
    links = []
    seen: set = set(known_urls)

    def _clean(url: str) -> str:
        return url.rstrip(".,;:!?)")

    for m in _MD_LINK_RE.finditer(reply):
        url = _clean(m.group(2))
        if url in seen:
            continue
        seen.add(url)
        source, ltype = _classify_reply_link(url)
        links.append({
            "url": url, "source": source, "type": ltype,
            "title": m.group(1).strip()[:80],
            "description": urlparse(url).netloc,
        })
    # Bare URLs outside markdown links
    stripped = _MD_LINK_RE.sub(" ", reply)
    for m in _BARE_URL_RE.finditer(stripped):
        url = _clean(m.group(0))
        if url in seen or len(url) < 12:
            continue
        seen.add(url)
        source, ltype = _classify_reply_link(url)
        links.append({
            "url": url, "source": source, "type": ltype,
            "title": urlparse(url).netloc,
            "description": url[:100],
        })
    return links


# ── Auto-infra extraction ──────────────────────────────────────────

_ECOSYSTEM_TO_CATEGORY = {
    "java":        "software_library",
    "npm":         "software_library",
    "python":      "software_library",
    "ruby":        "software_library",
    "go":          "software_library",
    "dotnet":      "software_library",
    "windows":     "operating_system",
    "linux":       "operating_system",
    "network":     "network",
    "browser":     "application",
    "application": "application",
}



def _score_to_severity(score) -> str:
    if score is None: return None
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"



def _serialize_content(content):
    """Convert message content to a JSON-serializable form."""
    if isinstance(content, str):
        return content
    blocks = []
    for block in content:
        if hasattr(block, 'model_dump'):
            blocks.append(block.model_dump())
        else:
            blocks.append(block)
    return blocks


# ── CSRF validation ───────────────────────────────────────────────────────────
# State-changing requests (POST/PATCH/DELETE) must carry an X-CSRF-Token header
# matching the token stored in the server-side session.
# Auth routes and /send (SSE) are excluded — /send uses its own session check,
# auth routes run before a session exists.
_CSRF_EXEMPT = {"/auth/login", "/auth/register", "/auth/verify-2fa",
                "/auth/forgot-password", "/auth/logout"}

@app.before_request
def _csrf_protect():
    if request.method not in ("POST", "PATCH", "DELETE", "PUT"):
        return
    if request.path in _CSRF_EXEMPT or request.path.startswith("/auth/reset-password"):
        return
    token = session.get("csrf_token")
    header = request.headers.get("X-CSRF-Token", "")
    if not token or not _secrets.compare_digest(token, header):
        logger.warning("CSRF validation failed: %s %s from %s", request.method, request.path, request.remote_addr)
        return jsonify({"error": "CSRF validation failed."}), 403


@app.before_request
def _start_monitor_scheduler():
    # Idempotent; lives here (not module level) so the Werkzeug reloader
    # parent — which imports main.py but never serves — starts no thread.
    monitoring.ensure_scheduler()
    # Stamp request start time for the after_request duration log.
    request._t0 = time.perf_counter()


@app.after_request
def _log_request(response):
    # Universal access log: method + path + status + duration.
    # Skips /healthz (noisy) and static assets.
    path = request.path
    if path == "/healthz" or path.startswith("/static/"):
        return response
    duration_ms = (time.perf_counter() - getattr(request, "_t0", time.perf_counter())) * 1000
    logger.info("HTTP %s %s → %d  (%.0fms)", request.method, path, response.status_code, duration_ms)
    return response


login_required = _auth.login_required


@app.route("/healthz")
def healthz():
    return {"ok": True}, 200


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/stats", methods=["GET"])
@login_required
def get_stats():
    return jsonify(db.get_stats())


@app.route("/conversations", methods=["GET"])
@login_required
def get_conversations():
    return jsonify(db.list_conversations(user_id=session.get("user_id")))


@app.route("/conversations", methods=["POST"])
@login_required
def new_conversation():
    conv_id = str(uuid.uuid4())
    db.create_conversation(conv_id, "New conversation", user_id=session.get("user_id"))
    return jsonify({"id": conv_id})


@app.route("/conversations/<conv_id>", methods=["GET"])
@login_required
def get_conversation(conv_id):
    limit  = request.args.get("limit",  type=int)
    offset = request.args.get("offset", 0, type=int)
    messages, total = db.load_messages(conv_id, limit=limit, offset=offset)
    display = []
    for msg in messages:
        content = msg["content"]
        if msg["role"] == "user" and isinstance(content, str):
            display.append({"role": "user", "text": content})
        elif msg["role"] == "assistant":
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        display.append({"role": "assistant", "text": block["text"]})
            elif isinstance(content, str):
                display.append({"role": "assistant", "text": content})
    has_more = (offset + (limit or total)) < total if limit else False
    return jsonify({"messages": display, "total": total, "has_more": has_more})


@app.route("/conversations/<conv_id>/full", methods=["GET"])
@login_required
def get_conversation_full(conv_id):
    """Consolidated conversation load — messages + links + candidates in one SQLite pass.

    Replaces the three parallel fetches (/conversations/<id>, /links/<id>, /candidates/<id>)
    that openConversation() previously fired on every conversation switch. One round-trip
    also makes AbortController trivial: a single signal cancels everything.
    See TEACHABLE-1 in docs/TEACHABLE.md.
    """
    limit  = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    messages, total = db.load_messages(conv_id, limit=limit, offset=offset)
    display = []
    for msg in messages:
        content = msg["content"]
        if msg["role"] == "user" and isinstance(content, str):
            display.append({"role": "user", "text": content})
        elif msg["role"] == "assistant":
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        display.append({"role": "assistant", "text": block["text"]})
            elif isinstance(content, str):
                display.append({"role": "assistant", "text": content})
    has_more = (offset + limit) < total
    return jsonify({
        "messages":   display,
        "total":      total,
        "has_more":   has_more,
        "links":      db.get_links(conv_id),
        "candidates": db.get_candidates(conv_id),
    })


@app.route("/conversations/<conv_id>", methods=["DELETE"])
@login_required
def delete_conversation(conv_id):
    if conv_id in chats:
        del chats[conv_id]
    if conv_id in conv_links:
        del conv_links[conv_id]
    if conv_id in conv_actions:
        del conv_actions[conv_id]
    db.delete_conversation(conv_id)
    return jsonify({"ok": True})


@app.route("/send", methods=["POST"])
@login_required
@limiter.limit("20 per minute")   # each LLM call costs money — cap abuse
def send():
    """SSE streaming endpoint.
    Phase 1 — token stream: yields `data: {"token": "..."}` events as Sonnet writes.
    Phase 2 — done event: after all post-processing (GV, Haiku, infra, DB), yields
               `data: {"done": true, "reply": "...", "gv": {...}, ...}`.
    If GV revised the reply the done event carries the corrected text so the browser
    can swap the streamed draft for the final version.
    Errors yield `data: {"error": "..."}` so the browser always gets a parseable event.

    SSE (Server-Sent Events): unidirectional HTTP/1.1 stream of `data:` lines.
    Each event is `data: <json>\n\n`. The browser's EventSource or a manual
    ReadableStream reader picks these up without polling. Works through gunicorn
    gevent workers because gevent yields on each `yield` in the generator.
    """
    data = request.get_json()
    message  = data["message"]
    conv_id  = data["conversation_id"]
    user_id  = session.get("user_id")

    def _sse(obj: dict) -> str:
        return f"data: {json.dumps(obj)}\n\n"

    @stream_with_context
    def generate():
        try:
            db.ensure_conversation(conv_id, user_id)

            if conv_id not in chats:
                stored, _ = db.load_messages(conv_id)
                chats[conv_id] = CVEChat(
                    client, tools, TOOL_REGISTRY,
                    system=_build_system_prompt(),
                    messages=stored
                )
                if conv_id not in conv_links:
                    conv_links[conv_id] = {l["url"]: l for l in db.get_links(conv_id)}
            else:
                chats[conv_id].system = _build_system_prompt()

            ctx.reset_links()
            ctx.reset_actions()
            ctx.cve_store.result       = None
            ctx.euvd_store.result      = None
            ctx.cve_retry.cve_id       = None
            ctx.pkg_store.results      = []
            ctx.current_cve_id.value   = None
            ctx.current_conv.conv_id   = conv_id
            ctx.advisor_store.called   = False
            ctx.advisor_store.count    = 0
            # Live reference — tool results appended during the loop are visible
            # to ask_advisor before it fires, since Sonnet calls tools sequentially.
            ctx.conv_messages.messages = chats[conv_id].messages
            ctx.init_prefetch()
            nvd_queued_for = None
            prev_count = len(chats[conv_id].messages)
            _t_send    = time.perf_counter()
            hist_len   = len(chats[conv_id].messages)
            logger.info("send conv=%s history=%d msg=%r → Sonnet (streaming)",
                        conv_id[:8], hist_len, message[:80])

            # ── Phase 1: stream tokens directly from CVEChat generator ──
            # stream_reply() is a generator that yields ("token", chunk) for each
            # text delta and ("done", full_reply) at the end. We iterate it here
            # and immediately yield each token as an SSE event — no greenlet, no
            # polling, no buffering. Tokens flow: Anthropic SDK → stream_reply →
            # this generator → HTTP chunked response → browser.
            reply = None
            for kind, value in chats[conv_id].stream_reply(message):
                if kind == "token":
                    yield _sse({"token": value})
                elif kind == "done":
                    reply = value
                    break
            if reply is None:
                raise RuntimeError("stream_reply ended without a done event")
            logger.info("send Sonnet ✓ %.1fs reply=%dchars",
                        time.perf_counter() - _t_send, len(reply))
            new_messages = chats[conv_id].messages[prev_count:]

            # ── Phase 2: post-processing (GV, Haiku, infra, DB) ──
            # Signal browser that streaming is done and verification is running.
            yield _sse({"verifying": True})

            _t_gv = time.perf_counter()
            logger.debug("send GV → grounded-verification pass")
            gv = verification.run_gv(
                client, "claude-sonnet-4-6", reply, new_messages,
                nvd_result=getattr(ctx.nvd_store, "result", None),
                messages=chats[conv_id].messages,
                on_demand=bool(data.get("verify")),
            )
            logger.info("send GV ✓ %.1fs ran=%s revised=%s reason=%s",
                        time.perf_counter() - _t_gv, gv["ran"], gv["revised"],
                        gv.get("reason") or "-")
            reply = gv["reply"]
            if gv["revised"]:
                new_messages = chats[conv_id].messages[prev_count:]

            # ── Fan-out: spawn Haiku calls concurrently so they run while the
            # synchronous CVE/product DB writes below proceed. gevent yields on
            # every I/O boundary (Anthropic HTTP), so both calls overlap without
            # native threads. We join before consuming their results.
            try:
                import gevent as _gevent
                _t_haiku   = time.perf_counter()
                _g_actions = _gevent.spawn(
                    extraction.llm_extract_actions, reply, "claude", 3072
                ) if len(reply) > 300 else None
                _g_title = _gevent.spawn(
                    extraction.generate_title, message
                ) if prev_count == 0 else None
                _haiku_labels = ("actions " if _g_actions else "") + ("title" if _g_title else "")
                if _g_actions or _g_title:
                    logger.debug("send Haiku → %s (spawned concurrently)", _haiku_labels.strip())
            except ImportError:
                # Dev server without gevent — fall back to sequential, run actions now.
                _gevent = None
                _g_actions = None
                _g_title   = None
                _t_haiku   = time.perf_counter()
                if len(reply) > 300:
                    ctx.add_actions(extraction.llm_extract_actions(reply, "claude", max_tokens=3072))
                    logger.info("send Haiku ✓ %.1fs actions_pending=%d (sequential)",
                                time.perf_counter() - _t_haiku,
                                len(getattr(ctx.action_store, "pending", {})))

            known_urls = set(conv_links.get(conv_id, {})) | set(ctx.flush_links())
            ctx.add_links(_extract_reply_links(reply, known_urls))

            nvd_result = getattr(ctx.nvd_store, "result", None)
            _retry_cve_peek = getattr(ctx.cve_retry, "cve_id", None)
            logger.debug("send post-tool: nvd=%s retry_cve=%s",
                         "✓" if nvd_result else "✗(queued)" if _retry_cve_peek else "✗(not called)",
                         _retry_cve_peek or "-")
            if nvd_result:
                products = nvd_result.get("products") or []
                if not products:
                    euvd_result = getattr(ctx.euvd_store, "result", None)
                    products = (euvd_result or {}).get("products") or []
                for p in products:
                    vendor_name  = (p.get("vendor") or "").strip()
                    product_name = (p.get("product") or "").strip()
                    vendor = vendor_name or product_name
                    if not vendor:
                        continue
                    vendor_id = db.upsert_vendor(vendor)
                    if product_name and vendor_name:
                        db.upsert_product(vendor_id, product_name, p.get("category", "application"), conv_id)
                if products:
                    db.set_relevant_to_infra(conv_id, True)
                    _nvd_cve = (nvd_result.get("id") or "").strip()
                    logger.info("send CVE.org ✓ → seeded %d product(s), checking KEV for %s",
                                len(products), _nvd_cve)
                    monitoring.ensure_kev_status(_nvd_cve)
                    logger.debug("send KEV ✓")
                ctx.cve_store.result  = None
                ctx.euvd_store.result = None
            else:
                euvd_result = getattr(ctx.euvd_store, "result", None)
                retry_cve   = getattr(ctx.cve_retry, "cve_id", None)
                logger.info("send CVE.org ✗ → fallback: retry_cve=%s euvd_found=%s",
                            retry_cve, bool(euvd_result and euvd_result.get("found")))
                if retry_cve:
                    products_seeded = 0
                    if euvd_result and euvd_result.get("found"):
                        score    = euvd_result.get("cvss_score")
                        severity = _score_to_severity(score)
                        db.store_cve_metadata(conv_id, retry_cve, score, severity)
                        db.set_relevant_to_infra(conv_id, True)
                        logger.info("send EUVD fallback: score=%s severity=%s → stored, KEV check for %s",
                                    score, severity, retry_cve)
                        monitoring.ensure_kev_status(retry_cve)
                        logger.debug("send KEV ✓")
                    euvd_products = (euvd_result or {}).get("products") or []
                    for p in euvd_products:
                        vendor_name  = (p.get("vendor") or "").strip()
                        product_name = (p.get("product") or "").strip()
                        vendor = vendor_name or product_name
                        if not vendor:
                            continue
                        vendor_id = db.upsert_vendor(vendor)
                        if product_name and vendor_name:
                            db.upsert_product(vendor_id, product_name, "application", conv_id)
                            products_seeded += 1
                    if products_seeded:
                        db.set_relevant_to_infra(conv_id, True)
                    # Store the count: retry scheduler skips product seeding only when
                    # products_seeded equals the total expected from CVE.org. Using a
                    # count (not a bool) lets the scheduler detect partial seeding and
                    # re-seed if CVE.org returns more products than EUVD did.
                    db.queue_cve_retry(retry_cve, conv_id, products_seeded=products_seeded)
                    nvd_queued_for = retry_cve
                    ctx.cve_retry.cve_id = None
                ctx.euvd_store.result = None

            _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            pkg_results = getattr(ctx.pkg_store, "results", None)
            if pkg_results:
                for pkg in pkg_results:
                    pkg_name  = (pkg.get("package") or "").strip()
                    ecosystem = (pkg.get("ecosystem") or "").strip().lower()
                    version   = (pkg.get("version") or "").strip()
                    if not pkg_name:
                        continue
                    category   = _ECOSYSTEM_TO_CATEGORY.get(ecosystem, "software_library")
                    vendor_id  = db.upsert_vendor(pkg_name)
                    product_id = db.upsert_product(vendor_id, pkg_name, category, conv_id)
                    if version:
                        db.upsert_version(product_id, version, conv_id)
                    highest_sev = None
                    for v in (pkg.get("vulns") or []):
                        sev = (v.get("severity") or "").upper()
                        if sev in _SEV_RANK and (highest_sev is None or _SEV_RANK[sev] < _SEV_RANK[highest_sev]):
                            highest_sev = sev
                        # CVEs discovered via package queries bypass the normal CVE.org
                        # pipeline (sources/nvd.py only runs when the user mentions a CVE
                        # directly). Queue them for background retry so the scheduler will
                        # call fetch_cveorg_primary, seed products, and produce the
                        # CVE→product `affects` edge in the attack graph.
                        vuln_id = (v.get("id") or "").strip().upper()
                        if vuln_id.startswith("CVE-"):
                            db.queue_cve_retry(vuln_id, conv_id, products_seeded=False)
                            logger.debug("pkg-scan queued CVE retry %s for %s", vuln_id, pkg_name)
                    db.store_pkg_record(
                        ecosystem=ecosystem, package=pkg_name,
                        vuln_count=pkg.get("total", 0), malware_count=pkg.get("malware_count", 0),
                        highest_sev=highest_sev, conv_id=conv_id,
                    )
                db.set_relevant_to_infra(conv_id, True)
                ctx.pkg_store.results = []

            new_links = ctx.flush_links()
            if new_links:
                if conv_id not in conv_links:
                    conv_links[conv_id] = {}
                conv_links[conv_id].update(new_links)
                db.upsert_links(conv_id, list(new_links.values()))

            # ── Join concurrent Haiku greenlets (if spawned above) ───────────
            # Use `is not None` — dead greenlets are falsy (Greenlet.__bool__ = not self.dead)
            # so truthiness checks silently skip the result consumption after joinall.
            if _gevent and (_g_actions is not None or _g_title is not None):
                _gevent.joinall([g for g in (_g_actions, _g_title) if g is not None], timeout=60)
                logger.info("send Haiku ✓ %.1fs %s",
                            time.perf_counter() - _t_haiku, _haiku_labels.strip())
            if _g_actions is not None:
                if _g_actions.exception:
                    logger.warning("send Haiku actions greenlet raised: %s", _g_actions.exception)
                else:
                    ctx.add_actions(_g_actions.value or [])
                logger.info("send Haiku actions_pending=%d",
                            len(getattr(ctx.action_store, "pending", {})))

            new_actions = ctx.flush_actions()
            if new_actions:
                if conv_id not in conv_actions:
                    conv_actions[conv_id] = {}
                conv_actions[conv_id].update(new_actions)
                db.upsert_candidates(conv_id, list(new_actions.values()))

            for msg in new_messages:
                db.append_message(conv_id, msg["role"], _serialize_content(msg["content"]))

            if prev_count == 0:
                if _g_title is not None:
                    _title = (_g_title.value if not _g_title.exception else None) or message[:60]
                else:
                    _title = extraction.generate_title(message)
                db.update_title(conv_id, _title)

            db.touch_conversation(conv_id)
            logger.info("send ✓ total=%.1fs links=%d actions=%d cve_pending=%s advisor=%s",
                        time.perf_counter() - _t_send,
                        len(conv_links.get(conv_id, {})),
                        len(conv_actions.get(conv_id, {})),
                        nvd_queued_for is not None,
                        getattr(ctx.advisor_store, "count", 0) or "-")

            # Final event — carries the (possibly GV-revised) reply plus metadata.
            # Browser replaces the streamed draft with this rendered version.
            yield _sse({
                "done":        True,
                "reply":       reply,
                "links":       list(conv_links.get(conv_id, {}).values()),
                "actions":     list(conv_actions.get(conv_id, {}).values()),
                "gv":          {"ran": gv["ran"], "revised": gv["revised"]},
                "advisor":     {"called": getattr(ctx.advisor_store, "called", False),
                                "count":  getattr(ctx.advisor_store, "count",  0)},
                "nvd_pending": nvd_queued_for is not None,
            })

        except Exception as exc:
            import traceback
            logger.exception("send ERROR %s: %s", type(exc).__name__, exc)
            try:
                _err_text = f"⚠️ Something went wrong: {exc}\n\nThis error has been logged. Please try again."
                db.ensure_conversation(conv_id, user_id)
                db.append_message(conv_id, "assistant", _err_text)
            except Exception:
                pass
            yield _sse({"error": f"Internal error: {exc}"})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.route("/nvd-retry/<conv_id>", methods=["GET"])
@login_required
def nvd_retry_status(conv_id):
    """Poll endpoint for the NVD retry ribbon. Returns {pending: bool, attempts?: int}."""
    row = db.get_cve_retry_status(conv_id)
    if row:
        return jsonify({"pending": True, "attempts": row["attempts"]})
    return jsonify({"pending": False})


@app.route("/cve-dashboard", methods=["GET"])
@login_required
def cve_dashboard():
    return jsonify(db.get_cve_dashboard())


@app.route("/graph-data", methods=["GET"])
@login_required
def graph_data():
    """Serve the attack graph payload. Merges the new weighted attack graph
    (CVE/product/zone nodes + threat edges) with the legacy structural nodes
    (CWE, package, ecosystem) so the renderer has the full picture."""
    # Attack graph: weighted CVE/product/zone nodes + threat propagation edges
    dashboard   = db.get_cve_dashboard()
    attack      = dashboard.get("attack_graph", {"nodes": [], "edges": []})

    # Legacy graph: CWE posture nodes + package/ecosystem nodes + structural edges
    legacy       = db.get_graph_data()
    legacy_types = {"cwe", "package", "ecosystem"}
    extra_nodes  = [n for n in legacy["nodes"] if n.get("type") in legacy_types]

    # Legacy edges use bare CVE IDs (e.g. "CVE-2021-44228") but attack graph nodes
    # use prefixed IDs ("cve:cve-2021-44228"). Remap source/target on legacy edges
    # so they connect correctly after the client-side ID filter.
    attack_cve_ids = {n["id"] for n in attack["nodes"] if n.get("type") == "cve"}
    # Build lookup: bare uppercase CVE ID → attack graph node ID
    cve_id_map = {n["id"].split(":", 1)[1].upper(): n["id"]
                  for n in attack["nodes"] if n.get("type") == "cve"}

    def _remap(eid):
        return cve_id_map.get(eid.upper(), eid)

    extra_edges = []
    for e in legacy["edges"]:
        if e.get("rel") not in ("root_cause", "has_cve", "contains", "same_lib"):
            continue
        extra_edges.append({**e, "source": _remap(e["source"]), "target": _remap(e["target"])})

    return jsonify({
        "nodes": attack["nodes"] + extra_nodes,
        "edges": attack["edges"] + extra_edges,
    })


@app.route("/graph-context", methods=["POST"])
@login_required
def graph_context():
    """Lightweight Sonnet call for topology fact extraction from the graph screen.
    No conversation history — only the two extraction tools and the infra snapshot.
    Fast and cheap: no streaming, no agentic loop beyond tool use."""
    body = request.get_json(silent=True) or {}
    statement = (body.get("statement") or "").strip()
    if not statement:
        return jsonify({"error": "empty statement"}), 400

    import anthropic as _anthropic

    client  = _anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))
    infra   = db.get_infrastructure()
    infra_text = "\n".join(
        f"  {v['name']}: " + ", ".join(p["name"] for p in v["products"])
        for v in infra
    ) or "No infrastructure recorded yet."

    # Only the two extraction tools — no CVE sources, no advisor
    tool_names  = {"add_to_infrastructure", "add_topology_fact"}
    _mods       = sources.load(enabled=tool_names)
    tool_defs   = [m.TOOL_DEF for m in _mods]
    tool_map    = {m.NAME: m.fetch for m in _mods}

    system = (
        "You are extracting infrastructure topology facts from a user statement. "
        "Call add_to_infrastructure for any new component mentioned. "
        "Call add_topology_fact for any relationship or network control mentioned. "
        "Do not explain. Do not ask questions. Just call the tools and confirm briefly."
    )
    messages = [{"role": "user", "content":
        f"Known infrastructure:\n{infra_text}\n\nUser statement: {statement}"}]

    facts_recorded = []
    for _ in range(4):   # max 4 tool calls per statement
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=system,
            tools=tool_defs,
            messages=messages,
        )
        if resp.stop_reason != "tool_use":
            break
        tool_results = []
        for blk in resp.content:
            if blk.type != "tool_use":
                continue
            fn     = tool_map.get(blk.name)
            result = fn(**blk.input) if fn else {"error": "unknown tool"}
            facts_recorded.append({"tool": blk.name, "input": blk.input, "result": result})
            tool_results.append({"type": "tool_result", "tool_use_id": blk.id,
                                  "content": str(result)})
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user",      "content": tool_results})

    logger.info("graph-context: %d fact(s) from %r", len(facts_recorded), statement[:60])
    return jsonify({"ok": True, "facts": len(facts_recorded)})


@app.route("/relationship/<int:rel_id>/confirm", methods=["POST"])
@login_required
def confirm_relationship(rel_id):
    """Mark an inferred relationship as user-confirmed.
    Confirmed edges carry confidence_factor=1.0 in the attack graph weight formula
    vs 0.7 for inferred — bumping the propagated threat score by ~43%."""
    db.confirm_relationship(rel_id)
    return jsonify({"ok": True})


@app.route("/relationship/<int:rel_id>", methods=["DELETE"])
@login_required
def delete_relationship(rel_id):
    """Remove a relationship edge from the attack graph."""
    db.delete_relationship(rel_id)
    return jsonify({"ok": True})


@app.route("/relationship", methods=["POST"])
@login_required
def add_relationship():
    """Manually add a relationship edge between two infrastructure nodes."""
    body = request.get_json(silent=True) or {}
    src  = (body.get("source") or "").strip()
    tgt  = (body.get("target") or "").strip()
    rel  = (body.get("relationship_type") or "").strip()
    if not src or not tgt or not rel:
        return jsonify({"error": "source, target, and relationship_type required"}), 400
    rel_id = db.store_relationship(src, tgt, rel, user_confirmed=True)
    return jsonify({"ok": True, "id": rel_id})


@app.route("/cwe-controls", methods=["GET"])
@login_required
def list_cwe_controls():
    cwe_id = request.args.get("cwe_id")
    return jsonify(db.get_cwe_controls(cwe_id))


@app.route("/cwe-controls", methods=["POST"])
@login_required
def add_cwe_control():
    """Record a remediation control for a CWE weakness class.
    One control covers every CVE in the graph that shares this CWE —
    the primary posture leverage point."""
    body = request.get_json(silent=True) or {}
    cwe_id = (body.get("cwe_id") or "").strip().upper()
    text   = (body.get("text") or "").strip()
    if not cwe_id or not text:
        return jsonify({"error": "cwe_id and text required"}), 400
    cid = db.add_cwe_control(cwe_id, text)
    return jsonify({"id": cid, "cwe_id": cwe_id})


@app.route("/cwe-controls/<control_id>", methods=["DELETE"])
@login_required
def delete_cwe_control(control_id):
    db.delete_cwe_control(control_id)
    return jsonify({"ok": True})


@app.route("/iocs", methods=["GET"])
@login_required
def get_iocs_cached():
    """Return persisted IOCs for a CVE — fast, no external calls."""
    cve_id = (request.args.get("cve_id") or "").strip().upper()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    return jsonify(db.get_iocs(cve_id))


@app.route("/iocs", methods=["POST"])
@login_required
def search_iocs_route():
    """Fresh structured IOC pull, persist only new IOCs, return full
    set + new_count. Optional {"rebaseline": true} wipes the CVE's persisted
    IOCs/sources first — recovery path for data polluted before the
    grounding-based source model."""
    data   = request.get_json()
    cve_id = (data.get("cve_id") or "").strip().upper()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400

    raw = search_iocs(cve_id)
    if not raw.get("found"):
        # Return whatever is cached even if fresh search found nothing
        # (and don't wipe on a failed rebaseline — nothing to replace it with)
        cached = db.get_iocs(cve_id)
        return jsonify({**cached,
                        "new_count": 0,
                        "error": raw.get("error") or "No results found"})

    if data.get("rebaseline"):
        db.delete_cve_iocs(cve_id)

    sources_list = raw["sources"]

    # Deduplicate by (type, normalised value)
    seen: set = set()
    deduped: list = []
    for ioc in raw["iocs"]:
        key = (ioc.get("type"), ioc.get("value", "").lower())
        if key not in seen and ioc.get("value"):
            seen.add(key)
            deduped.append(ioc)

    # Compute delta against what's already persisted
    _IOC_NS = uuid.UUID("c9d8e7f6-a5b4-4c3d-2e1f-0a9b8c7d6e5f")
    def _ioc_id(cve, ioc):
        return str(uuid.uuid5(_IOC_NS, f"{cve}:{ioc['type']}:{ioc['value'].lower()}"))

    existing     = db.get_iocs(cve_id)
    existing_ids = {_ioc_id(cve_id, ioc) for ioc in existing["iocs"]}
    new_count    = sum(1 for ioc in deduped if _ioc_id(cve_id, ioc) not in existing_ids)

    # Persist only new IOCs and sources
    db.upsert_iocs(cve_id, deduped)
    db.upsert_ioc_sources(cve_id, sources_list)

    # Return full persisted set + new_count
    updated = db.get_iocs(cve_id)
    return jsonify({**updated, "new_count": new_count})


# ── Monitor routes (Phase G) — entity_type fixed to 'cve' until package
#    monitors land on Library cards ─────────────────────────────────────────────

@app.route("/monitors/<entity_id>", methods=["GET"])
@login_required
def get_monitor(entity_id):
    """Monitor state for the War Room panel. Default when none exists: disabled."""
    m = db.get_monitor("cve", entity_id.upper())
    return jsonify(m or {"enabled": 0, "cadence_hours": 24, "last_polled_at": None})


@app.route("/monitors/<entity_id>", methods=["PUT"])
@login_required
def put_monitor(entity_id):
    """Create/update a monitor: {enabled: bool, cadence_hours: int}."""
    data = request.get_json() or {}
    cadence = int(data.get("cadence_hours", 24))
    if cadence not in (6, 12, 24, 168):
        return jsonify({"error": "cadence_hours must be 6, 12, 24 or 168"}), 400
    m = db.upsert_monitor("cve", entity_id.upper(),
                          enabled=bool(data.get("enabled", True)),
                          cadence_hours=cadence)
    return jsonify(m)


@app.route("/monitors/<entity_id>/poll", methods=["POST"])
@login_required
def poll_monitor_now(entity_id):
    """Ad-hoc 'Check now' — runs a poll regardless of dueness."""
    m = db.get_monitor("cve", entity_id.upper())
    if not m:
        return jsonify({"error": "no monitor for this entity"}), 404
    result = monitoring.poll_monitor(m)
    items = db.get_monitor_news("cve", entity_id.upper())
    return jsonify({**result, "items": items})


@app.route("/monitor-news/<entity_id>", methods=["GET"])
@login_required
def get_monitor_news(entity_id):
    return jsonify(db.get_monitor_news("cve", entity_id.upper()))


@app.route("/monitor-news/<entity_id>/seen", methods=["POST"])
@login_required
def mark_monitor_news_seen(entity_id):
    db.mark_monitor_news_seen("cve", entity_id.upper())
    return jsonify({"ok": True})


# ── VirusTotal hash lookup ─────────────────────────────────────────

@app.route("/vt/<file_hash>", methods=["POST"])
@login_required
def vt_lookup(file_hash):
    """On-demand VT lookup for a hash IOC. Cache-first — a cached row is returned
    without spending quota; otherwise query VT live and persist the result."""
    file_hash = (file_hash or "").strip().lower()
    cached = db.get_vt_result(file_hash)
    if cached:
        return jsonify({"ok": True, "cached": True, **cached})
    result = query_virustotal(file_hash)
    if result.get("ok"):
        db.upsert_vt_result(file_hash, result)
    return jsonify({**result, "cached": False})


# ── CISA KEV watch ─────────────────────────────────────────────────

@app.route("/kev/check", methods=["POST"])
@login_required
def kev_check_now():
    """Run the KEV catalog sweep on demand (the daily scheduler does it too)."""
    try:
        result = monitoring.poll_kev()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    return jsonify(result)


@app.route("/kev/<cve_id>", methods=["GET"])
@login_required
def kev_status(cve_id):
    """Stored KEV status for one CVE (panel detail)."""
    return jsonify(db.get_kev_status(cve_id) or {"in_kev": None})


@app.route("/kev/<cve_id>/seen", methods=["POST"])
@login_required
def kev_seen(cve_id):
    db.mark_kev_seen(cve_id)
    return jsonify({"ok": True})


# ── Exploit-DB ad-hoc check ──────────────────────────────────────────────────

@app.route("/exploitdb/check/<cve_id>", methods=["POST"])
@login_required
def exploitdb_check(cve_id):
    """Ad-hoc Exploit-DB lookup for a CVE from the War Room panel."""
    import re
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id, re.IGNORECASE):
        return jsonify({"ok": False, "error": "invalid CVE ID"}), 400
    from sources.exploitdb import fetch as exploitdb_fetch
    try:
        result = exploitdb_fetch(cve_id)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    # store_exploitdb is already called inside fetch() when conv_id is set;
    # here we also need to update any conversation row that matched this CVE
    db.store_exploitdb_by_cve(cve_id, result.get("count", 0))
    return jsonify(result)


# ── CVSS ad-hoc recheck ──────────────────────────────────────────────────────

@app.route("/cvss-recheck/<cve_id>", methods=["POST"])
@login_required
def cvss_recheck(cve_id):
    """Re-fetch CVSS scores from CVE.org and EUVD and persist them.
    Returns the updated scores so the War Room panel can update immediately
    without a full War Room reload. Useful when a new CVE hasn't been
    processed by NVD/CVE.org yet — user can retry once it's available."""
    import re
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id, re.IGNORECASE):
        return jsonify({"error": "invalid CVE ID"}), 400
    cve_id = cve_id.upper()

    # Find a conv_id for this CVE to use with store_cve_metadata
    conv_id = db.get_conv_id_for_cve(cve_id) or ""

    result = {"cve_id": cve_id, "cvss_score": None, "cvss_version": None,
              "euvd_cvss_score": None, "euvd_cvss_version": None}

    # ── CVE.org score ─────────────────────────────────────────────────────────
    try:
        from sources.cveorg_primary import fetch_cveorg_primary
        cve_data = fetch_cveorg_primary(cve_id)
        score, severity, version = None, None, None
        _ver_map = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = cve_data.get(key)
            if m and m != "N/A":
                score    = m.get("baseScore")
                severity = m.get("baseSeverity")
                if score and score != "N/A":
                    version = _ver_map[key]
                    break
        if score:
            db.store_cve_metadata(conv_id, cve_id, score, severity, version, force=True)
            result["cvss_score"]   = score
            result["cvss_version"] = version
            logger.info("cvss-recheck CVE.org %s score=%s ver=%s", cve_id, score, version)
        # Seed products from CVE.org CPE data — same logic as the /send pipeline.
        # Without this, CVEs discovered indirectly (via package queries) never get
        # their infra products seeded and appear disconnected in the attack graph.
        for p in (cve_data.get("products") or []):
            vendor_name  = (p.get("vendor") or "").strip()
            product_name = (p.get("product") or "").strip()
            if not vendor_name or not product_name:
                continue
            vid = db.upsert_vendor(vendor_name)
            db.upsert_product(vid, product_name, p.get("category", "application"), conv_id)
            logger.debug("cvss-recheck seeded product %s / %s for %s", vendor_name, product_name, cve_id)
    except Exception as e:
        logger.warning("cvss-recheck CVE.org failed for %s: %s", cve_id, e)

    # ── EUVD score ────────────────────────────────────────────────────────────
    try:
        from sources.euvd import _fetch_raw as euvd_raw
        euvd_data = euvd_raw(cve_id)
        if euvd_data:
            escore   = euvd_data.get("baseScore")
            eversion = euvd_data.get("baseScoreVersion")
            if escore is not None:
                db.store_euvd_score(cve_id, escore, eversion)
                result["euvd_cvss_score"]   = escore
                result["euvd_cvss_version"] = eversion
                logger.info("cvss-recheck EUVD %s score=%s ver=%s", cve_id, escore, eversion)
    except Exception as e:
        logger.warning("cvss-recheck EUVD failed for %s: %s", cve_id, e)

    # ── KEV, EPSS, infra flag ─────────────────────────────────────────────────
    # cvss_recheck is the only manual re-entry point into the enrichment pipeline.
    # Run the same post-fetch steps the /send path and retry scheduler run, so a
    # manual recheck fully populates the War Room card.
    try:
        monitoring.ensure_kev_status(cve_id)
        logger.debug("cvss-recheck KEV ✓ %s", cve_id)
    except Exception as e:
        logger.debug("cvss-recheck KEV ✗ %s: %s", cve_id, e)
    try:
        from tools import query_epss
        epss_data  = query_epss(cve_id)
        epss_items = epss_data.get("results", [])
        if epss_items:
            ei = epss_items[0]
            db.store_epss(cve_id, ei["epss_score"], ei["percentile"])
            result["epss_score"]      = ei["epss_score"]
            result["epss_percentile"] = ei["percentile"]
            logger.debug("cvss-recheck EPSS ✓ %s score=%.4f", cve_id, ei["epss_score"])
    except Exception as e:
        logger.debug("cvss-recheck EPSS ✗ %s: %s", cve_id, e)
    if conv_id:
        db.set_relevant_to_infra(conv_id, True)

    return jsonify(result)


# ── CWE lookup — proxies MITRE REST API with SQLite cache ────────────────────

@app.route("/cwe/<cwe_id>")
@login_required
def cwe_lookup(cwe_id):
    """Proxy MITRE CWE REST API with SQLite caching.

    The CWE catalogue updates only a few times per year, so we cache
    each entry indefinitely. Endpoint: https://cwe-api.mitre.org/api/v1/cwe/weakness/{n}
    Returns {name, desc} for tooltip display.
    """
    import re as _re, urllib.request
    m = _re.match(r'^CWE-(\d+)$', cwe_id.upper())
    if not m:
        return jsonify({"error": "invalid CWE ID"}), 400
    num = m.group(1)
    canonical = f"CWE-{num}"

    cached = db.get_cwe(canonical)
    if cached:
        return jsonify(cached)

    try:
        url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{num}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = json.loads(resp.read())
    except Exception as e:
        logger.warning("CWE API fetch failed for %s: %s", canonical, e)
        return jsonify({"error": str(e)}), 502

    weaknesses = raw.get("Weaknesses", [])
    if not weaknesses:
        return jsonify({"error": "not found"}), 404
    w = weaknesses[0]
    name = w.get("Name", "")
    desc  = w.get("Description", "") or ""
    if isinstance(desc, dict):
        desc = desc.get("#text", "")
    desc = _re.sub(r"\s+", " ", desc).strip()
    if len(desc) > 260:
        desc = desc[:257] + "…"

    result = {"name": name, "desc": desc}
    db.store_cwe(canonical, result)
    return jsonify(result)


# ── EPSS ad-hoc recheck ──────────────────────────────────────────────────────

@app.route("/epss-recheck/<cve_id>", methods=["POST"])
@login_required
def epss_recheck(cve_id):
    """Re-fetch EPSS score from FIRST API and persist it."""
    import re
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id, re.IGNORECASE):
        return jsonify({"error": "invalid CVE ID"}), 400
    cve_id = cve_id.upper()
    try:
        from tools import query_epss
        data = query_epss(cve_id)
        items = data.get("results", [])
        if not items:
            return jsonify({"error": "no EPSS data returned"}), 404
        item = items[0]
        db.store_epss(cve_id, item["epss_score"], item["percentile"])
        logger.info("epss-recheck %s score=%.4f pct=%.4f", cve_id, item["epss_score"], item["percentile"])
        return jsonify({"epss_score": item["epss_score"], "epss_percentile": item["percentile"],
                        "epss_pct": item["epss_pct"], "percentile_pct": item["percentile_pct"]})
    except Exception as e:
        logger.warning("epss-recheck failed for %s: %s", cve_id, e)
        return jsonify({"error": str(e)}), 500


# ── NB — news/blog watch ───────────────────────────────────────────
# Ephemeral list + reading list + curated feed management. news.py is not an
# agent tool — only these routes and the daily 'feeds' sentinel call it.

@app.route("/news", methods=["GET"])
@login_required
def get_news():
    """Current ephemeral list (NB1), capped at the user's count (default 20)."""
    limit = max(1, min(int(request.args.get("limit", news.DEFAULT_LIMIT)), 100))
    return jsonify(db.get_news_items(limit))


@app.route("/news/refresh", methods=["POST"])
@login_required
def refresh_news():
    """NB2 — clear the non-bookmarked list and refetch every enabled feed."""
    data  = request.get_json(silent=True) or {}
    limit = max(1, min(int(data.get("limit", news.DEFAULT_LIMIT)), 100))
    result = news.poll_feeds(limit=limit)
    return jsonify({**result, "items": db.get_news_items(limit)})


@app.route("/news/seen", methods=["POST"])
@login_required
def news_seen():
    db.mark_news_seen()
    return jsonify({"ok": True})


@app.route("/news/<item_id>/bookmark", methods=["POST"])
@login_required
def bookmark_news(item_id):
    """NB3 — toggle the bookmark flag; bookmarked items survive a refresh."""
    data = request.get_json(silent=True) or {}
    ok = db.set_news_bookmarked(item_id, bool(data.get("bookmarked", True)))
    return jsonify({"ok": ok})


@app.route("/reading-list", methods=["GET"])
@login_required
def reading_list():
    return jsonify(db.get_reading_list())


@app.route("/feeds", methods=["GET"])
@login_required
def get_feeds():
    return jsonify(db.get_feeds())


@app.route("/feeds", methods=["POST"])
@login_required
def add_feed():
    """Add a source (NB5). If no feed_url is given, run the discovery helper to
    classify it as an rss feed or fall back to the Exa-domain ('exa') kind."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    url  = (data.get("url") or "").strip()
    if not name or not url:
        return jsonify({"error": "name and url required"}), 400
    kind     = data.get("kind")
    feed_url = data.get("feed_url")
    if not feed_url and kind != "exa":
        disc     = news.discover_feed(url)
        kind     = disc["kind"]
        feed_url = disc["feed_url"]
    feed = db.upsert_feed(name, url, kind=kind or "rss", feed_url=feed_url,
                          enabled=bool(data.get("enabled", True)))
    return jsonify(feed)


@app.route("/feeds/<feed_id>", methods=["PUT"])
@login_required
def update_feed(feed_id):
    """Toggle a feed on/off."""
    data = request.get_json(silent=True) or {}
    db.set_feed_enabled(feed_id, bool(data.get("enabled", True)))
    return jsonify({"ok": True})


@app.route("/feeds/<feed_id>", methods=["DELETE"])
@login_required
def remove_feed(feed_id):
    db.delete_feed(feed_id)
    return jsonify({"ok": True})


# ── NB6/NB7 — learning recommendations ──────────────────────────────

@app.route("/recommendations", methods=["GET"])
@login_required
def get_recommendations():
    """Recommended-reading cards grouped by topic, with NB7 provenance."""
    include_done = request.args.get("include_done") == "1"
    uid = session.get("user_id")
    return jsonify(db.get_recommendations(include_done=include_done, user_id=uid))


@app.route("/recommendations/run", methods=["POST"])
@login_required
def run_recommendations():
    """Ad-hoc: analyse conversations now (the daily 'learning' sentinel does it
    automatically). Returns counts + the refreshed card list."""
    uid = session.get("user_id")
    result = learning.analyze_conversations(user_id=uid)
    return jsonify({**result, "recommendations": db.get_recommendations(user_id=uid)})


@app.route("/recommendations/<rec_id>", methods=["PATCH"])
@login_required
def patch_recommendation(rec_id):
    """Mark a reading item done (read) or dismissed."""
    data   = request.get_json(silent=True) or {}
    status = data.get("status", "")
    if not db.set_rec_status(rec_id, status):
        return jsonify({"error": "invalid status or rec not found"}), 400
    return jsonify({"ok": True})


# ── OBS3 — self-observability advisory ──────────────────────────────

@app.route("/suggestions", methods=["GET"])
@login_required
def get_suggestions():
    """Advisory suggestions (the OBS5 bottom-panel tray reads this). Pending only
    by default; ?include_resolved=1 adds done."""
    include_resolved = request.args.get("include_resolved") == "1"
    return jsonify(db.get_suggestions(include_resolved=include_resolved))


@app.route("/suggestions/run", methods=["POST"])
@login_required
def run_suggestions():
    """Ad-hoc: run the advisory pass now (the 12h 'telemetry' sentinel does it
    automatically). Returns counts + the refreshed suggestion list."""
    result = obs.run_advisory()
    return jsonify({**result, "suggestions": db.get_suggestions()})


@app.route("/suggestions/<suggestion_id>", methods=["PATCH"])
@login_required
def patch_suggestion(suggestion_id):
    """Mark a suggestion done (acted on) or dismissed — both stop it re-surfacing."""
    data   = request.get_json(silent=True) or {}
    status = data.get("status", "")
    if not db.set_suggestion_status(suggestion_id, status):
        return jsonify({"error": "invalid status or suggestion not found"}), 400
    return jsonify({"ok": True})


@app.route("/telemetry/digest", methods=["GET"])
@login_required
def get_telemetry_digest():
    """The raw OBS2 digest (cost/load/cache/deltas) — drives the panel's
    projections header without an LLM call."""
    return jsonify(telemetry.aggregate())


@app.route("/checklist", methods=["GET"])
@login_required
def get_all_checklist():
    return jsonify(db.get_all_checklist())


@app.route("/checklist/<conv_id>", methods=["GET"])
@login_required
def get_checklist(conv_id):
    return jsonify(db.get_checklist(conv_id))


@app.route("/checklist/<conv_id>", methods=["POST"])
@login_required
def save_checklist(conv_id):
    items = request.get_json().get("items", [])
    if items:
        db.upsert_checklist_items(conv_id, items)
    return jsonify({"ok": True, "saved": len(items)})


@app.route("/checklist/<conv_id>/<item_id>", methods=["PATCH"])
@login_required
def patch_checklist_item(conv_id, item_id):
    status = request.get_json().get("status")
    if status not in ("pending", "done"):
        return jsonify({"error": "invalid status"}), 400
    db.update_checklist_item(item_id, status)
    return jsonify({"ok": True})


@app.route("/checklist/<conv_id>/<item_id>", methods=["DELETE"])
@login_required
def delete_checklist_item(conv_id, item_id):
    db.delete_checklist_item(item_id)
    return jsonify({"ok": True})


@app.route("/links/<conv_id>", methods=["GET"])
@login_required
def get_conversation_links(conv_id):
    """Pane A tiles for a conversation — persisted, survives server restarts."""
    return jsonify(db.get_links(conv_id))


@app.route("/candidates/<conv_id>", methods=["GET"])
@login_required
def get_candidates(conv_id):
    """Return all checklist items for a conversation (all statuses — candidate, pending, done, dismissed)."""
    return jsonify(db.get_candidates(conv_id))


def _build_system_prompt() -> list:
    """Build the Sonnet system prompt, appending known infrastructure if present.

    Two-block design (OPEN-1 resolution):
      Block 1 — SYSTEM_PROMPT: the large static body (tools, protocol, persona).
                Has cache_control so Anthropic caches it permanently across calls.
      Block 2 — dynamic infra block: the ## Known Infrastructure section.
                No cache_control — intentionally re-evaluated every call because
                it changes as products are added.

    Result: the expensive static block is always served from Anthropic's cache;
    only the small dynamic block pays full input-token cost. Adding a product to
    the infra model no longer invalidates the static cache.
    """
    vendors = db.get_infrastructure()
    if not vendors:
        return SYSTEM_PROMPT
    lines = ["## Known Infrastructure\n",
             "The user has confirmed the following products are part of their environment:\n"]
    for vendor in vendors:
        if not vendor["products"]:
            lines.append(f"- **{vendor['name']}** (no specific products recorded)")
            continue
        for product in vendor["products"]:
            label = f"{vendor['name']} {product['name']}"
            versions = product.get("versions", [])
            if versions:
                ver_str = ", ".join(v["version"] for v in versions)
                lines.append(f"- **{label}** (versions: {ver_str})")
            else:
                lines.append(f"- **{label}**")
    lines.append(
        "\nWhen analysing CVEs, explicitly cross-reference against this environment. "
        "State which of the user's systems are affected. Prioritise guidance for products "
        "present in this list."
    )
    return SYSTEM_PROMPT + [{"type": "text", "text": "\n".join(lines)}]


# ── Infrastructure routes ─────────────────────────────────────────────────────


@app.route("/infrastructure", methods=["GET"])
@login_required
def get_infrastructure():
    return jsonify(db.get_infrastructure())


@app.route("/infrastructure/vendor/<vendor_id>", methods=["DELETE"])
@login_required
def remove_infra_vendor(vendor_id):
    db.delete_infra_vendor(vendor_id)
    return jsonify({"ok": True})


@app.route("/infrastructure/product/<product_id>", methods=["DELETE"])
@login_required
def remove_infra_product(product_id):
    db.delete_infra_product(product_id)
    return jsonify({"ok": True})


@app.route("/infrastructure/version/<version_id>", methods=["DELETE"])
@login_required
def remove_infra_version(version_id):
    db.delete_infra_version(version_id)
    return jsonify({"ok": True})


# ── Profile (AUTH-1) ─────────────────────────────────────────────────────────

@app.route("/profile", methods=["GET"])
@login_required
def get_profile():
    user = db.get_user_by_id(session.get("user_id"))
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": user["username"], "email": user["email"]})


@app.route("/profile/password", methods=["PATCH"])
@login_required
def change_password():
    import re as _re
    from werkzeug.security import check_password_hash as _chk, generate_password_hash as _gen
    data    = request.get_json() or {}
    current = data.get("current_password", "")
    new_pw  = data.get("new_password", "")
    user    = db.get_user_by_id(session.get("user_id"))
    if not user or not _chk(user["password_hash"], current):
        return jsonify({"error": "Current password is incorrect."}), 400
    rules = [_re.compile(p) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]")]
    if len(new_pw) < 15 or not all(r.search(new_pw) for r in rules):
        return jsonify({"error": "Password must be ≥15 characters with uppercase, lowercase, digit, and symbol."}), 400
    db.update_user_password(user["id"], _gen(new_pw))
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True)
