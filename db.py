import sqlite3
import uuid
import json
import logging
import os
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_DB_PATH = os.getenv("DB_PATH", "smashedburger.db")

# ── Access contract for sources/ modules ──────────────────────────────────────
# Modules in sources/ may import db directly but are restricted to two domains:
#   • CVE intel writes: store_cve_metadata, store_cveorg_data, store_exploitdb,
#                       store_exploitdb_by_cve, store_euvd_score, queue_cve_retry
#   • Infra writes:     upsert_vendor, upsert_product, upsert_version
# Anything outside these domains (conversations, messages, auth, checklist,
# monitors, telemetry, suggestions) must go through main.py routes, not sources/.
# ─────────────────────────────────────────────────────────────────────────────


def _now() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# Stable namespace for deterministic infrastructure IDs
_INFRA_NS = uuid.UUID("c9d8e7f6-a5b4-4c3d-2e1f-0a9b8c7d6e5f")

_LEGAL_SUFFIX = re.compile(
    r"\s+(inc\.?|llc\.?|ltd\.?|corp\.?|corporation|limited|gmbh|s\.a\.?|plc|ag|bv|nv)\.?$",
    re.IGNORECASE,
)

def _normalize_vendor(name: str) -> str:
    """Strip common legal suffixes so 'Google LLC' and 'Google' hash to the same row."""
    return _LEGAL_SUFFIX.sub("", name.strip()).strip()

def _infra_id(*parts: str) -> str:
    """Deterministic ID from one or more string parts joined by ':'."""
    return str(uuid.uuid5(_INFRA_NS, ":".join(p.lower().strip() for p in parts)))


def _conn() -> sqlite3.Connection:
    """Open a read connection. WAL mode lets reads proceed concurrently with writes."""
    conn = sqlite3.connect(_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# ── Write serialisation (TEACHABLE-4) ────────────────────────────────────────
# A gevent Semaphore(1) acts as a per-process write mutex: only one greenlet
# holds a write connection at a time; others queue behind it cooperatively.
# This eliminates intra-process write contention. WAL handles cross-process
# read/write overlap. Together they cover both concurrency axes for SQLite.
#
# Why Semaphore and not a queue? A Semaphore(1) IS the degenerate queue — one
# slot, first-come first-served. A full job-queue (gevent.queue.Queue + worker
# greenlet) adds ordering guarantees and batching but isn't needed here.
# Use a full queue when you need to coalesce writes or guarantee strict ordering
# beyond what the semaphore provides.
_write_lock = None

def _get_write_lock():
    global _write_lock
    if _write_lock is None:
        try:
            from gevent.lock import Semaphore
            _write_lock = Semaphore(1)
        except ImportError:
            # gevent not available (e.g. unit tests) — use a no-op context
            import contextlib
            _write_lock = contextlib.nullcontext()
    return _write_lock


class _WriteConn:
    """Context manager: acquires the write semaphore, yields a connection, releases on exit."""
    def __enter__(self):
        _get_write_lock().acquire()
        self._conn = sqlite3.connect(_DB_PATH, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        return self._conn

    def __exit__(self, exc_type, *_):
        try:
            if exc_type:
                self._conn.rollback()
            else:
                self._conn.commit()
        finally:
            self._conn.close()
            _get_write_lock().release()


def _wconn():
    """Return a write-serialised connection context manager."""
    return _WriteConn()


def init_db():
    """Create tables if they don't exist."""
    logger.info("init_db — path=%s", _DB_PATH)
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS conversations (
                id                TEXT PRIMARY KEY,
                title             TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL,
                user_id           TEXT,
                relevant_to_infra INTEGER NOT NULL DEFAULT 0,
                cve_id            TEXT,
                cvss_score        REAL,
                cvss_severity     TEXT,
                cvss_version      TEXT,
                euvd_cvss_score   REAL,
                euvd_cvss_version TEXT,
                cna               TEXT,
                cwe_id            TEXT,
                exploitdb_count   INTEGER
            );

            CREATE TABLE IF NOT EXISTS messages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT    NOT NULL
                                        REFERENCES conversations(id)
                                        ON DELETE CASCADE,
                role            TEXT    NOT NULL,
                content         TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checklist_items (
                id         TEXT PRIMARY KEY,
                conv_id    TEXT NOT NULL,
                text       TEXT NOT NULL,
                source     TEXT NOT NULL,
                type       TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending',
                cve_id     TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS infra_vendors (
                id       TEXT PRIMARY KEY,
                name     TEXT NOT NULL UNIQUE,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS infra_products (
                id        TEXT PRIMARY KEY,
                vendor_id TEXT NOT NULL REFERENCES infra_vendors(id) ON DELETE CASCADE,
                name      TEXT NOT NULL,
                category  TEXT NOT NULL DEFAULT 'other',
                conv_id   TEXT,
                UNIQUE(vendor_id, name)
            );

            CREATE TABLE IF NOT EXISTS infra_versions (
                id         TEXT PRIMARY KEY,
                product_id TEXT NOT NULL REFERENCES infra_products(id) ON DELETE CASCADE,
                version    TEXT NOT NULL,
                conv_id    TEXT NOT NULL,
                added_at   TEXT NOT NULL,
                UNIQUE(product_id, version)
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id        TEXT PRIMARY KEY,
                cve_id    TEXT NOT NULL,
                type      TEXT NOT NULL,
                value     TEXT NOT NULL,
                context   TEXT,
                reference TEXT,
                mitre_id  TEXT,
                found_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ioc_sources (
                id        TEXT PRIMARY KEY,
                cve_id    TEXT NOT NULL,
                url       TEXT NOT NULL,
                title     TEXT,
                found_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS monitors (
                id             TEXT PRIMARY KEY,
                entity_type    TEXT NOT NULL,
                entity_id      TEXT NOT NULL,
                enabled        INTEGER NOT NULL DEFAULT 1,
                cadence_hours  INTEGER NOT NULL DEFAULT 24,
                last_polled_at TEXT,
                created_at     TEXT NOT NULL,
                UNIQUE(entity_type, entity_id)
            );

            CREATE TABLE IF NOT EXISTS vt_results (
                hash       TEXT PRIMARY KEY,
                in_vt      INTEGER NOT NULL DEFAULT 0,
                malicious  INTEGER,
                suspicious INTEGER,
                total      INTEGER,
                reputation INTEGER,
                name       TEXT,
                link       TEXT,
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kev_status (
                cve_id            TEXT PRIMARY KEY,
                in_kev            INTEGER NOT NULL DEFAULT 0,
                date_added        TEXT,
                due_date          TEXT,
                ransomware        TEXT,
                short_description TEXT,
                required_action   TEXT,
                product           TEXT,
                checked_at        TEXT NOT NULL,
                added_seen        INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS monitor_news (
                id             TEXT PRIMARY KEY,
                entity_type    TEXT NOT NULL,
                entity_id      TEXT NOT NULL,
                url            TEXT NOT NULL,
                title          TEXT,
                published_date TEXT,
                snippet        TEXT,
                found_at       TEXT NOT NULL,
                seen           INTEGER NOT NULL DEFAULT 0
            );

            -- CWE controls: user-recorded remediations for a weakness class.
            -- One control can cover multiple CVEs that share the same CWE —
            -- this is the posture leverage point in the attack surface graph.
            CREATE TABLE IF NOT EXISTS cwe_controls (
                id         TEXT PRIMARY KEY,
                cwe_id     TEXT NOT NULL,
                text       TEXT NOT NULL,
                added_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS links (
                conv_id     TEXT NOT NULL,
                url         TEXT NOT NULL,
                source      TEXT,
                type        TEXT,
                title       TEXT,
                description TEXT,
                added_at    TEXT NOT NULL,
                PRIMARY KEY (conv_id, url)
            );

            -- NB (news/blog watch) — curated source list. kind 'rss' = a
            -- feedparser-readable feed at feed_url; 'exa' = no feed, discovered
            -- via Exa includeDomains fallback (HeroDevs). url = the human site.
            CREATE TABLE IF NOT EXISTS feeds (
                id        TEXT PRIMARY KEY,
                name      TEXT NOT NULL,
                url       TEXT NOT NULL,
                kind      TEXT NOT NULL DEFAULT 'rss',
                feed_url  TEXT,
                enabled   INTEGER NOT NULL DEFAULT 1,
                added_at  TEXT NOT NULL
            );

            -- NB — fetched news items. Ephemeral by design (NB2): a refresh
            -- clears every row EXCEPT bookmarked=1, which is the reading list
            -- (NB3). PK = uuid5(url) so the same article never duplicates and a
            -- re-fetch of an already-bookmarked item preserves its flag.
            CREATE TABLE IF NOT EXISTS news_items (
                id         TEXT PRIMARY KEY,
                source     TEXT,
                url        TEXT NOT NULL,
                title      TEXT,
                published  TEXT,
                summary    TEXT,
                fetched_at TEXT NOT NULL,
                seen       INTEGER NOT NULL DEFAULT 0,
                bookmarked INTEGER NOT NULL DEFAULT 0
            );

            -- NB6 learning recommendations. A `topic` is a class-level concept
            -- lifted off the user's conversations (status taught = already
            -- recommended, so it never re-surfaces — the dedup mechanism).
            CREATE TABLE IF NOT EXISTS topics (
                id         TEXT PRIMARY KEY,
                concept    TEXT NOT NULL,
                class      TEXT,
                weight     REAL NOT NULL DEFAULT 0,
                status     TEXT NOT NULL DEFAULT 'pending',
                user_id    TEXT,
                created_at TEXT NOT NULL
            );

            -- NB7 provenance: every reason a topic was suggested traces to a
            -- concrete conversation turn (role + is_question drive the weight,
            -- title powers the "suggested because you explored this in [A],[B]").
            CREATE TABLE IF NOT EXISTS topic_mentions (
                id          TEXT PRIMARY KEY,
                topic_id    TEXT NOT NULL,
                conv_id     TEXT,
                conv_title  TEXT,
                theme       TEXT,
                role        TEXT,
                is_question INTEGER NOT NULL DEFAULT 0,
                quote       TEXT,
                created_at  TEXT NOT NULL
            );

            -- NB6 recommended reading: one row per surfaced teaching link.
            -- Reuses the Pane B candidate state machine (pending|done|dismissed).
            CREATE TABLE IF NOT EXISTS learning_recs (
                id         TEXT PRIMARY KEY,
                topic_id   TEXT NOT NULL,
                concept    TEXT,
                why_teach  TEXT,
                title      TEXT,
                url        TEXT NOT NULL,
                source     TEXT,
                snippet    TEXT,
                status     TEXT NOT NULL DEFAULT 'pending',
                user_id    TEXT,
                created_at TEXT NOT NULL
            );

            -- OBS1 — append-only self-observability telemetry. One row
            -- per LLM call, tool call, or CRUD op at the three choke points.
            -- Measurement is deterministic code: token counts come verbatim from
            -- the Anthropic `usage` object; cost is computed later (OBS2), never
            -- stored, so a price-config change re-prices history for free.
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts                    TEXT NOT NULL,
                kind                  TEXT NOT NULL,            -- llm | tool | crud
                name                  TEXT NOT NULL,           -- purpose / tool name
                model                 TEXT,
                input_tokens          INTEGER NOT NULL DEFAULT 0,
                output_tokens         INTEGER NOT NULL DEFAULT 0,
                cache_read_tokens     INTEGER NOT NULL DEFAULT 0,
                cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
                latency_ms            INTEGER NOT NULL DEFAULT 0,
                ok                    INTEGER NOT NULL DEFAULT 1,
                conv_id               TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_telemetry_ts       ON telemetry_events(ts);
            CREATE INDEX IF NOT EXISTS idx_telemetry_conv      ON telemetry_events(conv_id);
            CREATE INDEX IF NOT EXISTS idx_messages_conv       ON messages(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_checklist_conv      ON checklist_items(conv_id);
            CREATE INDEX IF NOT EXISTS idx_topic_mentions_conv ON topic_mentions(conv_id);
            CREATE INDEX IF NOT EXISTS idx_conversations_cve   ON conversations(cve_id);
            CREATE INDEX IF NOT EXISTS idx_monitor_news_entity ON monitor_news(entity_type, entity_id);
            -- idx_nvd_retry_conv is defined after its table below — executescript
            -- runs top-to-bottom, so an index before its table crashes a fresh DB.

            -- AUTH-1 — users + ephemeral auth codes (2FA, email-verify, pw-reset).
            -- user_id is deterministic: uuid5(_USER_NS, email.lower()).
            -- password_hash via werkzeug.security (scrypt); codes stored as sha256.
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                verified      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            );

            -- purpose: '2fa' (5-min 6-digit) | 'email_verify' (24-h URL token)
            --          | 'password_reset' (15-min URL token)
            -- one-shot: mark used=1 on first successful validation.
            CREATE TABLE IF NOT EXISTS auth_codes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash  TEXT NOT NULL,
                purpose    TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            );

            -- OBS3 — advisory suggestions from the 2×/day Opus pass.
            -- id = uuid5(normalised title): the SAME advice from a later run
            -- collapses onto its existing row (INSERT OR IGNORE), so a dismissed
            -- or done suggestion never re-surfaces. Reuses the Pane B candidate
            -- state machine: pending | done | dismissed.
            CREATE TABLE IF NOT EXISTS telemetry_suggestions (
                id         TEXT PRIMARY KEY,        -- uuid5(issue_key)
                issue_key  TEXT,                    -- canonical kebab slug = dedup identity
                title      TEXT NOT NULL,           -- free-form display text (reworded run-to-run)
                category   TEXT NOT NULL,           -- arch | token | load
                metric     TEXT,                    -- the cited digest metric (grounding)
                rationale  TEXT,
                impact     TEXT,
                status     TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );

            -- NVD retry queue: when NVD times out, a row is queued here and the
            -- scheduler retries with backoff. UNIQUE(cve_id, conv_id) means a
            -- duplicate /send call for the same CVE never queues a second attempt.
            -- products_seeded=1 means EUVD already extracted products for this
            -- conversation, so the NVD retry skips llm_extract_products.
            CREATE TABLE IF NOT EXISTS nvd_retry_queue (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id           TEXT NOT NULL,
                conv_id          TEXT NOT NULL,
                attempts         INTEGER NOT NULL DEFAULT 0,
                next_retry_at    TEXT NOT NULL,
                products_seeded  INTEGER NOT NULL DEFAULT 0,
                created_at       TEXT NOT NULL,
                UNIQUE(cve_id, conv_id)
            );
            -- Index defined here, right after its table — NOT in the index block
            -- above. executescript runs top-to-bottom; on a fresh DB an index that
            -- precedes its table fails with "no such table". Idempotent on existing DBs.
            CREATE INDEX IF NOT EXISTS idx_nvd_retry_conv ON nvd_retry_queue(conv_id);

            -- CVE intelligence records — keyed by CVE ID, NOT by conversation.
            -- Survives conversation deletion. One row per unique CVE ever discussed.
            -- The conversations table keeps a cve_id FK for the "discussed in" link,
            -- but all CVE-specific fields live here so the War Room is CVE-centric.
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id            TEXT PRIMARY KEY,
                cvss_score        REAL,
                cvss_severity     TEXT,
                cvss_version      TEXT,
                euvd_cvss_score   REAL,
                euvd_cvss_version TEXT,
                cna               TEXT,
                cwe_id            TEXT,
                exploitdb_count   INTEGER,
                description       TEXT,
                epss_score        REAL,
                epss_percentile   REAL,
                cvss_vector       TEXT,
                updated_at        TEXT NOT NULL
            );

            -- Package intelligence records — keyed by 'ecosystem:package'.
            -- Survives conversation deletion (no FK to conversations).
            -- War Room package cards read from here; infra vendor/product rows
            -- are seeded separately in infra_vendors/infra_products.
            CREATE TABLE IF NOT EXISTS pkg_records (
                id            TEXT PRIMARY KEY,  -- 'ecosystem:package'
                ecosystem     TEXT NOT NULL,
                package       TEXT NOT NULL,
                vuln_count    INTEGER NOT NULL DEFAULT 0,
                malware_count INTEGER NOT NULL DEFAULT 0,
                highest_sev   TEXT,
                updated_at    TEXT NOT NULL
            );

            -- CWE description cache — populated on first graph tooltip hover via
            -- the MITRE CWE REST API (https://cwe-api.mitre.org/api/v1/).
            -- The catalogue changes only a few times a year so no expiry needed.
            CREATE TABLE IF NOT EXISTS cwe_cache (
                cwe_id    TEXT PRIMARY KEY,   -- e.g. 'CWE-502'
                name      TEXT NOT NULL DEFAULT '',
                desc      TEXT NOT NULL DEFAULT '',
                cached_at TEXT NOT NULL
            );

            -- Conversation → package links (no FK — survives conversation deletion).
            -- Lets the War Room panel show 'Open conversation' for a package entry
            -- even after some conversations about it have been deleted.
            CREATE TABLE IF NOT EXISTS pkg_conv_links (
                pkg_id  TEXT NOT NULL,
                conv_id TEXT NOT NULL,
                PRIMARY KEY (pkg_id, conv_id)
            );

            -- Attack graph: user-declared or Sonnet-inferred relationships between
            -- infra nodes. source/target use stable node IDs: "product:<vendor>:<name>",
            -- "zone:<name>", "os:<vendor>:<name>". user_confirmed=1 means the user
            -- explicitly validated this edge; 0 means Sonnet inferred it (confidence 0.7).
            CREATE TABLE IF NOT EXISTS infra_relationships (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                source_node_id    TEXT NOT NULL,
                target_node_id    TEXT NOT NULL,
                relationship_type TEXT NOT NULL,  -- runs_on | depends_on | exposed_via | hosts
                user_confirmed    INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT NOT NULL
            );

            -- Network and security controls that modify CVE reachability for a node.
            -- constraint_type: firewall | port_restriction | waf | dmz | air_gap
            -- detail: free text, e.g. "80,443" for port_restriction
            CREATE TABLE IF NOT EXISTS network_constraints (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id         TEXT NOT NULL,
                constraint_type TEXT NOT NULL,
                detail          TEXT,
                created_at      TEXT NOT NULL
            );
        """)
        for col in [
            "ALTER TABLE conversations ADD COLUMN user_id TEXT",
            "ALTER TABLE conversations ADD COLUMN relevant_to_infra INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE conversations ADD COLUMN cve_id TEXT",
            "ALTER TABLE conversations ADD COLUMN cvss_score REAL",
            "ALTER TABLE conversations ADD COLUMN cvss_severity TEXT",
            "ALTER TABLE conversations ADD COLUMN cvss_version TEXT",
            "ALTER TABLE checklist_items ADD COLUMN cve_id TEXT",
            "ALTER TABLE iocs ADD COLUMN reference TEXT",
            "ALTER TABLE iocs ADD COLUMN mitre_id TEXT",
            "ALTER TABLE telemetry_suggestions ADD COLUMN issue_key TEXT",
            "ALTER TABLE conversations ADD COLUMN euvd_cvss_score REAL",
            "ALTER TABLE conversations ADD COLUMN euvd_cvss_version TEXT",
            "ALTER TABLE conversations ADD COLUMN cna TEXT",
            "ALTER TABLE conversations ADD COLUMN cwe_id TEXT",
            "ALTER TABLE conversations ADD COLUMN exploitdb_count INTEGER",
            "ALTER TABLE topics ADD COLUMN user_id TEXT",
            "ALTER TABLE learning_recs ADD COLUMN user_id TEXT",
            # conv_id on infra_products: records which conversation caused the product
            # to be seeded — gives us a direct CVE→Product link without needing versions.
            "ALTER TABLE infra_products ADD COLUMN conv_id TEXT",
            "ALTER TABLE cve_records ADD COLUMN description TEXT",
            "ALTER TABLE cve_records ADD COLUMN epss_score REAL",
            "ALTER TABLE cve_records ADD COLUMN epss_percentile REAL",
            "ALTER TABLE cve_records ADD COLUMN cvss_vector TEXT",
        ]:
            try:
                conn.execute(col)
            except Exception:
                pass  # Column already exists

        # Migrate existing CVE data from conversations into cve_records.
        # INSERT OR IGNORE — if the row already exists, keep existing data.
        conn.execute("""
            INSERT OR IGNORE INTO cve_records
                (cve_id, cvss_score, cvss_severity, cvss_version,
                 euvd_cvss_score, euvd_cvss_version,
                 cna, cwe_id, exploitdb_count, updated_at)
            SELECT cve_id, cvss_score, cvss_severity, cvss_version,
                   euvd_cvss_score, euvd_cvss_version,
                   cna, cwe_id, exploitdb_count, updated_at
            FROM conversations
            WHERE cve_id IS NOT NULL
        """)

        # Backfill cve_id on existing checklist items from their conversation.
        # Safe to run on every startup — only touches rows where cve_id IS NULL.
        conn.execute("""
            UPDATE checklist_items
            SET cve_id = (
                SELECT c.cve_id FROM conversations c WHERE c.id = checklist_items.conv_id
            )
            WHERE cve_id IS NULL
            AND EXISTS (
                SELECT 1 FROM conversations c
                WHERE c.id = checklist_items.conv_id AND c.cve_id IS NOT NULL
            )
        """)

    _seed_default_feeds()
    logger.info("init_db complete")


# NB5 — the curated source list feeds BOTH the watcher (NB1) and, later, the
# learning-rec quality pool (NB6). One list, two uses. Confirmed feed URLs
# (PROGRESS 2026-06-12): Snyk RSS, Socket Atom, OX WordPress RSS; HeroDevs has
# no feed (Webflow) → kind 'exa' fallback. INSERT OR IGNORE on a deterministic
# id makes this idempotent — re-seeding never clobbers a user's edits/removals
# because removed rows are deleted, not disabled, and edited rows keep their id.
_DEFAULT_FEEDS = [
    ("Snyk",      "https://snyk.io/blog/",            "rss", "https://snyk.io/blog/feed/"),
    ("Socket",    "https://socket.dev/blog",          "rss", "https://socket.dev/api/blog/feed.atom"),
    ("OX Security","https://www.ox.security/blog/",    "rss", "https://www.ox.security/blog/category/research/feed/"),
    ("HeroDevs",  "https://www.herodevs.com/blog",     "exa", None),
]


def _seed_default_feeds():
    """Insert the default NB5 source set once. Idempotent via deterministic id."""
    now = _now()
    with _conn() as conn:
        # Only seed when the table is empty so user removals stick across restarts.
        if conn.execute("SELECT COUNT(*) FROM feeds").fetchone()[0] > 0:
            return
        conn.executemany(
            """INSERT OR IGNORE INTO feeds (id, name, url, kind, feed_url, enabled, added_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            [(_infra_id("feed", name), name, url, kind, feed_url, now)
             for name, url, kind, feed_url in _DEFAULT_FEEDS],
        )


def create_conversation(conv_id: str, title: str, user_id: str = None):
    """Insert a new conversation. created_at and updated_at = now (ISO 8601 UTC)."""
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO conversations (id, title, user_id, created_at, updated_at) VALUES (?,?,?,?,?)",
            (conv_id, title, user_id, now, now),
        )
    logger.debug("conversation created conv=%s", conv_id[:8])


def ensure_conversation(conv_id: str, user_id: str = None) -> bool:
    """LO-1 (server side): Guarantee a conversation row exists before messages reference it.

    Returns True if a new row was created (the conv was missing). Defensive:
    /send appends messages with a FK to conversations(id); if the client sends a
    conv_id that was never persisted or was wiped (DB reset on redeploy, deleted
    in another tab, machine restart), the INSERT OR IGNORE creates it so the
    message insert can't FOREIGN KEY-fail and 500 the whole request."""
    now = _now()
    with _conn() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO conversations (id, title, user_id, created_at, updated_at) "
            "VALUES (?,?,?,?,?)",
            (conv_id, "New conversation", user_id, now, now),
        )
        created = cur.rowcount > 0
    if created:
        logger.warning("conversation auto-created conv=%s (stale client id — ghost recovery)", conv_id[:8])
    return created


def update_title(conv_id: str, title: str):
    """Update the title and updated_at for a conversation."""
    with _conn() as conn:
        conn.execute(
            "UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?",
            (title, _now(), conv_id),
        )


def touch_conversation(conv_id: str):
    """Update updated_at to now — called after new messages are saved."""
    with _conn() as conn:
        conn.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (_now(), conv_id),
        )


def append_message(conv_id: str, role: str, content):
    """
    Serialize content to JSON and insert a message row.
    content may be a string or a list of dicts — json.dumps both cases.
    Failures are logged at WARNING rather than silently swallowed — a missed
    persist means in-memory history diverges from the DB, which surfaces as
    lost messages after a server restart.
    """
    try:
        with _wconn() as conn:
            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                (conv_id, role, json.dumps(content), _now()),
            )
    except Exception as exc:
        logger.warning("append_message failed conv=%s role=%s: %s", conv_id, role, exc)


def load_messages(conv_id: str, limit: int = None, offset: int = 0) -> tuple:
    """
    Return (messages, total) for a conversation.
    With limit/offset: newest-first DESC slice, reversed to chronological order.
    Without limit: all messages in chronological order.
    """
    with _conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?", (conv_id,)
        ).fetchone()[0]
        if limit is not None:
            rows = conn.execute(
                "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (conv_id, limit, offset),
            ).fetchall()
            rows = list(reversed(rows))
        else:
            rows = conn.execute(
                "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC",
                (conv_id,),
            ).fetchall()
    messages = [{"role": row["role"], "content": json.loads(row["content"])} for row in rows]
    return messages, total


def list_conversations(user_id: str = None) -> list:
    """Return conversations ordered by updated_at DESC. Filtered by user_id when given."""
    with _conn() as conn:
        if user_id:
            rows = conn.execute(
                "SELECT id, title, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC",
                (user_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, title, updated_at FROM conversations ORDER BY updated_at DESC",
            ).fetchall()
    return [dict(row) for row in rows]


def delete_conversation(conv_id: str):
    """Delete the conversation — messages cascade automatically.
    Checklist items are intentionally NOT deleted — they persist beyond conversation lifetime.
    Pane A links ARE deleted — they have no cross-conversation screen."""
    with _conn() as conn:
        conn.execute("DELETE FROM conversations WHERE id = ?", (conv_id,))
        conn.execute("DELETE FROM links WHERE conv_id = ?", (conv_id,))
    logger.info("conversation deleted conv=%s", conv_id[:8])


def upsert_links(conv_id: str, links: list):
    """Persist Pane A link tiles. INSERT OR REPLACE keyed on (conv_id, url) —
    re-extracting the same URL refreshes its title/description."""
    if not links:
        return
    now = _now()
    with _conn() as conn:
        conn.executemany(
            """INSERT OR REPLACE INTO links
               (conv_id, url, source, type, title, description, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(conv_id, l["url"], l.get("source", ""), l.get("type", ""),
              l.get("title", ""), l.get("description", ""), now) for l in links],
        )


def get_links(conv_id: str) -> list:
    with _conn() as conn:
        rows = conn.execute(
            """SELECT url, source, type, title, description
               FROM links WHERE conv_id = ? ORDER BY added_at""",
            (conv_id,),
        ).fetchall()
    return [{"url": r[0], "source": r[1], "type": r[2],
             "title": r[3], "description": r[4]} for r in rows]


def upsert_candidates(conv_id: str, items: list):
    """Auto-save extracted action items as candidates. INSERT OR IGNORE — never
    overwrites an item that has already been committed or dismissed."""
    now = _now()
    with _conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO checklist_items
               (id, conv_id, text, source, type, status, cve_id, created_at)
               VALUES (?, ?, ?, ?, ?, 'candidate', ?, ?)""",
            [(item["id"], conv_id, item["text"], item["source"], item["type"],
              item.get("cve_id"), now)
             for item in items],
        )


def upsert_checklist_items(conv_id: str, items: list):
    """Persist selected action items to the checklist. INSERT OR IGNORE — safe to call
    repeatedly; existing items (by id) are not overwritten."""
    now = _now()
    with _conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO checklist_items
               (id, conv_id, text, source, type, status, cve_id, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
            [(item["id"], conv_id, item["text"], item["source"], item["type"],
              item.get("cve_id"), now)
             for item in items],
        )


def get_checklist(conv_id: str) -> list:
    """Return all checklist items for a conversation, ordered by creation time."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, text, source, type, status FROM checklist_items "
            "WHERE conv_id = ? ORDER BY created_at ASC",
            (conv_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_checklist() -> list:
    """Return all non-candidate checklist items across all conversations, with conversation title and CVE."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT ci.id, ci.conv_id, ci.text, ci.source, ci.type, ci.status,
                      ci.cve_id,
                      COALESCE(c.title, ci.conv_id) AS conv_title
               FROM checklist_items ci
               LEFT JOIN conversations c ON ci.conv_id = c.id
               WHERE ci.status != 'candidate'
               ORDER BY
                   CASE WHEN ci.cve_id IS NOT NULL THEN 0 ELSE 1 END,
                   ci.cve_id,
                   ci.created_at DESC""",
        ).fetchall()
    return [dict(row) for row in rows]


def get_candidates(conv_id: str) -> list:
    """Return all candidate items for a conversation."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT id, text, source, type, status, cve_id FROM checklist_items
               WHERE conv_id = ?
               ORDER BY created_at ASC""",
            (conv_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_stats() -> dict:
    """Return headline counts for the dashboard."""
    with _conn() as conn:
        cves = conn.execute(
            "SELECT COUNT(*) FROM conversations WHERE relevant_to_infra = 1"
        ).fetchone()[0]
        products = conn.execute(
            "SELECT COUNT(*) FROM infra_products"
        ).fetchone()[0]
        actions = conn.execute(
            "SELECT COUNT(*) FROM checklist_items WHERE status IN ('pending', 'done')"
        ).fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM checklist_items WHERE status = 'pending'"
        ).fetchone()[0]
        done = conn.execute(
            "SELECT COUNT(*) FROM checklist_items WHERE status = 'done'"
        ).fetchone()[0]
    return {"cves": cves, "products": products, "actions": actions, "pending": pending, "done": done}


def update_checklist_item(item_id: str, status: str):
    """Update the status of a checklist item (pending / done)."""
    with _conn() as conn:
        conn.execute(
            "UPDATE checklist_items SET status = ? WHERE id = ?",
            (status, item_id),
        )


def delete_checklist_item(item_id: str):
    """Hard-delete a checklist item — used for both Pane B discard and Checklist screen dismiss."""
    with _conn() as conn:
        conn.execute("DELETE FROM checklist_items WHERE id = ?", (item_id,))


# ── Infrastructure hierarchy ──────────────────────────────────────────────────

def upsert_vendor(name: str) -> str:
    """Insert vendor if not exists. Returns vendor id."""
    name = _normalize_vendor(name)
    vid = _infra_id(name)
    with _wconn() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO infra_vendors (id, name, added_at) VALUES (?, ?, ?)",
            (vid, name, _now()),
        )
    if cur.rowcount:
        logger.debug("infra vendor added name=%s", name)
    return vid


def upsert_product(vendor_id: str, name: str, category: str = "other",
                   conv_id: str | None = None) -> str:
    """Insert product under vendor if not exists. Returns product id.
    conv_id records which conversation caused this product to be seeded —
    the direct audit trail for CVE→Product graph edges without needing versions."""
    pid = _infra_id(vendor_id, name)
    with _wconn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO infra_products (id, vendor_id, name, category, conv_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (pid, vendor_id, name.strip(), category, conv_id),
        )
        # If the product already existed with no conv_id, backfill it now.
        # INSERT OR IGNORE silently skips on conflict, so conv_id would stay NULL
        # forever on products seeded before conv_id was tracked.
        if conv_id:
            conn.execute(
                "UPDATE infra_products SET conv_id = ? WHERE id = ? AND conv_id IS NULL",
                (conv_id, pid),
            )
    return pid


def upsert_version(product_id: str, version: str, conv_id: str) -> str:
    """Insert version under product if not exists. Returns version id."""
    vid = _infra_id(product_id, version)
    with _wconn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO infra_versions (id, product_id, version, conv_id, added_at) VALUES (?, ?, ?, ?, ?)",
            (vid, product_id, version.strip(), conv_id, _now()),
        )
    return vid


def get_infrastructure() -> list:
    """Return full vendor→product→version hierarchy as a list of vendor dicts."""
    with _conn() as conn:
        vendors = conn.execute(
            "SELECT id, name FROM infra_vendors ORDER BY name"
        ).fetchall()
        result = []
        for v in vendors:
            products = conn.execute(
                "SELECT id, name, category, conv_id FROM infra_products WHERE vendor_id = ? ORDER BY name",
                (v["id"],),
            ).fetchall()
            product_list = []
            for p in products:
                versions = conn.execute(
                    "SELECT id, version FROM infra_versions WHERE product_id = ? ORDER BY added_at",
                    (p["id"],),
                ).fetchall()
                product_list.append({
                    "id":       p["id"],
                    "name":     p["name"],
                    "category": p["category"],
                    "conv_id":  p["conv_id"],
                    "versions": [dict(r) for r in versions],
                })
            result.append({
                "id":       v["id"],
                "name":     v["name"],
                "products": product_list,
            })
    return result


def delete_infra_vendor(vendor_id: str):
    """Remove vendor and all its products and versions (cascade)."""
    with _conn() as conn:
        conn.execute("DELETE FROM infra_vendors WHERE id = ?", (vendor_id,))


def delete_infra_product(product_id: str):
    """Remove product and all its versions (cascade)."""
    with _conn() as conn:
        conn.execute("DELETE FROM infra_products WHERE id = ?", (product_id,))


def delete_infra_version(version_id: str):
    """Remove a single version entry."""
    with _conn() as conn:
        conn.execute("DELETE FROM infra_versions WHERE id = ?", (version_id,))


def store_cve_metadata(conv_id: str, cve_id: str, score, severity: str,
                       version: str = None, force: bool = False,
                       cvss_vector: str = None):
    """Link this conversation to a CVE and upsert the CVE record.
    Writes to cve_records (keyed by CVE ID) so data survives conversation deletion.
    Default: first score/severity wins (COALESCE — EUVD placeholder holds until NVD lands).
    force=True: NVD retry path — always overwrite with authoritative NVD data."""
    sev = (severity or "").upper() or None
    now = _now()
    with _wconn() as conn:
        # Link conversation → CVE (first CVE seen in this conversation wins)
        conn.execute(
            "UPDATE conversations SET cve_id = ? WHERE id = ? AND cve_id IS NULL",
            (cve_id, conv_id),
        )
        if force:
            # NVD retry: always overwrite — COALESCE would silently drop real scores
            # if EUVD had already written a placeholder (even None blocks COALESCE).
            conn.execute(
                """INSERT INTO cve_records (cve_id, cvss_score, cvss_severity, cvss_version, cvss_vector, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(cve_id) DO UPDATE SET
                       cvss_score    = excluded.cvss_score,
                       cvss_severity = excluded.cvss_severity,
                       cvss_version  = excluded.cvss_version,
                       cvss_vector   = COALESCE(excluded.cvss_vector, cve_records.cvss_vector),
                       updated_at    = excluded.updated_at""",
                (cve_id, score, sev, version, cvss_vector, now),
            )
        else:
            # Normal path: first score wins (COALESCE)
            conn.execute(
                """INSERT INTO cve_records (cve_id, cvss_score, cvss_severity, cvss_version, cvss_vector, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(cve_id) DO UPDATE SET
                       cvss_score    = COALESCE(cve_records.cvss_score,    excluded.cvss_score),
                       cvss_severity = COALESCE(cve_records.cvss_severity, excluded.cvss_severity),
                       cvss_version  = COALESCE(cve_records.cvss_version,  excluded.cvss_version),
                       cvss_vector   = COALESCE(cve_records.cvss_vector,   excluded.cvss_vector),
                       updated_at    = excluded.updated_at""",
                (cve_id, score, sev, version, cvss_vector, now),
            )
    logger.debug("CVE metadata stored cve=%s score=%s severity=%s force=%s", cve_id, score, sev, force)


def _conv_cve_id(conn, conv_id: str):
    """Resolve the CVE ID linked to a conversation (used by sibling store functions)."""
    row = conn.execute("SELECT cve_id FROM conversations WHERE id = ?", (conv_id,)).fetchone()
    return row["cve_id"] if row else None


def store_cveorg_data(conv_id: str, cna: str, cwe_id: str, description: str | None = None):
    """Upsert CNA, CWE, and description into cve_records. First write wins (COALESCE)."""
    now = _now()
    with _conn() as conn:
        cve_id = _conv_cve_id(conn, conv_id)
        if not cve_id:
            return
        conn.execute(
            """INSERT INTO cve_records (cve_id, cna, cwe_id, description, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   cna         = COALESCE(cve_records.cna,         excluded.cna),
                   cwe_id      = COALESCE(cve_records.cwe_id,      excluded.cwe_id),
                   description = COALESCE(cve_records.description, excluded.description),
                   updated_at  = excluded.updated_at""",
            (cve_id, cna, cwe_id, description, now),
        )


def store_exploitdb(conv_id: str, count: int):
    """Upsert Exploit-DB count into cve_records. Always overwrites (latest count wins)."""
    now = _now()
    with _conn() as conn:
        cve_id = _conv_cve_id(conn, conv_id)
        if not cve_id:
            return
        conn.execute(
            """INSERT INTO cve_records (cve_id, exploitdb_count, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   exploitdb_count = excluded.exploitdb_count,
                   updated_at      = excluded.updated_at""",
            (cve_id, count, now),
        )


def store_exploitdb_by_cve(cve_id: str, count: int):
    """Upsert Exploit-DB count for a CVE ID directly (ad-hoc War Room 'Check now' path)."""
    now = _now()
    with _conn() as conn:
        conn.execute(
            """INSERT INTO cve_records (cve_id, exploitdb_count, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   exploitdb_count = excluded.exploitdb_count,
                   updated_at      = excluded.updated_at""",
            (cve_id.upper(), count, now),
        )


# ── Attack graph ─────────────────────────────────────────────────────────────

def store_relationship(source_node_id: str, target_node_id: str,
                       relationship_type: str, user_confirmed: bool = False) -> int:
    """Upsert an infra relationship edge. Returns the row id.
    Node IDs use the scheme: product:<vendor>:<name>, zone:<name>, os:<vendor>:<name>.
    Duplicate (source, target, type) tuples are ignored — first write wins."""
    now = _now()
    with _conn() as conn:
        cur = conn.execute(
            """INSERT INTO infra_relationships
                   (source_node_id, target_node_id, relationship_type, user_confirmed, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT DO NOTHING""",
            (source_node_id, target_node_id, relationship_type, int(user_confirmed), now),
        )
        if cur.lastrowid:
            return cur.lastrowid
        row = conn.execute(
            "SELECT id FROM infra_relationships WHERE source_node_id=? AND target_node_id=? AND relationship_type=?",
            (source_node_id, target_node_id, relationship_type),
        ).fetchone()
        return row[0] if row else -1


def confirm_relationship(rel_id: int):
    """Mark a relationship as user-confirmed (full weight in attack graph)."""
    with _conn() as conn:
        conn.execute("UPDATE infra_relationships SET user_confirmed=1 WHERE id=?", (rel_id,))


def delete_relationship(rel_id: int):
    with _conn() as conn:
        conn.execute("DELETE FROM infra_relationships WHERE id=?", (rel_id,))


def store_network_constraint(node_id: str, constraint_type: str, detail: str | None = None):
    """Upsert a network/security control for a node. Duplicate (node_id, type) ignored."""
    now = _now()
    with _conn() as conn:
        conn.execute(
            """INSERT INTO network_constraints (node_id, constraint_type, detail, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT DO NOTHING""",
            (node_id, constraint_type, detail, now),
        )


def get_attack_graph_data() -> dict:
    """Return all relationship edges and network constraints for attack graph computation."""
    with _conn() as conn:
        rels = [dict(r) for r in conn.execute(
            "SELECT id, source_node_id, target_node_id, relationship_type, user_confirmed FROM infra_relationships"
        ).fetchall()]
        constraints = [dict(r) for r in conn.execute(
            "SELECT node_id, constraint_type, detail FROM network_constraints"
        ).fetchall()]
    return {"relationships": rels, "constraints": constraints}


def get_cwe(cwe_id: str) -> dict | None:
    """Return cached CWE {name, desc} or None if not yet cached."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT name, desc FROM cwe_cache WHERE cwe_id = ?", (cwe_id,)
        ).fetchone()
    return {"name": row["name"], "desc": row["desc"]} if row else None


def store_cwe(cwe_id: str, data: dict) -> None:
    """Cache a CWE entry fetched from the MITRE REST API."""
    with _conn() as conn:
        conn.execute(
            """INSERT INTO cwe_cache (cwe_id, name, desc, cached_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(cwe_id) DO UPDATE SET
                   name = excluded.name,
                   desc = excluded.desc,
                   cached_at = excluded.cached_at""",
            (cwe_id, data.get("name", ""), data.get("desc", ""), _now()),
        )


def store_epss(cve_id: str, score: float, percentile: float):
    """Upsert EPSS exploitation probability into cve_records. Always overwrites —
    EPSS is updated daily by FIRST so the latest value is always more accurate."""
    if not cve_id:
        return
    now = _now()
    with _conn() as conn:
        conn.execute(
            """INSERT INTO cve_records (cve_id, epss_score, epss_percentile, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   epss_score       = excluded.epss_score,
                   epss_percentile  = excluded.epss_percentile,
                   updated_at       = excluded.updated_at""",
            (cve_id.upper(), score, percentile, now),
        )


def store_euvd_score(cve_id: str, score: float, version: str):
    """Upsert EUVD CVSS score into cve_records. First write wins (COALESCE).
    Takes cve_id directly — the old signature looked it up via _conv_cve_id which
    returned NULL when NVD had not yet set conversations.cve_id (NVD-fail path),
    silently dropping the score and hiding the cross-validation section."""
    if not cve_id:
        return
    now = _now()
    with _conn() as conn:
        conn.execute(
            """INSERT INTO cve_records (cve_id, euvd_cvss_score, euvd_cvss_version, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   euvd_cvss_score   = COALESCE(cve_records.euvd_cvss_score,   excluded.euvd_cvss_score),
                   euvd_cvss_version = COALESCE(cve_records.euvd_cvss_version, excluded.euvd_cvss_version),
                   updated_at        = excluded.updated_at""",
            (cve_id.upper(), score, version, now),
        )


def get_cve_dashboard() -> dict:
    """Return all tracked CVEs with checklist progress for the War Room.

    Keyed by cve_records.cve_id — survives conversation deletion. Each row
    includes a conv_id/title pointing to the most recent conversation that
    discussed this CVE (for the 'Open conversation' link in the panel)."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT
                   cr.cve_id AS id,
                   cr.cve_id,
                   cr.cvss_score, cr.cvss_severity, cr.cvss_version,
                   cr.euvd_cvss_score, cr.euvd_cvss_version,
                   cr.cna, cr.cwe_id, cr.exploitdb_count, cr.description,
                   cr.epss_score, cr.epss_percentile, cr.cvss_vector, cr.updated_at,
                   (SELECT c2.id    FROM conversations c2
                    WHERE  c2.cve_id = cr.cve_id
                    ORDER  BY c2.updated_at DESC LIMIT 1) AS conv_id,
                   (SELECT c2.title FROM conversations c2
                    WHERE  c2.cve_id = cr.cve_id
                    ORDER  BY c2.updated_at DESC LIMIT 1) AS title,
                   COUNT(CASE WHEN ci.status = 'pending' THEN 1 END) AS pending_count,
                   COUNT(CASE WHEN ci.status = 'done'    THEN 1 END) AS done_count,
                   (SELECT m.enabled FROM monitors m
                    WHERE m.entity_type = 'cve' AND m.entity_id = cr.cve_id) AS monitor_enabled,
                   (SELECT COUNT(*) FROM monitor_news mn
                    WHERE mn.entity_type = 'cve' AND mn.entity_id = cr.cve_id
                      AND mn.seen = 0) AS unseen_news,
                   k.in_kev AS kev_in, k.ransomware AS kev_ransomware,
                   k.added_seen AS kev_seen
               FROM cve_records cr
               LEFT JOIN checklist_items ci
                   ON ci.cve_id = cr.cve_id AND ci.status IN ('pending', 'done')
               LEFT JOIN kev_status k ON k.cve_id = cr.cve_id
               GROUP BY cr.cve_id
               ORDER BY
                   CASE cr.cvss_severity
                       WHEN 'CRITICAL' THEN 1
                       WHEN 'HIGH'     THEN 2
                       WHEN 'MEDIUM'   THEN 3
                       WHEN 'LOW'      THEN 4
                       ELSE 5
                   END,
                   cr.updated_at DESC""",
        ).fetchall()
    cves = [dict(r) for r in rows]

    with _conn() as conn:
        pkg_rows = conn.execute(
            """SELECT
                   pr.id, pr.ecosystem, pr.package,
                   pr.vuln_count, pr.malware_count, pr.highest_sev, pr.updated_at,
                   (SELECT pcl.conv_id FROM pkg_conv_links pcl
                    WHERE pcl.pkg_id = pr.id
                    ORDER BY rowid DESC LIMIT 1) AS conv_id
               FROM pkg_records pr
               ORDER BY
                   CASE pr.highest_sev
                       WHEN 'CRITICAL' THEN 1 WHEN 'HIGH'   THEN 2
                       WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'    THEN 4
                       ELSE 5 END,
                   pr.updated_at DESC""",
        ).fetchall()
    packages = [dict(r) for r in pkg_rows]

    def _sev(item, key):
        return (item.get(key) or "").upper()

    all_items = cves + packages
    stats = {
        "total":        len(all_items),
        "critical":     sum(1 for c in cves if _sev(c, "cvss_severity") == "CRITICAL")
                      + sum(1 for p in packages if _sev(p, "highest_sev") == "CRITICAL"),
        "high":         sum(1 for c in cves if _sev(c, "cvss_severity") == "HIGH")
                      + sum(1 for p in packages if _sev(p, "highest_sev") == "HIGH"),
        "medium":       sum(1 for c in cves if _sev(c, "cvss_severity") == "MEDIUM")
                      + sum(1 for p in packages if _sev(p, "highest_sev") == "MEDIUM"),
        "actions_open": sum(c["pending_count"] for c in cves),
    }
    # ── Attack graph ─────────────────────────────────────────────────────────
    # Build the weighted node+edge payload for the force-graph renderer.
    # Imported here to avoid circular imports at module load time.
    infra      = get_infrastructure()
    graph_data = get_attack_graph_data()
    try:
        from graph import build_attack_graph
        attack_graph = build_attack_graph(
            cves, infra,
            graph_data["relationships"],
            graph_data["constraints"],
        )
    except Exception as exc:
        logger.warning("attack graph build failed: %s", exc)
        attack_graph = {"nodes": [], "edges": []}

    return {"stats": stats, "cves": cves, "packages": packages,
            "attack_graph": attack_graph}


def add_cwe_control(cwe_id: str, text: str) -> str:
    """Record a control or remediation for a CWE weakness class.
    One control here covers every CVE in the graph that shares this CWE."""
    import uuid
    cid = str(uuid.uuid4())
    with _conn() as conn:
        conn.execute(
            "INSERT INTO cwe_controls (id, cwe_id, text, added_at) VALUES (?, ?, ?, ?)",
            (cid, cwe_id.upper(), text.strip(), _now()),
        )
    return cid


def get_cwe_controls(cwe_id: str | None = None) -> list[dict]:
    """Return all controls, or controls for a specific CWE."""
    with _conn() as conn:
        if cwe_id:
            rows = conn.execute(
                "SELECT * FROM cwe_controls WHERE cwe_id = ? ORDER BY added_at DESC",
                (cwe_id.upper(),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cwe_controls ORDER BY cwe_id, added_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def delete_cwe_control(control_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM cwe_controls WHERE id = ?", (control_id,))


def get_graph_data() -> dict:
    """Global attack-surface graph — social network model.

    CVEs and Packages are the central nodes. CWE is the posture leverage point:
    one control on a CWE covers every CVE that shares it.

    Node types:
      cve       — tracked CVE, coloured by severity
      cwe       — weakness class; size = CVE count; has_control flag
      vendor    — confirmed infrastructure vendor
      product   — specific product under a vendor
      package   — pkg_records entry
      ecosystem — package registry grouping

    Edge types (no CNA heuristics — structural data only):
      root_cause  CVE → CWE      cve_records.cwe_id; weight = CVEs sharing this CWE
      affects     CVE → Product  conversations.cve_id → infra_products.conv_id (audit trail)
      owns        Vendor → Product infra_products.vendor_id
      has_cve     Package → CVE  pkg_conv_links → conversations.cve_id
      contains    Ecosystem → Package grouping
      same_lib    Product ↔ Package substring name match (low confidence, dashed)

    CWE node enrichment:
      cve_count    — how many CVEs in the graph share this CWE (drives node size)
      has_control  — whether the user has recorded a control/remediation for it
      control_count — number of controls recorded
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()
    edge_set: set[tuple] = set()

    def _add_node(nid, **kwargs):
        if nid not in node_ids:
            nodes.append({"id": nid, **kwargs})
            node_ids.add(nid)

    def _add_edge(src, dst, rel, **kwargs):
        key = (src, dst, rel)
        if key not in edge_set:
            edges.append({"source": src, "target": dst, "rel": rel, **kwargs})
            edge_set.add(key)

    with _conn() as conn:
        # ── CWE weights and controls (pre-computed) ────────────────────────
        cwe_weight = {}
        for r in conn.execute(
            "SELECT cwe_id, COUNT(*) AS cnt FROM cve_records WHERE cwe_id IS NOT NULL GROUP BY cwe_id"
        ).fetchall():
            cwe_weight[r["cwe_id"]] = r["cnt"]

        cwe_controls_map: dict[str, int] = {}
        for r in conn.execute(
            "SELECT cwe_id, COUNT(*) AS cnt FROM cwe_controls GROUP BY cwe_id"
        ).fetchall():
            cwe_controls_map[r["cwe_id"]] = r["cnt"]

        # ── CVE nodes — enriched in one query ─────────────────────────────
        cve_rows = conn.execute(
            """SELECT
                   cr.cve_id, cr.cvss_severity, cr.cwe_id,
                   cr.exploitdb_count, cr.cvss_score,
                   k.in_kev, k.ransomware,
                   COUNT(DISTINCT CASE WHEN ci.status='pending' THEN ci.id END) AS pending_actions,
                   COUNT(DISTINCT ioc.id) AS ioc_count,
                   MAX(CASE WHEN m.enabled=1 THEN 1 ELSE 0 END) AS monitored
               FROM cve_records cr
               LEFT JOIN kev_status k       ON k.cve_id  = cr.cve_id
               LEFT JOIN checklist_items ci  ON ci.cve_id = cr.cve_id
               LEFT JOIN iocs ioc            ON ioc.cve_id = cr.cve_id
               LEFT JOIN monitors m          ON m.entity_type='cve' AND m.entity_id=cr.cve_id
               GROUP BY cr.cve_id"""
        ).fetchall()
        for r in cve_rows:
            _add_node(r["cve_id"],
                type="cve", label=r["cve_id"],
                severity=(r["cvss_severity"] or "UNKNOWN").upper(),
                cwe_id=r["cwe_id"],
                cvss_score=r["cvss_score"],
                exploitdb_count=r["exploitdb_count"] or 0,
                in_kev=bool(r["in_kev"]),
                ransomware=r["ransomware"] or None,
                pending_actions=r["pending_actions"] or 0,
                ioc_count=r["ioc_count"] or 0,
                monitored=bool(r["monitored"]),
            )
            # CVE → CWE with weight = number of CVEs sharing this weakness class.
            # A heavier edge means fixing this CWE covers more CVEs simultaneously.
            if r["cwe_id"]:
                w = cwe_weight.get(r["cwe_id"], 1)
                cc = cwe_controls_map.get(r["cwe_id"], 0)
                _add_node(r["cwe_id"],
                    type="cwe", label=r["cwe_id"],
                    cve_count=w,
                    has_control=cc > 0,
                    control_count=cc,
                )
                _add_edge(r["cve_id"], r["cwe_id"], "root_cause", weight=w)

        # ── Vendor + Product nodes ─────────────────────────────────────────
        infra_rows = conn.execute(
            """SELECT iv.id AS vid, iv.name AS vname,
                      ip.id AS pid, ip.name AS pname, ip.category
               FROM   infra_vendors iv
               LEFT JOIN infra_products ip ON ip.vendor_id = iv.id"""
        ).fetchall()
        product_list: list[dict] = []
        for r in infra_rows:
            vid = f"vendor:{r['vid']}"
            _add_node(vid, type="vendor", label=r["vname"])
            if r["pid"]:
                pid = f"product:{r['pid']}"
                _add_node(pid, type="product", label=r["pname"], category=r["category"])
                _add_edge(vid, pid, "owns")
                product_list.append({"nid": pid, "name": r["pname"].lower()})

        # ── CVE → Product (structural via infra_products.conv_id) ──────────
        # The conversation that discussed a CVE seeded the products it affects.
        # conv_id on infra_products is the direct, version-independent audit trail.
        cve_product_rows = conn.execute(
            """SELECT DISTINCT c.cve_id, ip.id AS pid
               FROM   conversations c
               JOIN   infra_products ip ON ip.conv_id = c.id
               WHERE  c.cve_id IS NOT NULL"""
        ).fetchall()
        for r in cve_product_rows:
            pid = f"product:{r['pid']}"
            if r["cve_id"] in node_ids and pid in node_ids:
                _add_edge(r["cve_id"], pid, "affects")

        # ── Package nodes ──────────────────────────────────────────────────
        # pending_actions: count open checklist items reachable via the package's
        # conversations (pkg_conv_links → conversations.cve_id → checklist_items).
        pkg_rows = conn.execute(
            """SELECT pr.id, pr.ecosystem, pr.package, pr.vuln_count, pr.malware_count, pr.highest_sev,
                      COUNT(DISTINCT CASE WHEN ci.status='pending' THEN ci.id END) AS pending_actions
               FROM   pkg_records pr
               LEFT JOIN pkg_conv_links pcl ON pcl.pkg_id = pr.id
               LEFT JOIN conversations c    ON c.id = pcl.conv_id AND c.cve_id IS NOT NULL
               LEFT JOIN checklist_items ci ON ci.cve_id = c.cve_id
               GROUP BY pr.id"""
        ).fetchall()
        package_list: list[dict] = []
        for r in pkg_rows:
            nid     = f"pkg:{r['id']}"
            eco_nid = f"eco:{r['ecosystem'].lower()}"
            _add_node(nid, type="package", label=r["package"],
                      ecosystem=r["ecosystem"],
                      vuln_count=r["vuln_count"] or 0,
                      malware_count=r["malware_count"] or 0,
                      severity=(r["highest_sev"] or "UNKNOWN").upper(),
                      pending_actions=r["pending_actions"] or 0)
            _add_node(eco_nid, type="ecosystem", label=r["ecosystem"])
            _add_edge(eco_nid, nid, "contains")
            package_list.append({"nid": nid, "name": r["package"].lower()})

        # ── Package → CVE (via shared conversation) ────────────────────────
        pkg_cve_rows = conn.execute(
            """SELECT DISTINCT pcl.pkg_id, c.cve_id
               FROM   pkg_conv_links pcl
               JOIN   conversations c ON c.id = pcl.conv_id
               WHERE  c.cve_id IS NOT NULL"""
        ).fetchall()
        for r in pkg_cve_rows:
            pkg_nid = f"pkg:{r['pkg_id']}"
            if pkg_nid in node_ids and r["cve_id"] in node_ids:
                _add_edge(pkg_nid, r["cve_id"], "has_cve")

        # ── Product ↔ Package name match (low confidence) ─────────────────
        for prod in product_list:
            if len(prod["name"]) < 4:
                continue
            for pkg in package_list:
                if prod["name"] in pkg["name"] or pkg["name"] in prod["name"]:
                    _add_edge(prod["nid"], pkg["nid"], "same_lib")

    return {"nodes": nodes, "edges": edges}


def store_pkg_record(ecosystem: str, package: str, vuln_count: int,
                     malware_count: int, highest_sev: str | None, conv_id: str | None):
    """Upsert a package intelligence record keyed by 'ecosystem:package'.
    Always overwrites counts (re-query reflects current state). No FK to
    conversations — survives deletion."""
    pkg_id = f"{ecosystem.lower()}:{package.lower()}"
    now = _now()
    with _conn() as conn:
        conn.execute(
            """INSERT INTO pkg_records (id, ecosystem, package, vuln_count, malware_count, highest_sev, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   vuln_count    = excluded.vuln_count,
                   malware_count = excluded.malware_count,
                   highest_sev   = excluded.highest_sev,
                   updated_at    = excluded.updated_at""",
            (pkg_id, ecosystem.lower(), package, vuln_count, malware_count, highest_sev, now),
        )
        if conv_id:
            conn.execute(
                "INSERT OR IGNORE INTO pkg_conv_links (pkg_id, conv_id) VALUES (?, ?)",
                (pkg_id, conv_id),
            )


def set_relevant_to_infra(conv_id: str, value: bool):
    """Mark or unmark a conversation as relevant to infrastructure."""
    with _conn() as conn:
        conn.execute(
            "UPDATE conversations SET relevant_to_infra = ? WHERE id = ?",
            (1 if value else 0, conv_id),
        )


# ── IOC persistence ───────────────────────────────────────────────────────────

def upsert_iocs(cve_id: str, iocs: list):
    """Persist extracted IOCs. INSERT OR IGNORE — stable ID prevents duplicates."""
    now = _now()
    with _conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO iocs (id, cve_id, type, value, context, reference, mitre_id, found_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    str(uuid.uuid5(_INFRA_NS, f"{cve_id}:{ioc.get('type')}:{ioc.get('value','').lower()}")),
                    cve_id,
                    ioc.get("type", ""),
                    ioc.get("value", ""),
                    ioc.get("context"),
                    ioc.get("reference"),
                    ioc.get("mitre_id"),
                    now,
                )
                for ioc in iocs
            ],
        )


def upsert_ioc_sources(cve_id: str, sources: list):
    """Persist IOC source URLs. INSERT OR IGNORE by stable ID."""
    now = _now()
    with _conn() as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO ioc_sources (id, cve_id, url, title, found_at)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    str(uuid.uuid5(_INFRA_NS, f"{cve_id}:{s.get('url','').lower()}")),
                    cve_id,
                    s.get("url", ""),
                    s.get("title"),
                    now,
                )
                for s in sources
                if s.get("url")
            ],
        )


# ── Monitors (Phase G) ────────────────────────────────────────────────────────
# Entity-generic: entity_type 'cve' today, 'package' when Library-card monitors land.

def _monitor_id(entity_type: str, entity_id: str) -> str:
    return _infra_id("monitor", entity_type, entity_id)


def upsert_monitor(entity_type: str, entity_id: str,
                   enabled: bool = True, cadence_hours: int = 24) -> dict:
    """Create or update a monitor. last_polled_at is preserved on update so
    toggling off/on does not reset the schedule."""
    mid = _monitor_id(entity_type, entity_id)
    with _conn() as conn:
        conn.execute(
            """INSERT INTO monitors (id, entity_type, entity_id, enabled, cadence_hours, created_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled,
                                             cadence_hours = excluded.cadence_hours""",
            (mid, entity_type, entity_id, 1 if enabled else 0, cadence_hours, _now()),
        )
    return get_monitor(entity_type, entity_id)


def get_monitor(entity_type: str, entity_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM monitors WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        ).fetchone()
    return dict(row) if row else None


def get_enabled_monitors() -> list:
    """All enabled monitors — dueness is computed in Python (ISO-string timestamps)."""
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM monitors WHERE enabled = 1").fetchall()
    return [dict(r) for r in rows]


def set_monitor_polled(monitor_id: str, polled_at: str | None = None):
    with _conn() as conn:
        conn.execute(
            "UPDATE monitors SET last_polled_at = ? WHERE id = ?",
            (polled_at or _now(), monitor_id),
        )


def upsert_monitor_news(entity_type: str, entity_id: str, items: list) -> int:
    """Persist news items, INSERT OR IGNORE keyed on uuid5(entity:url).
    Returns the number of genuinely new rows (the delta badge)."""
    if not items:
        return 0
    now = _now()
    with _conn() as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM monitor_news WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        ).fetchone()[0]
        conn.executemany(
            """INSERT OR IGNORE INTO monitor_news
               (id, entity_type, entity_id, url, title, published_date, snippet, found_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    str(uuid.uuid5(_INFRA_NS, f"news:{entity_type}:{entity_id}:{i['url'].lower()}")),
                    entity_type, entity_id, i["url"],
                    i.get("title", ""), i.get("published_date", ""),
                    i.get("snippet", ""), now,
                )
                for i in items if i.get("url")
            ],
        )
        after = conn.execute(
            "SELECT COUNT(*) FROM monitor_news WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        ).fetchone()[0]
    return after - before


def get_monitor_news(entity_type: str, entity_id: str, limit: int = 30) -> list:
    with _conn() as conn:
        rows = conn.execute(
            """SELECT url, title, published_date, snippet, found_at, seen
               FROM monitor_news WHERE entity_type = ? AND entity_id = ?
               ORDER BY published_date DESC, found_at DESC LIMIT ?""",
            (entity_type, entity_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_monitor_news_seen(entity_type: str, entity_id: str):
    with _conn() as conn:
        conn.execute(
            "UPDATE monitor_news SET seen = 1 WHERE entity_type = ? AND entity_id = ?",
            (entity_type, entity_id),
        )


# ── NB — feeds + news items (news/blog watch) ─────────────────────────────────

def _feed_id(name: str) -> str:
    return _infra_id("feed", name)


def _news_id(url: str) -> str:
    return _infra_id("news", url.lower())


def get_feeds(enabled_only: bool = False) -> list:
    q = "SELECT * FROM feeds"
    if enabled_only:
        q += " WHERE enabled = 1"
    q += " ORDER BY added_at"
    with _conn() as conn:
        return [dict(r) for r in conn.execute(q).fetchall()]


def upsert_feed(name: str, url: str, kind: str = "rss",
                feed_url: str | None = None, enabled: bool = True) -> dict:
    """Add or update a feed (id is deterministic from the name)."""
    fid = _feed_id(name)
    with _conn() as conn:
        conn.execute(
            """INSERT INTO feeds (id, name, url, kind, feed_url, enabled, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET url = excluded.url, kind = excluded.kind,
                                             feed_url = excluded.feed_url,
                                             enabled = excluded.enabled""",
            (fid, name, url, kind, feed_url, 1 if enabled else 0, _now()),
        )
        row = conn.execute("SELECT * FROM feeds WHERE id = ?", (fid,)).fetchone()
    return dict(row)


def set_feed_enabled(feed_id: str, enabled: bool):
    with _conn() as conn:
        conn.execute("UPDATE feeds SET enabled = ? WHERE id = ?",
                     (1 if enabled else 0, feed_id))


def delete_feed(feed_id: str):
    with _conn() as conn:
        conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))


def replace_news_items(items: list) -> int:
    """NB2 ephemeral refresh: drop every non-bookmarked row, then insert the
    fresh batch. INSERT OR IGNORE on uuid5(url) means a freshly-fetched article
    that is already bookmarked keeps its flag (never demoted, never duplicated).
    Returns the number of rows inserted as new (not already present)."""
    now = _now()
    with _conn() as conn:
        conn.execute("DELETE FROM news_items WHERE bookmarked = 0")
        before = conn.execute("SELECT COUNT(*) FROM news_items").fetchone()[0]
        conn.executemany(
            """INSERT OR IGNORE INTO news_items
                 (id, source, url, title, published, summary, fetched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(_news_id(i["url"]), i.get("source"), i["url"], i.get("title"),
              i.get("published"), i.get("summary"), now)
             for i in items if i.get("url")],
        )
        after = conn.execute("SELECT COUNT(*) FROM news_items").fetchone()[0]
    return after - before


def get_news_items(limit: int = 20) -> list:
    """The current news list (NB1) — newest first, capped at the user's count.
    Bookmarked items that resurfaced in the latest fetch appear here too."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT id, source, url, title, published, summary, fetched_at, seen, bookmarked
               FROM news_items ORDER BY published DESC, fetched_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_reading_list() -> list:
    """NB3 — the reading list is exactly news_items WHERE bookmarked = 1."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT id, source, url, title, published, summary, fetched_at, seen, bookmarked
               FROM news_items WHERE bookmarked = 1
               ORDER BY published DESC, fetched_at DESC""",
        ).fetchall()
    return [dict(r) for r in rows]


def set_news_bookmarked(item_id: str, bookmarked: bool) -> bool:
    with _conn() as conn:
        cur = conn.execute("UPDATE news_items SET bookmarked = ? WHERE id = ?",
                           (1 if bookmarked else 0, item_id))
    return cur.rowcount > 0


def mark_news_seen():
    """Clear the unseen flag for the whole current list (delta-badge UX)."""
    with _conn() as conn:
        conn.execute("UPDATE news_items SET seen = 1 WHERE seen = 0")


# ── NB6/NB7 — learning topics, provenance, recommendations ────────────────────

def get_all_user_ids() -> list[str]:
    """Return IDs of all registered users (for per-user scheduler passes)."""
    with _conn() as conn:
        rows = conn.execute("SELECT id FROM users").fetchall()
    return [r["id"] for r in rows]


def topic_id(concept: str, user_id: str = "") -> str:
    """Deterministic id from the normalised concept + user → re-running analysis
    on the same recurring topic for the same user hits the same row.
    Including user_id means two users' topics for the same concept are independent
    rows, so taught/pending state is per-user."""
    return _infra_id("topic", user_id, concept)


def get_topic(tid: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM topics WHERE id = ?", (tid,)).fetchone()
    return dict(row) if row else None


def upsert_topic(concept: str, klass: str, weight: float, status: str = "pending",
                 user_id: str = "") -> str:
    """Create/refresh a topic. A `taught` topic is NOT downgraded back to pending
    on re-analysis — that's what stops a rec from re-surfacing."""
    tid = topic_id(concept, user_id)
    with _conn() as conn:
        conn.execute(
            """INSERT INTO topics (id, concept, class, weight, status, user_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET weight = excluded.weight,
                                             class = excluded.class""",
            (tid, concept, klass, weight, status, user_id or None, _now()),
        )
    return tid


def mark_topic_taught(tid: str):
    with _conn() as conn:
        conn.execute("UPDATE topics SET status = 'taught' WHERE id = ?", (tid,))


def is_topic_taught(concept: str, user_id: str = "") -> bool:
    t = get_topic(topic_id(concept, user_id))
    return bool(t and t["status"] == "taught")


def replace_topic_mentions(tid: str, mentions: list):
    """Provenance rows for a topic (NB7). Replaced wholesale on each analysis so
    the 'suggested because…' trail reflects the latest corpus."""
    now = _now()
    with _conn() as conn:
        conn.execute("DELETE FROM topic_mentions WHERE topic_id = ?", (tid,))
        conn.executemany(
            """INSERT INTO topic_mentions
                 (id, topic_id, conv_id, conv_title, theme, role, is_question, quote, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(str(uuid.uuid5(_INFRA_NS, f"mention:{tid}:{i}")), tid,
              m.get("conv_id"), m.get("conv") or m.get("conv_title"), m.get("theme"),
              m.get("role"), 1 if m.get("is_question") else 0, (m.get("quote") or "")[:300], now)
             for i, m in enumerate(mentions)],
        )


def get_topic_mentions(tid: str) -> list:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT conv_id, conv_title, theme, role, is_question, quote FROM topic_mentions WHERE topic_id = ?",
            (tid,),
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_learning_recs(tid: str, concept: str, why_teach: str, recs: list,
                         user_id: str = "") -> int:
    """Persist surfaced reading links for a topic. INSERT OR IGNORE on uuid5(url)
    so re-analysis never duplicates a link or resets a done/dismissed one.
    Returns the count of genuinely new recs."""
    if not recs:
        return 0
    now = _now()
    with _conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM learning_recs WHERE topic_id = ?", (tid,)).fetchone()[0]
        conn.executemany(
            """INSERT OR IGNORE INTO learning_recs
                 (id, topic_id, concept, why_teach, title, url, source, snippet, status, user_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            [(str(uuid.uuid5(_INFRA_NS, f"rec:{tid}:{r['url'].lower()}")), tid, concept, why_teach,
              r.get("title"), r["url"], r.get("source"), (r.get("snippet") or "")[:400],
              user_id or None, now)
             for r in recs if r.get("url")],
        )
        after = conn.execute("SELECT COUNT(*) FROM learning_recs WHERE topic_id = ?", (tid,)).fetchone()[0]
    return after - before


def get_recommendations(include_done: bool = False, user_id: str | None = None) -> list:
    """Recommended-reading cards, grouped by topic with NB7 provenance. Dismissed
    recs are always hidden; done ones only when include_done. When user_id is given,
    only that user's recommendations are returned."""
    statuses = ("pending", "done") if include_done else ("pending",)
    placeholders = ",".join("?" * len(statuses))
    user_filter = "AND r.user_id = ?" if user_id else ""
    params = (*statuses, *([user_id] if user_id else []))
    with _conn() as conn:
        rows = conn.execute(
            f"""SELECT r.id, r.topic_id, r.concept, r.why_teach, r.title, r.url,
                       r.source, r.snippet, r.status, t.weight, t.class
                FROM learning_recs r LEFT JOIN topics t ON t.id = r.topic_id
                WHERE r.status IN ({placeholders}) {user_filter}
                ORDER BY t.weight DESC, r.created_at DESC""",
            params,
        ).fetchall()
    recs = [dict(r) for r in rows]
    # Attach provenance per topic (small N — one query per distinct topic is fine).
    prov: dict = {}
    grouped: dict = {}
    for r in recs:
        tid = r["topic_id"]
        if tid not in prov:
            prov[tid] = get_topic_mentions(tid)
        g = grouped.setdefault(tid, {
            "topic_id": tid, "concept": r["concept"], "why_teach": r["why_teach"],
            "class": r.get("class"), "weight": r.get("weight"),
            "mentions": prov[tid], "items": [],
        })
        g["items"].append({k: r[k] for k in ("id", "title", "url", "source", "snippet", "status")})
    return list(grouped.values())


def set_rec_status(rec_id: str, status: str) -> bool:
    if status not in ("pending", "done", "dismissed"):
        return False
    with _conn() as conn:
        cur = conn.execute("UPDATE learning_recs SET status = ? WHERE id = ?", (status, rec_id))
    return cur.rowcount > 0


def delete_cve_iocs(cve_id: str):
    """Wipe all persisted IOCs and sources for a CVE — the re-baseline path
: INSERT OR IGNORE keeps polluted rows forever otherwise."""
    with _conn() as conn:
        conn.execute("DELETE FROM iocs WHERE cve_id = ?", (cve_id,))
        conn.execute("DELETE FROM ioc_sources WHERE cve_id = ?", (cve_id,))


# ── OBS — self-observability telemetry ──────────────────────────────

def insert_telemetry_event(
    kind: str, name: str, model: str | None,
    input_tokens: int = 0, output_tokens: int = 0,
    cache_read_tokens: int = 0, cache_creation_tokens: int = 0,
    latency_ms: int = 0, ok: bool = True, conv_id: str | None = None,
    ts: str | None = None,
):
    """Append one telemetry row. Append-only — never updated or deleted (retention
    rollup deferred, single-user PoC). `ts` override exists only for fixture tests."""
    with _conn() as conn:
        conn.execute(
            """INSERT INTO telemetry_events
                 (ts, kind, name, model, input_tokens, output_tokens,
                  cache_read_tokens, cache_creation_tokens, latency_ms, ok, conv_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts or _now(), kind, name, model,
             int(input_tokens), int(output_tokens),
             int(cache_read_tokens), int(cache_creation_tokens),
             int(latency_ms), 1 if ok else 0, conv_id),
        )


def get_telemetry_events(since: str | None = None, until: str | None = None) -> list:
    """Rows in [since, until). ISO-8601 strings sort lexicographically (all UTC),
    so the range filter is a plain string comparison — no date parsing in SQL."""
    q = "SELECT * FROM telemetry_events"
    clauses, params = [], []
    if since is not None:
        clauses.append("ts >= ?"); params.append(since)
    if until is not None:
        clauses.append("ts < ?");  params.append(until)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY ts"
    with _conn() as conn:
        return [dict(r) for r in conn.execute(q, params).fetchall()]


def first_telemetry_ts() -> str | None:
    """Earliest event timestamp, or None if the table is empty — used to bound the
    aggregation window when no explicit `since` is given."""
    with _conn() as conn:
        row = conn.execute("SELECT MIN(ts) AS t FROM telemetry_events").fetchone()
    return row["t"] if row and row["t"] else None


def _suggestion_slug(text: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", text.strip().lower())).strip("-")


def _suggestion_id(key: str) -> str:
    """Deterministic id from the canonical ISSUE KEY (not the title) — the same
    underlying issue from a later run hashes to the same row even when the model
    rewords the title."""
    return str(uuid.uuid5(_INFRA_NS, f"obs:{key.strip().lower()}"))


def upsert_suggestions(suggestions: list) -> int:
    """Persist advisory suggestions. INSERT OR IGNORE on uuid5(issue_key) — a
    suggestion whose issue is already on file (in ANY status, incl. dismissed/done)
    is left untouched, so advice never re-surfaces even when reworded. Falls back
    to a slug of the title if no key is supplied. Returns the count of new rows."""
    if not suggestions:
        return 0
    now = _now()
    rows = []
    for s in suggestions:
        if not s.get("title"):
            continue
        key = (s.get("key") or "").strip() or _suggestion_slug(s["title"])
        rows.append((_suggestion_id(key), key, s["title"], s.get("category", "arch"),
                     s.get("metric", ""), s.get("rationale", ""), s.get("impact", ""), now))
    with _conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM telemetry_suggestions").fetchone()[0]
        conn.executemany(
            """INSERT OR IGNORE INTO telemetry_suggestions
                 (id, issue_key, title, category, metric, rationale, impact, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
            rows,
        )
        after = conn.execute("SELECT COUNT(*) FROM telemetry_suggestions").fetchone()[0]
    return after - before


def get_suggestions(include_resolved: bool = False) -> list:
    """Advisory suggestions, newest first. Pending only by default; dismissed are
    always hidden, done shown only when include_resolved."""
    statuses = ("pending", "done") if include_resolved else ("pending",)
    placeholders = ",".join("?" * len(statuses))
    with _conn() as conn:
        rows = conn.execute(
            f"""SELECT id, issue_key, title, category, metric, rationale, impact, status, created_at
                FROM telemetry_suggestions WHERE status IN ({placeholders})
                ORDER BY created_at DESC""",
            statuses,
        ).fetchall()
    return [dict(r) for r in rows]


def set_suggestion_status(suggestion_id: str, status: str) -> bool:
    if status not in ("pending", "done", "dismissed"):
        return False
    with _conn() as conn:
        cur = conn.execute("UPDATE telemetry_suggestions SET status = ? WHERE id = ?",
                           (status, suggestion_id))
    return cur.rowcount > 0


def clear_suggestions() -> int:
    """Wipe all advisory suggestions — the re-baseline path after a dedup-key
    change leaves duplicate rows behind (analogous to delete_cve_iocs, ).
    Returns rows deleted."""
    with _conn() as conn:
        cur = conn.execute("DELETE FROM telemetry_suggestions")
    return cur.rowcount


# ── VirusTotal hash cache ───────────────────────────────────────────

def upsert_vt_result(file_hash: str, result: dict):
    """Cache a VT lookup so re-clicks never re-spend the 500/day quota.
    Only successful lookups (ok=True) are cached; errors are not."""
    file_hash = (file_hash or "").strip().lower()
    if not file_hash or not result.get("ok"):
        return
    with _conn() as conn:
        conn.execute(
            """INSERT INTO vt_results
                 (hash, in_vt, malicious, suspicious, total, reputation, name, link, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(hash) DO UPDATE SET
                 in_vt=excluded.in_vt, malicious=excluded.malicious,
                 suspicious=excluded.suspicious, total=excluded.total,
                 reputation=excluded.reputation, name=excluded.name,
                 link=excluded.link, checked_at=excluded.checked_at""",
            (file_hash, 1 if result.get("in_vt") else 0, result.get("malicious"),
             result.get("suspicious"), result.get("total"), result.get("reputation"),
             result.get("name"), result.get("link"), _now()),
        )


def get_vt_result(file_hash: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM vt_results WHERE hash = ?",
            ((file_hash or "").strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


# ── CISA KEV status ─────────────────────────────────────────────────

def get_war_room_cve_ids() -> list:
    """Distinct CVE IDs tracked in the War Room (relevant_to_infra conversations)."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT DISTINCT cve_id FROM conversations
               WHERE relevant_to_infra = 1 AND cve_id IS NOT NULL""",
        ).fetchall()
    return [r["cve_id"] for r in rows]


def upsert_kev_status(cve_id: str, entry: dict | None) -> bool:
    """Record a CVE's KEV status from a catalog lookup (entry, or None if not
    listed). Returns True if this poll detected a NEW listing (not-in-KEV → in-KEV),
    which leaves added_seen = 0 for the War Room delta badge."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return False
    now = _now()
    in_kev = 1 if entry else 0
    with _conn() as conn:
        prev = conn.execute(
            "SELECT in_kev FROM kev_status WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        newly_listed = in_kev == 1 and (prev is None or prev["in_kev"] == 0)
        # Preserve added_seen unless this is a fresh listing (then 0 = unseen).
        # Not-in-KEV rows are always 'seen' (nothing to flag).
        if newly_listed:
            added_seen = 0
        elif in_kev == 0:
            added_seen = 1
        else:
            added_seen = conn.execute(
                "SELECT added_seen FROM kev_status WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            added_seen = added_seen["added_seen"] if added_seen else 1
        e = entry or {}
        conn.execute(
            """INSERT INTO kev_status
                 (cve_id, in_kev, date_added, due_date, ransomware,
                  short_description, required_action, product, checked_at, added_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 in_kev=excluded.in_kev, date_added=excluded.date_added,
                 due_date=excluded.due_date, ransomware=excluded.ransomware,
                 short_description=excluded.short_description,
                 required_action=excluded.required_action, product=excluded.product,
                 checked_at=excluded.checked_at, added_seen=excluded.added_seen""",
            (cve_id, in_kev, e.get("date_added"), e.get("due_date"),
             e.get("ransomware"), e.get("short_description"), e.get("required_action"),
             e.get("product"), now, added_seen),
        )
    return newly_listed


def get_kev_status(cve_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM kev_status WHERE cve_id = ?",
            ((cve_id or "").strip().upper(),),
        ).fetchone()
    return dict(row) if row else None


def mark_kev_seen(cve_id: str):
    with _conn() as conn:
        conn.execute(
            "UPDATE kev_status SET added_seen = 1 WHERE cve_id = ?",
            ((cve_id or "").strip().upper(),),
        )


def get_iocs(cve_id: str) -> dict:
    """Return all persisted IOCs and sources for a CVE."""
    with _conn() as conn:
        ioc_rows = conn.execute(
            "SELECT id, type, value, context, reference, mitre_id FROM iocs WHERE cve_id = ? ORDER BY type, found_at",
            (cve_id,),
        ).fetchall()
        src_rows = conn.execute(
            "SELECT url, title FROM ioc_sources WHERE cve_id = ? ORDER BY found_at",
            (cve_id,),
        ).fetchall()
    return {
        "found":   bool(ioc_rows),
        "iocs":    [dict(r) for r in ioc_rows],
        "sources": [dict(r) for r in src_rows],
    }


# ── AUTH-1 — user + auth-code CRUD ───────────────────────────────────────────

def get_user_by_email(email: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?",
                           (email.strip().lower(),)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_user(user_id: str, username: str, email: str, pw_hash: str):
    with _conn() as conn:
        conn.execute(
            "INSERT INTO users (id, username, email, password_hash, verified, created_at) VALUES (?,?,?,?,0,?)",
            (user_id, username, email.strip().lower(), pw_hash, _now()),
        )
    logger.info("user created user_id=%s email=%s", user_id, email.strip().lower())


def set_user_verified(user_id: str):
    with _conn() as conn:
        conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user_id,))
    logger.info("user verified user_id=%s", user_id)


def update_user_password(user_id: str, pw_hash: str):
    with _conn() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    logger.info("password updated user_id=%s", user_id)


def create_auth_code(user_id: str, code_hash: str, purpose: str, expires_at: str):
    with _conn() as conn:
        conn.execute(
            "INSERT INTO auth_codes (user_id, code_hash, purpose, expires_at) VALUES (?,?,?,?)",
            (user_id, code_hash, purpose, expires_at),
        )


def get_auth_code(code_hash: str, purpose: str, user_id: str = None) -> dict | None:
    """Return a valid (unused, unexpired) auth code row, or None."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        if user_id:
            row = conn.execute(
                "SELECT * FROM auth_codes WHERE code_hash=? AND purpose=? AND user_id=? AND used=0 AND expires_at>?",
                (code_hash, purpose, user_id, now),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM auth_codes WHERE code_hash=? AND purpose=? AND used=0 AND expires_at>?",
                (code_hash, purpose, now),
            ).fetchone()
    return dict(row) if row else None


def mark_code_used(code_id: int):
    with _conn() as conn:
        conn.execute("UPDATE auth_codes SET used = 1 WHERE id = ?", (code_id,))


def invalidate_user_codes(user_id: str, purpose: str):
    """Mark all unused codes for this user+purpose as used before issuing a new one."""
    with _conn() as conn:
        conn.execute(
            "UPDATE auth_codes SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0",
            (user_id, purpose),
        )


# ── CVE retry queue ───────────────────────────────────────────────────────────
# Table is named nvd_retry_queue in SQLite (no migration needed); Python API is
# provider-agnostic. Swap the primary CVE source without touching the schema.

def queue_cve_retry(cve_id: str, conv_id: str, products_seeded: int = 0):
    """Queue a failed primary CVE lookup for background retry. INSERT OR IGNORE —
    a second /send call for the same CVE+conv never creates a duplicate row.

    products_seeded is a count of products already written (e.g. from EUVD fallback).
    The retry scheduler re-seeds products when CVE.org returns more than this count,
    catching partial seeding where EUVD had fewer CPE entries than CVE.org."""
    from datetime import timedelta
    next_retry = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    with _conn() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO nvd_retry_queue
               (cve_id, conv_id, attempts, next_retry_at, products_seeded, created_at)
               VALUES (?, ?, 0, ?, ?, ?)""",
            (cve_id.upper(), conv_id, next_retry, int(products_seeded), _now()),
        )
    logger.debug("CVE retry queued cve=%s conv=%s products_already=%d",
                 cve_id.upper(), conv_id[:8], int(products_seeded))


def get_due_cve_retries() -> list:
    """Return retry rows whose next_retry_at has passed, oldest first."""
    now = _now()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM nvd_retry_queue WHERE next_retry_at <= ? ORDER BY next_retry_at",
            (now,),
        ).fetchall()
    return [dict(r) for r in rows]


def advance_cve_retry(row_id: int, attempts: int, next_retry_at: str):
    """Increment attempt counter and set the next wake time after a failure."""
    with _conn() as conn:
        conn.execute(
            "UPDATE nvd_retry_queue SET attempts = ?, next_retry_at = ? WHERE id = ?",
            (attempts, next_retry_at, row_id),
        )


def complete_cve_retry(row_id: int):
    """Remove a retry row — either on success or after exhausting all attempts."""
    with _conn() as conn:
        conn.execute("DELETE FROM nvd_retry_queue WHERE id = ?", (row_id,))


def get_cve_retry_status(conv_id: str) -> dict | None:
    """Return the retry row for a conversation, or None if no retry is queued."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT attempts, next_retry_at, products_seeded FROM nvd_retry_queue WHERE conv_id = ?",
            (conv_id,),
        ).fetchone()
    return dict(row) if row else None


def get_conv_id_for_cve(cve_id: str) -> str | None:
    """Return any conv_id associated with this CVE, for use when storing metadata
    outside of a request context (e.g. the CVSS recheck endpoint)."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT id FROM conversations WHERE cve_id = ? ORDER BY updated_at DESC LIMIT 1",
            (cve_id.upper(),),
        ).fetchone()
    return row["id"] if row else None


# Backward-compat aliases
queue_nvd_retry    = queue_cve_retry
get_due_nvd_retries  = get_due_cve_retries
advance_nvd_retry  = advance_cve_retry
complete_nvd_retry = complete_cve_retry
get_nvd_retry_status = get_cve_retry_status


def seed_admin_user(user_id: str, username: str, email: str, pw_hash: str):
    """Create the initial admin user if they don't exist. Pre-verified.
    Assigns any user_id-less conversations to them so existing history is preserved."""
    with _conn() as conn:
        exists = conn.execute("SELECT id FROM users WHERE email = ?",
                              (email.lower(),)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO users (id, username, email, password_hash, verified, created_at) VALUES (?,?,?,?,1,?)",
                (user_id, username, email.lower(), pw_hash, _now()),
            )
        # Assign any orphaned conversations (pre-auth rows) to this user
        conn.execute(
            "UPDATE conversations SET user_id = ? WHERE user_id IS NULL",
            (user_id,),
        )


