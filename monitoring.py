"""Phase G — CVE/package news monitoring.

Due-based scheduling, not cron: a monitor is due when
    last_polled_at + cadence_hours <= now (or never polled).
The scheduler daemon thread checks every SCHEDULER_INTERVAL seconds and polls
whatever is due. If the server was offline past a monitor's due time, the
monitor is simply due at next startup — one date-filtered search covers the
whole gap, so nothing is missed and there is no catch-up storm.

search_news is NOT an agent tool — only this module and the War Room
"Check now" route call it (decided 2026-06-11; same pattern as search_iocs).
"""
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import db

logger = logging.getLogger(__name__)
import kev
import learning
import obs
import news
from tools import search_news

SCHEDULER_INTERVAL = 60          # seconds between due-checks
KEV_CADENCE_HOURS = 24           # one catalog sweep per day serves all War Room CVEs
FIRST_POLL_LOOKBACK_DAYS = 30    # window when a monitor has never been polled
OVERLAP_DAYS = 2                 # re-cover recent days (publish-date lag); URL dedup absorbs it
FAILURE_BACKOFF_MINUTES = 15     # retry delay after a failed poll (in-memory)
RESULTS_PER_POLL = 5             # user decision 2026-06-12. No cost effect (Exa
                                 # prices 1-25 results as one request) — purely
                                 # less filler per poll reaching the post-filter.

# entity_type → Exa query template. Probe v3 (2026-06-12): natural-language
# phrasing beats keyword-soup (4/10 vs 2/10 on-topic), ties bare ID on ratio but
# returns reporting rather than CVE-database pages, and generalises to package
# names. Package template untested (no package monitors yet — probe when built).
_QUERY_TEMPLATES = {
    "cve":     "Latest developments on {entity_id}",
    "package": "Latest developments on the {entity_id} software package",
}

_failures: dict[str, float] = {}   # monitor_id → unix ts before which we won't retry
_scheduler_started = False
_scheduler_lock = threading.Lock()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _is_due(monitor: dict, now: datetime | None = None) -> bool:
    now = now or _now_dt()
    if not monitor.get("enabled"):
        return False
    last = monitor.get("last_polled_at")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except ValueError:
        return True
    return last_dt + timedelta(hours=monitor["cadence_hours"]) <= now


def _start_date(monitor: dict) -> str:
    """startPublishedDate for the search: last poll minus overlap, or the
    first-poll lookback. An offline gap widens the window automatically."""
    last = monitor.get("last_polled_at")
    if last:
        try:
            start = datetime.fromisoformat(last) - timedelta(days=OVERLAP_DAYS)
        except ValueError:
            start = _now_dt() - timedelta(days=FIRST_POLL_LOOKBACK_DAYS)
    else:
        start = _now_dt() - timedelta(days=FIRST_POLL_LOOKBACK_DAYS)
    return start.strftime("%Y-%m-%d")


def _mention_re(entity_id: str) -> re.Pattern:
    """Boundary-aware mention matcher. Plain substring is NOT enough: probe v2
    showed Exa returning CVE-2025-57790 for CVE-2025-5777 — and '...5777' is a
    substring of '...57790'. Require no alphanumeric before the match and no
    DIGIT after it (a trailing letter/punct is fine: 'CVE-2025-5777,' matches,
    'CVE-2025-57790' does not)."""
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(entity_id.lower()) + r"(?!\d)")


def _filter_results(monitor: dict, results: list, start_date: str) -> list:
    """Hard relevance + date guard over raw Exa results (G5 probes, 2026-06-12):
    Exa search pads with articles about OTHER (sometimes lookalike) CVEs when no
    fresh news exists, and startPublishedDate leaks pre-window items. Keep a
    result only if (a) title or snippet mentions the monitored entity at a word
    boundary, and (b) its published date, when present, is inside the window.
    An empty list after filtering is the CORRECT outcome for a quiet week."""
    needle = _mention_re(monitor["entity_id"])
    kept = []
    for r in results:
        text = f"{r.get('title', '')} {r.get('snippet', '')}".lower()
        if not needle.search(text):
            continue
        pub = r.get("published_date") or ""
        if pub and pub < start_date:
            continue
        kept.append({**r, "snippet": (r.get("snippet") or "")[:400]})
    return kept


def poll_monitor(monitor: dict) -> dict:
    """Run one poll: dated news search → relevance/date post-filter → persist
    new items (URL-deduped) → stamp last_polled_at. Returns {ok, new_count, error?}."""
    template = _QUERY_TEMPLATES.get(monitor["entity_type"], "{entity_id}")
    query = template.format(entity_id=monitor["entity_id"])
    start_date = _start_date(monitor)

    raw = search_news(query, start_published_date=start_date,
                      num_results=RESULTS_PER_POLL)
    if not raw.get("found") and raw.get("error"):
        _failures[monitor["id"]] = time.time() + FAILURE_BACKOFF_MINUTES * 60
        return {"ok": False, "new_count": 0, "error": raw["error"]}

    kept = _filter_results(monitor, raw.get("results", []), start_date)
    new_count = db.upsert_monitor_news(
        monitor["entity_type"], monitor["entity_id"], kept
    )
    db.set_monitor_polled(monitor["id"])
    _failures.pop(monitor["id"], None)
    return {"ok": True, "new_count": new_count}


def poll_kev(monitor: dict | None = None) -> dict:
    """Sweep all War Room CVEs against the CISA KEV catalog. ONE
    catalog fetch (cached) serves every CVE. Records each CVE's status and flags
    not-in-KEV → in-KEV transitions for the War Room delta badge. Stamps the
    sentinel monitor's last_polled_at when invoked by the scheduler."""
    cve_ids = db.get_war_room_cve_ids()
    if not cve_ids:
        if monitor:
            db.set_monitor_polled(monitor["id"])
        return {"ok": True, "checked": 0, "newly_listed": 0}

    catalog = kev.fetch_kev_catalog()   # raises on failure → caller backs off
    newly = 0
    for cve_id in cve_ids:
        if db.upsert_kev_status(cve_id, kev.lookup(cve_id, catalog)):
            newly += 1
    if monitor:
        db.set_monitor_polled(monitor["id"])
        _failures.pop(monitor["id"], None)
    return {"ok": True, "checked": len(cve_ids), "newly_listed": newly}


def ensure_kev_status(cve_id: str) -> bool:
    """Populate KEV status for ONE CVE if it has never been checked — called when
    a CVE first enters the War Room so its KEV badge appears immediately, without
    waiting for the daily sweep. Cheap and self-throttling: the catalog is cached
    in-process, and an existing row short-circuits the lookup. Returns True if a
    lookup was performed. Never raises (network failure just defers to the sweep)."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id or db.get_kev_status(cve_id) is not None:
        return False
    try:
        db.upsert_kev_status(cve_id, kev.lookup(cve_id))
        return True
    except Exception as e:
        logger.warning("kev on-add lookup failed for %s: %s", cve_id, e)
        return False


def poll_due_monitors() -> int:
    """Poll every enabled monitor that is due (and not in failure backoff).
    Returns the number of monitors polled. Dispatches by entity_type — the
    sentinel 'kev' monitor runs the catalog sweep, everything else news."""
    now = _now_dt()
    polled = 0
    for monitor in db.get_enabled_monitors():
        if not _is_due(monitor, now):
            continue
        if _failures.get(monitor["id"], 0) > time.time():
            continue
        try:
            if monitor["entity_type"] == "kev":
                poll_kev(monitor)
            elif monitor["entity_type"] == "feeds":
                news.poll_feeds(monitor)   # NB daily blog/news fetch
            elif monitor["entity_type"] == "learning":
                learning.analyze_conversations(monitor)  # NB6 daily tutor pass
            elif monitor["entity_type"] == "telemetry":
                obs.run_advisory(monitor)                 # OBS3 2×/day advisory
            else:
                poll_monitor(monitor)
            polled += 1
        except Exception as e:
            logger.error("monitor poll failed for %s: %s", monitor["entity_id"], e)
            _failures[monitor["id"]] = time.time() + FAILURE_BACKOFF_MINUTES * 60
    return polled


# Retry backoff: after attempt N fails, wait this many seconds before attempt N+1.
_NVD_RETRY_DELAYS = [60, 300]   # attempt 0→1: 1 min; attempt 1→2: 5 min; then give up


def process_cve_retry_queue():
    """Drain rows from the CVE retry queue whose next_retry_at has passed.
    On success: updates War Room, fills infra if not already seeded, deletes row.
    On failure: increments attempts + reschedules; gives up after 3 total attempts.
    Called from the scheduler loop every SCHEDULER_INTERVAL seconds.
    Provider-agnostic: swapping the primary CVE source only requires changing
    _fetch_primary_cve() below — the retry/infra logic is unchanged."""

    rows = db.get_due_cve_retries()
    for row in rows:
        cve_id          = row["cve_id"]
        conv_id         = row["conv_id"]
        attempts        = row["attempts"]
        # products_seeded is now a count (not a bool) — how many products EUVD
        # already wrote. Re-seed if CVE.org returns more, catching partial seeding.
        products_already = int(row["products_seeded"])

        try:
            result = _fetch_primary_cve(cve_id)
            score, severity, version = None, None, None
            _ver_map = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = result.get(key)
                if m and m != "N/A":
                    score    = m.get("baseScore")
                    severity = m.get("baseSeverity")
                    if score and score != "N/A":
                        version = _ver_map[key]
                        break
            # force=True: primary source is authoritative — overwrite any EUVD
            # placeholder that COALESCE would otherwise silently protect.
            db.store_cve_metadata(conv_id, result.get("id", cve_id), score, severity,
                                  version, force=True)

            products = result.get("products") or []
            # Always re-seed — upsert_product is idempotent so duplicates are
            # harmless, and EUVD and CVE.org may return the same count but
            # different products. products_already is kept for logging only.
            if products:
                logger.debug("CVE retry %s: seeding %d products (euvd_had=%d)",
                             cve_id, len(products), products_already)
                for p in products:
                    vendor_name  = (p.get("vendor") or "").strip()
                    product_name = (p.get("product") or "").strip()
                    vendor = vendor_name or product_name
                    if not vendor:
                        continue
                    vendor_id = db.upsert_vendor(vendor)
                    if product_name and vendor_name:
                        db.upsert_product(vendor_id, product_name, p.get("category", "application"), conv_id)

            db.set_relevant_to_infra(conv_id, True)
            ensure_kev_status(cve_id)
            # Fetch EPSS so the War Room card is fully populated. CVEs entering
            # via the retry queue (package scans, failed /send) skip the LLM
            # tool call that normally fetches EPSS inline.
            try:
                from tools import query_epss
                epss_data = query_epss(cve_id)
                epss_items = epss_data.get("results", [])
                if epss_items:
                    ei = epss_items[0]
                    db.store_epss(cve_id, ei["epss_score"], ei["percentile"])
                    logger.debug("CVE retry EPSS ✓ %s score=%.4f", cve_id, ei["epss_score"])
            except Exception as epss_exc:
                logger.debug("CVE retry EPSS ✗ %s: %s", cve_id, epss_exc)
            db.complete_cve_retry(row["id"])
            logger.info("CVE retry ✓ %s attempt=%d score=%s severity=%s ver=%s",
                        cve_id, attempts + 1, score, severity, version)

        except Exception as exc:
            new_attempts = attempts + 1
            if new_attempts >= 3:
                db.complete_cve_retry(row["id"])
                logger.error("CVE retry ✗ gave up on %s after %d attempts: %s",
                             cve_id, new_attempts, exc)
            else:
                delay = _NVD_RETRY_DELAYS[new_attempts - 1] if new_attempts <= len(_NVD_RETRY_DELAYS) else 300
                next_retry = (_now_dt() + timedelta(seconds=delay)).isoformat()
                db.advance_cve_retry(row["id"], new_attempts, next_retry)
                logger.warning("CVE retry ✗ attempt %d for %s failed (retry in %ds): %s",
                               new_attempts, cve_id, delay, exc)


# ── Primary CVE provider ───────────────────────────────────────────────────────
# Single swap point: replace this function to change the primary CVE data source.
# Must return a dict with the same shape as parse_nvd_cve():
#   id, cvssMetricV40/V31/V30/V2 (each with baseScore/baseSeverity), products list.
def _fetch_primary_cve(cve_id: str) -> dict:
    from sources.cveorg_primary import fetch_cveorg_primary
    return fetch_cveorg_primary(cve_id)


def _scheduler_loop():
    while True:
        try:
            poll_due_monitors()
            process_cve_retry_queue()
        except Exception as e:
            logger.error("scheduler iteration failed: %s", e)
        time.sleep(SCHEDULER_INTERVAL)


def ensure_scheduler():
    """Start the daemon scheduler thread exactly once. Called from a
    before_request hook — the Werkzeug reloader parent never serves requests,
    so this avoids the double-start that module-level startup would cause."""
    global _scheduler_started
    if _scheduler_started:
        return
    with _scheduler_lock:
        if _scheduler_started:
            return
        # Sentinel monitor drives the daily KEV catalog sweep through the same
        # due-based loop (one row, entity_type 'kev'); idempotent.
        try:
            db.upsert_monitor("kev", "catalog", enabled=True,
                              cadence_hours=KEV_CADENCE_HOURS)
            # NB daily feed fetch — same due-based sentinel pattern.
            db.upsert_monitor("feeds", "all", enabled=True,
                              cadence_hours=news.FEEDS_CADENCE_HOURS)
            # NB6 daily learning-recommendation pass.
            db.upsert_monitor("learning", "all", enabled=True,
                              cadence_hours=learning.LEARNING_CADENCE_HOURS)
            # OBS3 twice-daily self-observability advisory.
            db.upsert_monitor("telemetry", "advisor", enabled=True,
                              cadence_hours=obs.OBS_CADENCE_HOURS)
        except Exception as e:
            logger.error("could not ensure sentinel monitors: %s", e)
        threading.Thread(target=_scheduler_loop, daemon=True,
                         name="monitor-scheduler").start()
        _scheduler_started = True
        logger.info("scheduler started (interval=%ds)", SCHEDULER_INTERVAL)
