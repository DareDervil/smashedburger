"""NB — news/blog watch fetcher.

WP1 substrate (NB1/NB2/NB5): pull the curated source list, normalise every feed
to one item shape, and hand the batch to db.replace_news_items for the ephemeral
News dashboard. Two fetch mechanisms behind one interface (hybrid, decided
2026-06-12 after web_fetch probing):

  - kind 'rss'  → feedparser. It transparently normalises RSS 2.0 (Snyk),
                  Atom (Socket) AND JSON Feed, so a single code path handles all
                  three rather than three hand-rolled parsers.
  - kind 'exa'  → tools.search_news with includeDomains pinned to the blog's
                  own domain (HeroDevs is Webflow with no published feed).

Like kev.py / search_news, this is NOT an agent tool — only the News routes and
the daily 'feeds' scheduler sentinel call it. Sonnet never fetches blogs.

Sandbox note: the feed hosts (snyk.io, socket.dev, ...) are blocked by the dev
proxy, so this is fixture-tested offline and the user runs it live (same
workflow as every other external source in this project).
"""
import logging
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin, urlparse

import feedparser
import requests

import db
from tools import search_news

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = 15            # seconds per feed HTTP fetch
PER_FEED_CAP = 15             # items kept per source before the global cap
EXA_LOOKBACK_DAYS = 90        # recency window for the Exa fallback (a watcher,
                              # not the evergreen NB6 learning search)
DEFAULT_LIMIT = 20            # NB1 default list size; user-adjustable
FEEDS_CADENCE_HOURS = 24      # one daily fetch

_UA = {"User-Agent": "smashedburger-newswatch/0.4 (+local)"}

# rel=alternate feed types, and common probe paths for the discovery helper.
_FEED_TYPES = ("application/rss+xml", "application/atom+xml", "application/feed+json",
               "application/json")
_PROBE_PATHS = ("/feed/", "/feed", "/rss.xml", "/feed.atom", "/atom.xml", "/feed.json")


def _iso_date(entry) -> str:
    """Normalise a feedparser entry's date to YYYY-MM-DD (sortable, matches
    monitor_news.published_date). Falls back to '' when the feed omits a date."""
    for attr in ("published_parsed", "updated_parsed"):
        st = getattr(entry, attr, None) or (entry.get(attr) if hasattr(entry, "get") else None)
        if st:
            try:
                return time.strftime("%Y-%m-%d", st)
            except Exception:
                pass
    raw = (entry.get("published") or entry.get("updated") or "") if hasattr(entry, "get") else ""
    return raw[:10]


def _clean_summary(entry) -> str:
    """Strip HTML tags from the entry summary and trim. feedparser already
    decodes entities; we only need to drop markup and cap length."""
    import re
    raw = ""
    if hasattr(entry, "get"):
        raw = entry.get("summary") or (entry.get("content", [{}])[0].get("value", "")
                                       if entry.get("content") else "")
    text = re.sub(r"<[^>]+>", "", raw or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400]


def parse_feed_bytes(content: bytes, source: str) -> list:
    """Parse raw feed bytes (RSS/Atom/JSON) into normalised items. Separated
    from the network fetch so tests can drive it with fixtures offline.

    feedparser handles RSS 2.0 + Atom natively but its JSON Feed sniffing is
    unreliable when content-type isn't supplied, so JSON Feed gets an explicit
    fallback — that keeps the 'one parser, three formats' contract the NB plan
    requires without a second dependency."""
    parsed = feedparser.parse(content)
    if not parsed.entries:
        jf = _parse_json_feed(content, source)
        if jf:
            return jf
    items = []
    for e in parsed.entries[:PER_FEED_CAP]:
        link = (e.get("link") or "").strip() if hasattr(e, "get") else ""
        if not link:
            continue
        items.append({
            "source":    source,
            "url":       link,
            "title":     (e.get("title") or "").strip(),
            "published": _iso_date(e),
            "summary":   _clean_summary(e),
        })
    return items


def _parse_json_feed(content: bytes, source: str) -> list:
    """Minimal JSON Feed 1.x reader (jsonfeed.org). Returns [] if the bytes
    aren't a JSON Feed, so the caller can fall through harmlessly."""
    import json as _json, re
    try:
        data = _json.loads(content)
    except Exception:
        return []
    if not isinstance(data, dict) or "items" not in data:
        return []
    out = []
    for it in data.get("items", [])[:PER_FEED_CAP]:
        url = (it.get("url") or it.get("external_url") or "").strip()
        if not url:
            continue
        summary = it.get("summary") or it.get("content_text") or ""
        if not summary and it.get("content_html"):
            summary = re.sub(r"<[^>]+>", "", it["content_html"])
        out.append({
            "source":    source,
            "url":       url,
            "title":     (it.get("title") or "").strip(),
            "published": (it.get("date_published") or it.get("date_modified") or "")[:10],
            "summary":   re.sub(r"\s+", " ", summary).strip()[:400],
        })
    return out


def fetch_feed(feed: dict) -> list:
    """Fetch and parse one rss-kind feed. Returns [] on any failure (a dead
    feed must not break the whole refresh)."""
    feed_url = feed.get("feed_url") or feed.get("url")
    if not feed_url:
        return []
    try:
        resp = requests.get(feed_url, headers=_UA, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        logger.warning("news feed fetch failed for %s: %s", feed.get("name"), e)
        return []
    return parse_feed_bytes(resp.content, feed.get("name") or feed_url)


def fetch_exa_feed(feed: dict, limit: int = PER_FEED_CAP) -> list:
    """Exa fallback for feed-less blogs (HeroDevs). Restrict to the blog's
    domain and bound recency — this is a watcher, so fresh posts only."""
    domain = urlparse(feed.get("url") or "").netloc.lstrip("www.")
    if not domain:
        return []
    start = (datetime.now(timezone.utc) - timedelta(days=EXA_LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    raw = search_news(
        f"Latest posts from the {feed.get('name')} security blog",
        start_published_date=start, num_results=limit,
        include_domains=[domain],
    )
    out = []
    for r in raw.get("results", []):
        if not r.get("url"):
            continue
        out.append({
            "source":    feed.get("name"),
            "url":       r["url"],
            "title":     r.get("title", ""),
            "published": (r.get("published_date") or "")[:10],
            "summary":   (r.get("snippet") or "")[:400],
        })
    return out


def discover_feed(site_url: str) -> dict:
    """Feed-discovery helper (NB5): given a blog homepage, find its feed.
    Strategy: (1) parse <link rel="alternate" type="...rss/atom/json..."> from
    the HTML head; (2) probe common feed paths; (3) give up → kind 'exa'.
    Returns {kind: 'rss'|'exa', feed_url: str|None}."""
    try:
        resp = requests.get(site_url, headers=_UA, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        logger.warning("news discovery fetch failed for %s: %s", site_url, e)
        html = ""

    found = _discover_in_html(html, site_url)
    if found:
        return {"kind": "rss", "feed_url": found}

    base = f"{urlparse(site_url).scheme}://{urlparse(site_url).netloc}"
    for path in _PROBE_PATHS:
        candidate = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.get(candidate, headers=_UA, timeout=FETCH_TIMEOUT)
            if r.ok and feedparser.parse(r.content).entries:
                return {"kind": "rss", "feed_url": candidate}
        except Exception:
            continue
    return {"kind": "exa", "feed_url": None}


def _discover_in_html(html: str, base_url: str) -> str | None:
    """Pull the first rel=alternate feed link out of an HTML head. Regex (not a
    DOM parser) keeps the dependency surface small; feed <link> tags are simple
    and well-formed in practice."""
    import re
    for m in re.finditer(r"<link\b[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        if "alternate" not in tag.lower():
            continue
        if not any(t in tag.lower() for t in _FEED_TYPES):
            continue
        href = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if href:
            return urljoin(base_url, href.group(1))
    return None


def fetch_all_feeds(limit: int = DEFAULT_LIMIT) -> list:
    """Pull every enabled feed, dedup by URL, sort newest-first, cap to `limit`.
    One dead feed contributes nothing but never aborts the batch."""
    items: list = []
    for feed in db.get_feeds(enabled_only=True):
        if feed.get("kind") == "exa":
            items.extend(fetch_exa_feed(feed))
        else:
            items.extend(fetch_feed(feed))

    seen: set = set()
    deduped: list = []
    for it in items:
        u = (it.get("url") or "").lower()
        if not u or u in seen:
            continue
        seen.add(u)
        deduped.append(it)

    deduped.sort(key=lambda i: i.get("published") or "", reverse=True)
    return deduped[:limit]


def poll_feeds(monitor: dict | None = None, limit: int = DEFAULT_LIMIT) -> dict:
    """Scheduler/ad-hoc entry point: fetch everything → replace the ephemeral
    list (bookmarks preserved) → stamp the sentinel's last_polled_at. Mirrors
    monitoring.poll_monitor's contract: {ok, new_count, error?}."""
    try:
        items = fetch_all_feeds(limit)
    except Exception as e:
        logger.error("news poll_feeds failed: %s", e)
        return {"ok": False, "new_count": 0, "error": str(e)}
    new_count = db.replace_news_items(items)
    if monitor:
        db.set_monitor_polled(monitor["id"])
    return {"ok": True, "new_count": new_count, "total": len(items)}
