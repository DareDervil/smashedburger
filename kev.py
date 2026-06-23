"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The whole catalog is ONE structured JSON file (~1300 entries, no key, no JS), so
a single fetch serves every tracked CVE — unlike the per-entity Exa news search.
An in-process TTL cache means a daily sweep over N War Room CVEs costs one
download, not N. The catalog also carries `knownRansomwareCampaignUse` and a
remediation `dueDate`, so "is this in KEV", "ransomware?", and "patch deadline"
all come from the same row.

NOT an agent tool — only the monitor scheduler and the /kev routes call this,
same pattern as search_news / search_iocs.
"""
import logging
import threading
import time

import requests

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 6 * 3600     # refetch the catalog at most every 6h
_TIMEOUT = 30

_cache: dict = {"by_cve": None, "fetched_at": 0.0, "catalog_version": None}
_lock = threading.Lock()


def _normalise(entry: dict) -> dict:
    """One KEV catalog row → the fields we surface. Ransomware flag normalised to
    a clean 'Known' / 'Unknown'."""
    ransom = (entry.get("knownRansomwareCampaignUse") or "Unknown").strip()
    vendor = (entry.get("vendorProject") or "").strip()
    product = (entry.get("product") or "").strip()
    return {
        "date_added":        entry.get("dateAdded", ""),
        "due_date":          entry.get("dueDate", ""),
        "ransomware":        "Known" if ransom.lower() == "known" else "Unknown",
        "short_description": (entry.get("shortDescription") or "").strip(),
        "required_action":   (entry.get("requiredAction") or "").strip(),
        "product":           " ".join(p for p in (vendor, product) if p),
        "name":              (entry.get("vulnerabilityName") or "").strip(),
    }


def fetch_kev_catalog(force: bool = False) -> dict:
    """Return {CVE-ID(upper): normalised entry}. Cached for CACHE_TTL_SECONDS.
    Raises on network/parse failure (callers handle it)."""
    now = time.time()
    with _lock:
        if (not force and _cache["by_cve"] is not None
                and now - _cache["fetched_at"] < CACHE_TTL_SECONDS):
            return _cache["by_cve"]

    resp = requests.get(KEV_URL, timeout=_TIMEOUT,
                        headers={"Accept": "application/json"})
    resp.raise_for_status()
    data = resp.json()
    by_cve = {
        (v.get("cveID") or "").strip().upper(): _normalise(v)
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }
    with _lock:
        _cache.update(by_cve=by_cve, fetched_at=now,
                      catalog_version=data.get("catalogVersion"))
    return by_cve


def lookup(cve_id: str, catalog: dict | None = None) -> dict | None:
    """KEV entry for a CVE, or None if not listed. Pass a pre-fetched catalog to
    avoid re-fetching inside a sweep."""
    cat = catalog if catalog is not None else fetch_kev_catalog()
    return cat.get((cve_id or "").strip().upper())
