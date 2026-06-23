"""parse_nvd_cve — Primary CVE lookup (now backed by CVE.org, not NVD).
The tool name is kept as parse_nvd_cve so the system prompt and Sonnet's
tool-calling behaviour are unchanged — the name is just an identifier.
Internally calls fetch_cveorg_primary() which hits the MITRE CVE.org API.

Why CVE.org over NVD?
- CVEs arrive here first; NVD is downstream and often lags days on new CVEs.
- No API key or per-IP rate limit (NVD requires a key for reliable throughput).
- Same data shape — CVSS scores come from the NVD ADP container inside the
  CVE.org record, so scores are identical once NVD processes the entry.

Side effects are unchanged: stamps ctx.cve_store, ctx.current_cve_id, and
warms the prefetch cache for supplementary sources (EUVD, Exploit-DB) via
gevent greenlets."""
import logging
import gevent
import db
import context as ctx
from sources.cveorg_primary import fetch_cveorg_primary

logger = logging.getLogger(__name__)

NAME  = "parse_nvd_cve"
ORDER = 10

TOOL_DEF = {
    "name": NAME,
    "description": "Query the NVD (National Vulnerability Database) API for a given CVE ID. "
    "Returns a cleaned summary including: CVE ID, published and last-modified dates, "
    "vulnerability status, and English description. For each available CVSS version "
    "(v2, v3.0, v3.1, v4.0) returns the base score, severity rating, raw vector string, "
    "and a human-readable breakdown of every CVSS metric (e.g. Attack Vector: Network, "
    "Privileges Required: None). Also includes CISA exploit data when present (exploit "
    "add date, required action, vulnerability name), and a references list of vendor "
    "advisory and patch URLs. Use the references to find input URLs for the vendor "
    "advisory tools: fortiguard.fortinet.com/psirt/FG-IR-... for fetch_fortinet_advisory, "
    "support.citrix.com URLs containing a CTX ID for fetch_citrix_advisory, and "
    "support.broadcom.com URLs containing 'SecurityAdvisories' for "
    "fetch_broadcom_advisory. Use this whenever the user asks about a specific CVE "
    "or vulnerability by ID.",
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE-ID to query, e.g. 'CVE-2021-44228'",
            }
        },
        "required": ["cve_id"],
    },
    "input_examples": [{"cve_id": "CVE-2021-44228"}],
}

PROMPT = (
    "- **parse_nvd_cve** — Call this whenever the user mentions a CVE ID. Returns CVSS scores, "
    "severity, description, and CISA KEV status."
)


def _spawn_prefetch(cve_id: str):
    """Fire-and-forget gevent greenlets that warm the prefetch cache for the
    three supplementary CVE sources, so Sonnet's later sequential tool calls
    return from cache instead of waiting on the network.

    Uses gevent.spawn (NOT threading.Thread): greenlets run cooperatively ON
    the gevent hub and overlap with Sonnet's API round-trips. Native threads
    doing blocking SSL here would stall the hub and get the gunicorn worker
    SIGKILLed — that bug shipped once and was reverted (see PROGRESS.md).

    Degrades safely with no hub (Flask dev server): the greenlets simply never
    get scheduled, every lookup misses, and each tool does a live fetch."""
    cache = getattr(ctx.prefetch_cache, "cache", None)
    if cache is None or not cve_id:
        return
    # Lazy imports avoid circular-import issues at module load time
    from sources.euvd      import _fetch_raw as _euvd_raw
    from sources.cveorg    import _fetch_raw as _cveorg_raw
    from sources.exploitdb import _fetch_raw as _exploitdb_raw
    key_cve = cve_id.upper()

    def _run(source, fn):
        try:
            raw = fn(cve_id)
            if raw is not None:
                cache[f"{source}:{key_cve}"] = raw
        except Exception:
            pass

    for source, fn in (("euvd", _euvd_raw), ("cveorg", _cveorg_raw), ("exploitdb", _exploitdb_raw)):
        gevent.spawn(_run, source, fn)


def fetch(cve_id: str) -> dict:
    try:
        result = fetch_cveorg_primary(cve_id)
    except Exception as exc:
        # CVE.org failed (timeout, not yet published) — queue background retry
        logger.warning("CVE.org fetch failed for %s: %s — queuing retry", cve_id, exc)
        ctx.cve_retry.cve_id = cve_id
        ctx.current_cve_id.value = cve_id   # still stamp so EUVD/actions tag correctly
        _spawn_prefetch(cve_id)             # warm siblings even when CVE.org fails
        return {"found": False, "error": str(exc), "cve_id": cve_id, "source": "nvd"}

    logger.info("CVE.org ✓ %s status=%s", result.get("id", cve_id), result.get("vulnStatus", "?"))
    ctx.current_cve_id.value = result.get("id", cve_id)   # stamp CVE for action tagging
    ctx.cve_store.result = result   # picked up in /send for auto-infra extraction
    _spawn_prefetch(ctx.current_cve_id.value)

    # Store CVE metadata for the War Room (first CVE per conversation wins)
    conv_id = getattr(ctx.current_conv, "conv_id", "")
    if conv_id:
        score, severity, version = None, None, None
        _ver_map = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}
        vector = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = result.get(key)
            if m and m != "N/A":
                score    = m.get("baseScore")
                severity = m.get("baseSeverity")
                if score and score != "N/A":
                    version = _ver_map[key]
                    vector  = m.get("vectorString")
                    break
        db.store_cve_metadata(conv_id, result.get("id", cve_id), score, severity, version,
                              cvss_vector=vector)

    return result


def extract_links(result: dict) -> list:
    links = []
    cve_id = result.get("id", "")
    if cve_id:
        links.append({
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": "nvd", "type": "reference",
            "title": cve_id, "description": "NVD Entry",
        })
    if result.get("cisaExploitAdd") not in (None, "N/A"):
        links.append({
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source": "cisa", "type": "reference",
            "title": "CISA KEV",
            "description": result.get("cisaVulnerabilityName", "Known Exploited Vulnerability"),
        })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions = []
    required_action = result.get("cisaRequiredAction")
    if required_action and required_action != "N/A":
        text = f"CISA required action: {required_action}"
        actions.append({"text": text, "source": "cisa", "type": "mitigation"})
    return actions, []
