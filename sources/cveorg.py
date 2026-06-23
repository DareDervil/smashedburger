"""fetch_cveorg — CVE.org (MITRE) authoritative record lookup.
Extracts CNA attribution and CWE root-cause classification. ORDER=12.
No CVSS scores — that is NVD's domain. This fills the description/CWE/CNA
gap that NVD leaves on new CVEs still marked 'Awaiting Analysis'."""
import logging
import requests as _requests
import db
import context as ctx

logger = logging.getLogger(__name__)

NAME  = "fetch_cveorg"
ORDER = 12

_BASE    = "https://cveawg.mitre.org/api/cve"
_TIMEOUT = 8

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Query the CVE.org API (MITRE CVE Program) for the authoritative CVE record. "
        "Returns the CNA (CVE Numbering Authority — the organization that published the CVE), "
        "the CWE root-cause classification (e.g. CWE-79 XSS, CWE-502 Deserialization), "
        "and the authoritative English description. "
        "Call this after parse_nvd_cve. Include the CNA name and CWE classification in "
        "your briefing — the CNA identifies whether disclosure came from the vendor or an "
        "independent researcher, and the CWE anchors the root cause for remediation guidance."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE ID to look up, e.g. 'CVE-2021-44228'",
            }
        },
        "required": ["cve_id"],
    },
    "input_examples": [{"cve_id": "CVE-2021-44228"}],
}

PROMPT = (
    "- **fetch_cveorg** — Call after parse_nvd_cve. Returns CNA (disclosing org) "
    "and CWE root cause. Include both in your briefing."
)


def _fetch_raw(cve_id: str) -> dict | None:
    """Pure HTTP fetch — no ctx/db side effects. Used by NVD pre-fetch spawner."""
    try:
        resp = _requests.get(f"{_BASE}/{cve_id}", timeout=_TIMEOUT)
        if resp.status_code != 200:
            if resp.status_code in (429, 503):
                logger.warning("CVE.org (MITRE) %s for %s — skipping", resp.status_code, cve_id)
            else:
                logger.debug("CVE.org (MITRE) non-200 %s for %s", resp.status_code, cve_id)
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception as exc:
        logger.debug("CVE.org (MITRE) fetch error for %s: %s", cve_id, exc)
        return None


def fetch(cve_id: str) -> dict:
    data = ctx.get_prefetch("cveorg", cve_id) or _fetch_raw(cve_id)
    if not data:
        return {"found": False, "cve_id": cve_id, "source": "cveorg"}

    meta          = data.get("cveMetadata") or {}
    cna_container = (data.get("containers") or {}).get("cna") or {}

    # CNA name: assignerShortName from metadata is the most reliable
    cna_name = (
        meta.get("assignerShortName")
        or (cna_container.get("providerMetadata") or {}).get("shortName")
        or (cna_container.get("providerMetadata") or {}).get("orgId")
    )

    # CWE: first CWE-typed entry in problemTypes
    cwe_id, cwe_desc = None, None
    for pt in (cna_container.get("problemTypes") or []):
        for d in (pt.get("descriptions") or []):
            if d.get("type", "").upper() == "CWE" and d.get("cweId"):
                cwe_id   = d["cweId"]
                cwe_desc = d.get("description", "")
                break
        if cwe_id:
            break

    # Authoritative English description (fallback when NVD is thin)
    description = None
    for d in (cna_container.get("descriptions") or []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value")
            break

    conv_id = getattr(ctx.current_conv, "conv_id", "")
    if conv_id:
        db.store_cveorg_data(conv_id, cna_name, cwe_id, description)

    return {
        "found":          True,
        "cve_id":         cve_id,
        "source":         "cveorg",
        "cna":            cna_name,
        "cwe_id":         cwe_id,
        "cwe_desc":       cwe_desc,
        "description":    description,
        "state":          meta.get("state"),
        "date_published": meta.get("datePublished"),
    }


def extract_links(result: dict) -> list:
    if not result.get("found"):
        return []
    cve_id = result.get("cve_id", "")
    return [{
        "url":         f"https://www.cve.org/CVERecord?id={cve_id}",
        "source":      "cveorg",
        "type":        "reference",
        "title":       f"{cve_id} — CVE.org",
        "description": "MITRE CVE Program authoritative record",
    }]


def extract_actions(result: dict) -> tuple[list, list]:
    return [], []
