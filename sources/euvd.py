"""fetch_euvd_cve — ENISA European Vulnerability Database lookup.
Runs immediately after NVD (ORDER=11) to cross-validate CVSS scores.
Fail-open: any error returns {"found": False}, NVD remains primary."""
import logging
import requests as _requests
import db
import context as ctx

logger = logging.getLogger(__name__)

NAME  = "fetch_euvd_cve"
ORDER = 11

_BASE    = "https://euvdservices.enisa.europa.eu/api/enisaid"
_TIMEOUT = 8

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Query the ENISA European Vulnerability Database (EUVD) for a CVE. "
        "Returns CVSS base score and version, CVSS vector, EPSS exploitation "
        "probability, assigner, and the EUVD ID. "
        "Call this immediately after parse_nvd_cve. Compare CVSS scores for the "
        "same version (e.g. both v3.1). If NVD and EUVD differ by more than 0.5 "
        "for the same version, flag the discrepancy explicitly to the user — it "
        "may indicate a disputed score or a pending NVD update. "
        "NVD is the primary source; EUVD is supplementary EU context."
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
    "- **fetch_euvd_cve** — Call immediately after parse_nvd_cve. "
    "Cross-validates CVSS score. Flag discrepancies > 0.5 on the same CVSS version."
)


def _fetch_raw(cve_id: str) -> dict | None:
    """Pure HTTP fetch — no ctx/db side effects. Used by NVD pre-fetch spawner."""
    try:
        resp = _requests.get(_BASE, params={"id": cve_id}, timeout=_TIMEOUT)
        if resp.status_code != 200 or not resp.text.strip():
            if resp.status_code in (429, 503):
                logger.warning("EUVD %s for %s — skipping", resp.status_code, cve_id)
            else:
                logger.debug("EUVD non-200 %s for %s", resp.status_code, cve_id)
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception as exc:
        logger.debug("EUVD fetch error for %s: %s", cve_id, exc)
        return None


def fetch(cve_id: str) -> dict:
    data = ctx.get_prefetch("euvd", cve_id) or _fetch_raw(cve_id)
    if not data:
        return {"found": False, "cve_id": cve_id, "source": "euvd"}

    score   = data.get("baseScore")
    version = data.get("baseScoreVersion")
    vector  = data.get("baseScoreVector")
    epss    = data.get("epss")

    conv_id = getattr(ctx.current_conv, "conv_id", "")
    if score is not None:
        db.store_euvd_score(cve_id, score, version)  # cve_id direct — no longer needs conv_id
        # Also seed cvss_score/severity as a fallback so the War Room card always
        # shows a score even when NVD times out. COALESCE in store_cve_metadata means
        # NVD will silently overwrite this if/when it succeeds — EUVD never clobbers
        # authoritative NVD data.
        severity_from_score = (
            "CRITICAL" if score >= 9.0 else
            "HIGH"     if score >= 7.0 else
            "MEDIUM"   if score >= 4.0 else
            "LOW"
        )
        db.store_cve_metadata(conv_id, cve_id, score, severity_from_score, version)

    # Extract structured affected products — used for infra seeding without LLM.
    # Each entry: {"vendor": "Oracle Corporation", "product": "WebLogic Server", "version": "12.2.1.4.0"}
    products = []
    for entry in (data.get("enisaIdProduct") or []):
        p = entry.get("product") or {}
        v = p.get("vendor") or {}
        vendor_name  = (v.get("name") or "").strip()
        product_name = (p.get("name") or "").strip()
        version      = (entry.get("product_version") or "unknown").strip()
        if vendor_name or product_name:
            products.append({"vendor": vendor_name, "product": product_name, "version": version})

    result = {
        "found":          True,
        "cve_id":         cve_id,
        "euvd_id":        data.get("id"),
        "source":         "euvd",
        "cvss_score":     score,
        "cvss_version":   version,
        "cvss_vector":    vector,
        "epss":           epss,
        "assigner":       data.get("assigner"),
        "date_published": data.get("datePublished"),
        "date_updated":   data.get("dateUpdated"),
        "products":       products,
    }
    ctx.euvd_store.result = result
    return result


def extract_links(result: dict) -> list:
    if not result.get("found"):
        return []
    euvd_id = result.get("euvd_id", "").strip()
    if not euvd_id:
        return []
    return [{
        "url":         f"https://euvd.enisa.europa.eu/enisaid/{euvd_id}",
        "source":      "euvd",
        "type":        "reference",
        "title":       euvd_id,
        "description": "ENISA EUVD Entry",
    }]


def extract_actions(result: dict) -> tuple[list, list]:
    return [], []
