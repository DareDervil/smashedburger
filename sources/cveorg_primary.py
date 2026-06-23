"""Primary CVE lookup via the CVE.org (MITRE) API — drop-in replacement for NVD.

Why CVE.org instead of NVD?
- CVEs appear here first: NVD is a downstream consumer of CVE.org data.
- New CVEs land here days before NVD processes them ("Awaiting Analysis").
- No API key, no per-IP rate limits (NVD requires an API key for reliable access).
- CVSS scores are available via ADP containers (NVD and CISA populate these
  alongside the CNA's own scores).

Output shape matches parse_nvd_cve() so nothing downstream changes:
  id, published, lastModified, vulnStatus, description,
  cvssMetricV31 / cvssMetricV30 / cvssMetricV2  (each: baseScore, baseSeverity,
  vectorString, version, vectorUnpacked),
  cisaExploitAdd, cisaRequiredAction, cisaVulnerabilityName,
  products, references.

Architecture note — ADP containers:
  CVE.org 5.0 records have a `containers` dict with:
    - `cna`  : the CVE Numbering Authority's data (description, CWE, sometimes CVSS)
    - `adp`  : list of Authorized Data Publishers — CISA and NVD inject CVSS scores,
               KEV status, and CPE-based product lists here after the CNA publishes.
  We prefer ADP CVSS (NVD's contribution) over CNA CVSS, then fall back to CNA.
  Products come from CPE data in the NVD ADP container exactly as in NVD's own API.
"""
import logging
import requests as _requests

logger = logging.getLogger(__name__)

_BASE    = "https://cveawg.mitre.org/api/cve"
_TIMEOUT = 10   # CVE.org is generally fast; NVD was 25s


def fetch_cveorg_primary(cve_id: str) -> dict:
    """Fetch a CVE from CVE.org and return a dict matching parse_nvd_cve() output.
    Raises on network error or missing CVE — caller queues a background retry."""
    logger.debug("CVE.org fetch %s", cve_id.upper())
    resp = _requests.get(f"{_BASE}/{cve_id.upper()}", timeout=_TIMEOUT)
    if resp.status_code == 404:
        logger.debug("CVE.org 404 for %s", cve_id)
        raise ValueError(f"CVE not found on CVE.org: {cve_id}")
    resp.raise_for_status()
    data = resp.json()

    meta          = data.get("cveMetadata") or {}
    containers    = data.get("containers") or {}
    cna           = containers.get("cna") or {}
    adp_list      = containers.get("adp") or []

    # ── Description ──────────────────────────────────────────────────────────
    description = "N/A"
    for d in (cna.get("descriptions") or []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "N/A")
            break

    result = {
        "id":           meta.get("cveId", cve_id.upper()),
        "published":    meta.get("datePublished"),
        "lastModified": meta.get("dateUpdated"),
        "vulnStatus":   meta.get("state"),
        "description":  description,
    }

    # ── CVSS scores ───────────────────────────────────────────────────────────
    # CVE.org 5.0 metrics format differs from NVD's flat format.
    # Each metrics entry is a dict with a key like "cvssV3_1", "cvssV2_0", etc.
    # We collect from ADP first (NVD's contribution is most authoritative),
    # then fall back to CNA's own scoring.
    def _collect_metrics(container: dict) -> list:
        return container.get("metrics") or []

    # Merge: ADP metrics take priority over CNA
    all_metrics: list = []
    for adp in adp_list:
        all_metrics.extend(_collect_metrics(adp))
    all_metrics.extend(_collect_metrics(cna))

    # Map CVE.org metric keys → NVD output keys
    _KEY_MAP = {
        "cvssV4_0": ("cvssMetricV40", "4.0"),
        "cvssV3_1": ("cvssMetricV31", "3.1"),
        "cvssV3_0": ("cvssMetricV30", "3.0"),
        "cvssV2_0": ("cvssMetricV2",  "2.0"),
    }
    seen_metric_keys: set = set()
    for metric_entry in all_metrics:
        for cveorg_key, (nvd_key, version) in _KEY_MAP.items():
            if cveorg_key in metric_entry and nvd_key not in seen_metric_keys:
                cvss = metric_entry[cveorg_key]
                score    = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", "N/A")
                vector   = cvss.get("vectorString", "N/A")
                result[nvd_key] = {
                    "version":       version,
                    "vectorString":  vector,
                    "baseScore":     score,
                    "baseSeverity":  severity,
                    "vectorUnpacked": {},   # omit — not used by downstream logic
                }
                seen_metric_keys.add(nvd_key)

    # Fill any missing metric keys with "N/A" (same as parse_nvd_cve)
    for _, (nvd_key, _) in _KEY_MAP.items():
        if nvd_key not in result:
            result[nvd_key] = "N/A"

    # ── CISA KEV fields (from CISA ADP container) ────────────────────────────
    result["cisaExploitAdd"]        = "N/A"
    result["cisaRequiredAction"]    = "N/A"
    result["cisaVulnerabilityName"] = "N/A"
    for adp in adp_list:
        org = (adp.get("providerMetadata") or {}).get("shortName", "").lower()
        if "cisa" in org:
            for tag in (adp.get("tags") or []):
                if isinstance(tag, dict) and tag.get("kev"):
                    result["cisaExploitAdd"]     = tag["kev"].get("dateAdded", "N/A")
                    result["cisaRequiredAction"] = tag["kev"].get("requiredAction", "N/A")
                    result["cisaVulnerabilityName"] = tag["kev"].get("vulnerabilityName", "N/A")
            break

    # ── Products from CPE data (NVD ADP) ─────────────────────────────────────
    # NVD injects CPE-based product lists into its ADP container.
    # Format mirrors NVD API: configurations → nodes → cpeMatch.
    _CPE_CATEGORY = {"a": "application", "o": "operating_system", "h": "network"}
    products = []
    seen_products: set = set()
    nvd_adp = next(
        (a for a in adp_list
         if "nvd" in (a.get("providerMetadata") or {}).get("shortName", "").lower()),
        None,
    )
    configs = (nvd_adp or {}).get("configurations") or []
    for config in configs:
        for node in (config.get("nodes") or []):
            for match in (node.get("cpeMatch") or []):
                if not match.get("vulnerable", False):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 5:
                    continue
                cpe_type, cpe_vendor, cpe_product = parts[2], parts[3], parts[4]
                if "*" in (cpe_vendor, cpe_product):
                    continue
                key = (cpe_vendor, cpe_product)
                if key in seen_products:
                    continue
                seen_products.add(key)
                products.append({
                    "vendor":   cpe_vendor.replace("_", " ").title(),
                    "product":  cpe_product.replace("_", " ").title(),
                    "category": _CPE_CATEGORY.get(cpe_type, "application"),
                })
    result["products"] = products[:10]

    # ── References ────────────────────────────────────────────────────────────
    refs = []
    for ref in (cna.get("references") or []):
        url  = ref.get("url", "")
        tags = ref.get("tags") or []
        if url:
            refs.append({"url": url, "tags": tags})
    result["references"] = refs[:12]

    return result
