import html as html_lib
import json
import os
import re
import time
import urllib.parse
import requests
import dotenv

_ = dotenv.load_dotenv()

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
EXA_API_BASE  = "https://api.exa.ai/search"
VT_API_BASE   = "https://www.virustotal.com/api/v3/files/"

import re as _re
_HASH_RE = _re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def is_hash(value: str) -> bool:
    """True if value is a bare MD5/SHA-1/SHA-256 hex digest."""
    return bool(_HASH_RE.match((value or "").strip()))


def query_virustotal(file_hash: str) -> dict:
    """VirusTotal v3 file lookup for a hash IOC. On-demand, button-
    driven, results cached in DB — the free tier is 4 req/min, 500/day, so we
    never auto- or bulk-query. NOT an agent tool.

    Returns:
      {"ok": False, "error": ...}              key missing / invalid hash / transport error
      {"ok": True,  "in_vt": False}            hash not in VT (404)
      {"ok": True,  "in_vt": True, "malicious": n, "suspicious": n, "total": n,
                    "reputation": int, "name": str, "link": url}
    """
    file_hash = (file_hash or "").strip().lower()
    if not is_hash(file_hash):
        return {"ok": False, "error": "not a valid MD5/SHA-1/SHA-256 hash"}
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"ok": False, "error": "VIRUSTOTAL_API_KEY not configured"}

    try:
        resp = requests.get(VT_API_BASE + file_hash,
                            headers={"x-apikey": api_key}, timeout=20)
        if resp.status_code == 404:
            return {"ok": True, "in_vt": False}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as e:
        return {"ok": False, "error": str(e)}

    stats = attrs.get("last_analysis_stats", {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    sha256 = (resp.json().get("data", {}).get("id") or file_hash)
    return {
        "ok":         True,
        "in_vt":      True,
        "malicious":  int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "total":      total,
        "reputation": attrs.get("reputation"),
        "name":       attrs.get("meaningful_name") or "",
        "link":       f"https://www.virustotal.com/gui/file/{sha256}",
    }

# ---------------------------------------------------------------------------
# CVSS vector unpacking
# ---------------------------------------------------------------------------

_CVSS_V2_LABELS = {
    "AV":  ("Attack Vector",          {"L": "Local", "A": "Adjacent Network", "N": "Network"}),
    "AC":  ("Access Complexity",      {"H": "High", "M": "Medium", "L": "Low"}),
    "Au":  ("Authentication",         {"M": "Multiple", "S": "Single", "N": "None"}),
    "C":   ("Confidentiality Impact", {"N": "None", "P": "Partial", "C": "Complete"}),
    "I":   ("Integrity Impact",       {"N": "None", "P": "Partial", "C": "Complete"}),
    "A":   ("Availability Impact",    {"N": "None", "P": "Partial", "C": "Complete"}),
}

_CVSS_V3_LABELS = {
    "AV":  ("Attack Vector",          {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC":  ("Attack Complexity",      {"L": "Low", "H": "High"}),
    "PR":  ("Privileges Required",    {"N": "None", "L": "Low", "H": "High"}),
    "UI":  ("User Interaction",       {"N": "None", "R": "Required"}),
    "S":   ("Scope",                  {"U": "Unchanged", "C": "Changed"}),
    "C":   ("Confidentiality Impact", {"N": "None", "L": "Low", "H": "High"}),
    "I":   ("Integrity Impact",       {"N": "None", "L": "Low", "H": "High"}),
    "A":   ("Availability Impact",    {"N": "None", "L": "Low", "H": "High"}),
}

_CVSS_V40_LABELS = {
    # Exploitability
    "AV":  ("Attack Vector",                    {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC":  ("Attack Complexity",                {"L": "Low", "H": "High"}),
    "AT":  ("Attack Requirements",              {"N": "None", "P": "Present"}),
    "PR":  ("Privileges Required",              {"N": "None", "L": "Low", "H": "High"}),
    "UI":  ("User Interaction",                 {"N": "None", "P": "Passive", "A": "Active"}),
    # Vulnerable system impact
    "VC":  ("Vuln. System Confidentiality",     {"N": "None", "L": "Low", "H": "High"}),
    "VI":  ("Vuln. System Integrity",           {"N": "None", "L": "Low", "H": "High"}),
    "VA":  ("Vuln. System Availability",        {"N": "None", "L": "Low", "H": "High"}),
    # Subsequent system impact
    "SC":  ("Subsequent System Confidentiality",{"N": "None", "L": "Low", "H": "High"}),
    "SI":  ("Subsequent System Integrity",      {"N": "None", "L": "Low", "H": "High"}),
    "SA":  ("Subsequent System Availability",   {"N": "None", "L": "Low", "H": "High"}),
    # Threat
    "E":   ("Exploit Maturity",                 {"X": "Not Defined", "U": "Unreported", "P": "Proof-of-Concept", "A": "Attacked"}),
}


def _unpack_vector(vector_string: str, version: str) -> dict:
    """Parse a CVSS vector string into a human-readable dict of metric label → value label.
    Metrics marked X (Not Defined) or absent are omitted from the output.
    """
    if not vector_string or vector_string == "N/A":
        return {}

    # Strip the CVSS prefix (e.g. "CVSS:3.1/") if present
    parts = vector_string.lstrip("CVSS:").split("/")
    # Skip the version token when it looks like "3.1" or "4.0"
    metrics_parts = [p for p in parts if ":" in p]
    raw = dict(p.split(":", 1) for p in metrics_parts)

    if version.startswith("2"):
        label_map = _CVSS_V2_LABELS
    elif version.startswith("3"):
        label_map = _CVSS_V3_LABELS
    elif version.startswith("4"):
        label_map = _CVSS_V40_LABELS
    else:
        return raw  # unknown version — return raw tokens

    unpacked = {}
    for abbr, (label, values) in label_map.items():
        code = raw.get(abbr)
        if code is None or code == "X":
            continue
        unpacked[label] = values.get(code, code)

    return unpacked


def query_epss(cve_ids: str | list[str]) -> dict:
    """Fetch EPSS scores for one or more CVE IDs from the FIRST EPSS API.

    EPSS (Exploit Prediction Scoring System) measures the probability that a
    vulnerability will be exploited in the wild within the next 30 days.
    It is a threat metric, not a risk score — use it alongside CVSS, not instead of it:
      - High CVSS + High EPSS → patch immediately
      - High CVSS + Low EPSS  → monitor / prioritise by exposure
      - Low CVSS  + High EPSS → investigate (active exploitation despite low severity)
    """
    if isinstance(cve_ids, list):
        cve_param = ",".join(cve_ids)
    else:
        cve_param = cve_ids

    response = requests.get(
        EPSS_API_BASE,
        params={"cve": cve_param},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()

    results = []
    for item in data.get("data", []):
        epss_score = float(item.get("epss", 0))
        percentile  = float(item.get("percentile", 0))
        results.append({
            "cve":            item.get("cve"),
            "epss_score":     epss_score,
            "percentile":     percentile,
            "epss_pct":       f"{epss_score * 100:.1f}%",
            "percentile_pct": f"{percentile * 100:.1f}%",
        })

    return {
        "date":    data.get("data", [{}])[0].get("date") if results else None,
        "results": results,
    }


def search_cves_by_product(vendor: str, product: str) -> dict:
    """Search NVD for CVEs affecting a vendor/product. Returns up to 20 most recent
    CVEs with CVSS scores and structured version ranges where available.

    The NVD 2.0 API has NO sort parameters (unknown params → HTTP 404) and returns
    keyword results oldest-first. To get the newest CVEs: fetch the first page for
    totalResults, then re-fetch the LAST page (startIndex = totalResults - 20) and
    sort client-side, newest first."""
    keyword = f"{vendor} {product}".strip()
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}

    def _page(start_index: int) -> dict:
        # Without an API key NVD allows 5 req/30 s — be polite
        if not api_key:
            time.sleep(0.7)
        resp = requests.get(
            NVD_API_BASE,
            params={
                "keywordSearch":  keyword,
                "resultsPerPage": 20,
                "startIndex":     start_index,
            },
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    try:
        data = _page(0)
        total = data.get("totalResults", 0)
        if total > 20:
            data = _page(total - 20)
    except Exception as e:
        return {"found": False, "error": str(e), "cves": []}

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        # English description
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )

        # CVSS — prefer V3.1, fall back to V3.0 then V2
        score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = cve.get("metrics", {}).get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score = cvss.get("baseScore")
                # V2 keeps baseSeverity on the wrapper; V3+ inside cvssData
                severity = (
                    entries[0].get("baseSeverity", "UNKNOWN")
                    if key == "cvssMetricV2"
                    else cvss.get("baseSeverity", "UNKNOWN")
                )
                break

        # Structured version ranges from CPE match data
        version_ranges = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    vr = {}
                    for field in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding",   "versionEndExcluding",
                    ):
                        if match.get(field):
                            vr[field] = match[field]
                    if vr:
                        version_ranges.append(vr)

        cves.append({
            "id":            cve.get("id", ""),
            "description":   description[:400],   # truncate for token economy
            "cvssScore":     score,
            "severity":      severity,
            "published":     (cve.get("published")    or "")[:10],
            "lastModified":  (cve.get("lastModified") or "")[:10],
            "versionRanges": version_ranges,
        })

    # NVD returns oldest-first — present newest first
    cves.sort(key=lambda c: c["published"], reverse=True)

    return {
        "found":        len(cves) > 0,
        "totalResults": data.get("totalResults", 0),
        "returned":     len(cves),
        "keyword":      keyword,
        "cves":         cves,
    }


def query_nvd_cve(cve_id: str) -> dict:
    api_key = os.environ["NVD_API_KEY"]
    response = requests.get(
        NVD_API_BASE,
        params={"cveId": cve_id},
        headers={"apiKey": api_key, "User-Agent": "smashedburger/1.0"},
        timeout=25,
    )
    response.raise_for_status()
    return response.json()


def parse_nvd_cve(cve_id: str) -> dict:
    """Query NVD for a CVE and return a cleaned, flattened dict with only the fields of interest."""
    raw = query_nvd_cve(cve_id)

    vulnerabilities = raw.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError(f"No CVE data found for {cve_id}")

    cve = vulnerabilities[0]["cve"]

    # --- Always-present fields ---
    en_description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "N/A",
    )

    result = {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": en_description,
    }

    # --- Optional fields (N/A when absent) ---

    # CVSS metrics — check all known versions, return data for those present
    CVSS_METRIC_KEYS = {
        "cvssMetricV2":  "baseSeverity_v2",   # v2 stores baseSeverity on the wrapper
        "cvssMetricV30": None,                 # v3.x stores baseSeverity inside cvssData
        "cvssMetricV31": None,
        "cvssMetricV40": None,
    }
    metrics_raw = cve.get("metrics", {})
    for metric_key in CVSS_METRIC_KEYS:
        entries = metrics_raw.get(metric_key, [])
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            # v2 keeps baseSeverity on the wrapper entry; v3+ keep it inside cvssData
            base_severity = (
                entry.get("baseSeverity", "N/A")
                if metric_key == "cvssMetricV2"
                else cvss_data.get("baseSeverity", "N/A")
            )
            vector_string = cvss_data.get("vectorString", "N/A")
            version_str = cvss_data.get("version", "")
            result[metric_key] = {
                "version": version_str or "N/A",
                "vectorString": vector_string,
                "baseScore": cvss_data.get("baseScore", "N/A"),
                "baseSeverity": base_severity,
                "vectorUnpacked": _unpack_vector(vector_string, version_str),
            }
        else:
            result[metric_key] = "N/A"

    result["cisaExploitAdd"] = cve.get("cisaExploitAdd", "N/A")
    result["cisaRequiredAction"] = cve.get("cisaRequiredAction", "N/A")
    result["cisaVulnerabilityName"] = cve.get("cisaVulnerabilityName", "N/A")

    # CPE-based product extraction — structured, deterministic, no LLM needed.
    # CPE format: cpe:2.3:<type>:<vendor>:<product>:<version>:...
    # type: a=application, o=operating_system, h=hardware/network
    _CPE_CATEGORY = {"a": "application", "o": "operating_system", "h": "network"}
    products = []
    seen = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) < 5:
                    continue
                cpe_type, cpe_vendor, cpe_product = parts[2], parts[3], parts[4]
                if "*" in (cpe_vendor, cpe_product):
                    continue
                key = (cpe_vendor, cpe_product)
                if key in seen:
                    continue
                seen.add(key)
                products.append({
                    "vendor":   cpe_vendor.replace("_", " ").title(),
                    "product":  cpe_product.replace("_", " ").title(),
                    "category": _CPE_CATEGORY.get(cpe_type, "application"),
                })
    result["products"] = products[:10]   # cap for broad CVEs with many CPEs

    # References — vendor advisory and patch URLs. These are how the agent finds
    # the input URLs for fetch_fortinet_advisory (FG-IR), fetch_citrix_advisory
    # (CTX), and fetch_broadcom_advisory (SecurityAdvisories) — without them the
    # URL-input vendor tools are unreachable for post-cutoff CVEs.
    tagged = []
    untagged = []
    for ref in cve.get("references", []):
        url, tags = ref.get("url", ""), ref.get("tags", [])
        if not url:
            continue
        if "Vendor Advisory" in tags or "Patch" in tags:
            tagged.append({"url": url, "tags": tags})
        else:
            untagged.append({"url": url, "tags": tags})
    # New/unenriched CVEs often have no tags yet — fall back to untagged URLs
    result["references"] = (tagged or untagged)[:12]

    return result


_PAN_ADVISORY_BASE = "https://security.paloaltonetworks.com/json"


def _extract_cvss(metrics: list) -> dict:
    """Walk the metrics array and return score/severity/vector for the highest
    available CVSS version: v4.0 → v3.1 → v3.0 → v2.0."""
    preference = [
        ("cvssV4_0",  "baseSeverity", "baseScore", "vectorString"),
        ("cvssV3_1",  "baseSeverity", "baseScore", "vectorString"),
        ("cvssV3_0",  "baseSeverity", "baseScore", "vectorString"),
        ("cvssV2_0",  "baseSeverity", "baseScore", "vectorString"),
    ]
    for metric in (metrics or []):
        for key, sev_field, score_field, vec_field in preference:
            if key in metric:
                cvss = metric[key]
                return {
                    "cvss_version":  cvss.get("version", key.replace("cvss", "").replace("_", ".")),
                    "cvss_score":    cvss.get(score_field),
                    "cvss_severity": cvss.get(sev_field, "UNKNOWN").upper(),
                    "cvss_vector":   cvss.get(vec_field, "N/A"),
                }
    return {"cvss_version": "N/A", "cvss_score": None, "cvss_severity": "UNKNOWN", "cvss_vector": "N/A"}


def _first_text(items: list) -> str | None:
    """Return the English .value from the first item in a list, or None."""
    if not items:
        return None
    for item in items:
        if isinstance(item, dict):
            lang = item.get("lang", "en")
            if lang.startswith("en"):
                return item.get("value") or None
    return items[0].get("value") if isinstance(items[0], dict) else None


def fetch_palo_alto_advisory(cve_id: str) -> dict:
    """Fetch and parse a Palo Alto Networks security advisory from the CVE JSON 5.0 endpoint.

    Returns a flat dict with:
      - cve_id, title, description
      - cvss_score, cvss_severity, cvss_vector, cvss_version
      - affected_versions: flat list of affected version strings (x_affectedList)
      - affected_products: structured list [{product, affected_branches, fix_versions}]
      - required_config, workaround, solution, exploitation_status
      - references: list of URLs
      - date_published, date_updated
      - advisory_url: link to the human-readable page

    Returns {"found": False, "error": ...} on failure.
    """
    cve_id = cve_id.strip().upper()
    url    = f"{_PAN_ADVISORY_BASE}/{cve_id}"

    try:
        resp = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        if resp.status_code == 404:
            return {"found": False, "error": f"No Palo Alto advisory found for {cve_id}"}
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"found": False, "error": str(e)}

    meta = data.get("cveMetadata", {})
    cna  = data.get("containers", {}).get("cna", {})

    # CVSS — fallback chain v4 → v3.1 → v3.0 → v2
    cvss = _extract_cvss(cna.get("metrics", []))

    # Affected versions — flat list for easy infrastructure matching
    affected_versions = cna.get("x_affectedList", [])

    # Structured affected products — extract per-product fix versions
    affected_products = []
    for entry in cna.get("affected", []):
        product = entry.get("product", "")
        branches = []
        for v in entry.get("versions", []):
            if v.get("status") == "affected":
                fix_versions = [
                    c["at"] for c in v.get("changes", [])
                    if c.get("status") == "unaffected"
                ]
                branches.append({
                    "branch":       v.get("version"),
                    "fix_versions": fix_versions,
                })
        # Only include products that have at least one affected branch
        if branches:
            affected_products.append({"product": product, "affected_branches": branches})

    return {
        "found":               True,
        "cve_id":              meta.get("cveId", cve_id),
        "title":               cna.get("title", ""),
        "description":         _first_text(cna.get("descriptions", [])),
        **cvss,
        "affected_versions":   affected_versions,
        "affected_products":   affected_products,
        "required_config":     _first_text(cna.get("configurations", [])),
        "workaround":          _first_text(cna.get("workarounds", [])),
        "solution":            _first_text(cna.get("solutions", [])),
        "exploitation_status": _first_text(cna.get("exploits", [])),
        "references":          [r.get("url") for r in cna.get("references", []) if r.get("url")],
        "date_published":      (meta.get("datePublished") or "")[:10],
        "date_updated":        (meta.get("dateUpdated")   or "")[:10],
        "advisory_url":        f"https://security.paloaltonetworks.com/{cve_id}",
    }


_CISCO_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
_CISCO_ADVISORY_URL = "https://apix.cisco.com/security/advisories/v2/cve"
def fetch_cisco_advisory(cve_id: str) -> dict:
    """Fetch Cisco PSIRT advisories for a CVE via the OpenVuln API.

    Authenticates with client credentials (CISCO_API_KEY + CISCO_CLIENT_SECRET),
    then queries /security/advisories/v2/cve/{cve_id}.

    Returns a list of matching advisories (one CVE can map to multiple Cisco advisories),
    each with: advisory_id, title, sir (Security Impact Rating), cvss_base_score,
    cvss_vector, summary, workarounds, affected_products, fixed_versions, bug_ids,
    publication_url, date_published, date_updated.
    """
    cve_id = cve_id.strip().upper()
    client_id     = os.getenv("CISCO_API_KEY", "")
    client_secret = os.getenv("CISCO_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return {"found": False, "error": "CISCO_API_KEY or CISCO_CLIENT_SECRET not configured"}

    # ── Step 1: obtain bearer token ──
    try:
        token_resp = requests.post(
            _CISCO_TOKEN_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        if not token:
            return {"found": False, "error": "No access_token in Cisco auth response"}
    except Exception as e:
        return {"found": False, "error": f"Cisco auth failed: {e}"}

    # ── Step 2: query advisories by CVE ──
    try:
        adv_resp = requests.get(
            f"{_CISCO_ADVISORY_URL}/{cve_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept":        "application/json",
            },
            timeout=15,
        )
        if adv_resp.status_code == 404:
            return {"found": False, "error": f"No Cisco advisory found for {cve_id}"}
        adv_resp.raise_for_status()
        data = adv_resp.json()
    except Exception as e:
        return {"found": False, "error": f"Cisco advisory fetch failed: {e}"}

    raw_advisories = data.get("advisories", [])
    if not raw_advisories:
        return {"found": False, "error": f"No Cisco advisories returned for {cve_id}"}

    advisories = []
    for adv in raw_advisories:
        # CVSS vector — try v3 first, fall back to v2
        cvss_vector = adv.get("cvssBaseVector") or adv.get("cvssVector") or "N/A"
        cvss_score  = adv.get("cvssBaseScore")
        try:
            cvss_score = float(cvss_score) if cvss_score else None
        except (ValueError, TypeError):
            cvss_score = None

        # Affected products — productNames is a flat list of strings
        affected_products = adv.get("productNames", [])

        # Fixed versions — firstFixed is a list of dicts with 'version' and optionally 'platform'
        fixed_versions = []
        for ff in adv.get("firstFixed", []):
            if isinstance(ff, dict):
                entry = ff.get("version") or ff.get("firstFixed") or str(ff)
            else:
                entry = str(ff)
            if entry:
                fixed_versions.append(entry)

        # Workaround — single string or "No workarounds available"
        workaround = (adv.get("workarounds") or "").strip()
        if workaround.lower() in ("no workarounds available.", "no workarounds available", ""):
            workaround = ""

        advisories.append({
            "advisory_id":        adv.get("advisoryId", ""),
            "title":              adv.get("advisoryTitle", ""),
            "sir":                adv.get("sir", ""),          # Critical/High/Medium/Low
            "cvss_base_score":    cvss_score,
            "cvss_vector":        cvss_vector,
            "summary":            _html_text(adv.get("summary") or ""),
            "workaround":         workaround,
            "affected_products":  affected_products,
            "fixed_versions":     fixed_versions,
            "bug_ids":            adv.get("bugIDs", []),
            "publication_url":    adv.get("publicationUrl", ""),
            "date_published":     (adv.get("firstPublished") or "")[:10],
            "date_updated":       (adv.get("lastUpdated")    or "")[:10],
        })

    return {"found": True, "cve_id": cve_id, "advisories": advisories}


_FORTIGUARD_BASE = "https://fortiguard.fortinet.com"


def _html_text(fragment: str) -> str:
    """Strip HTML tags and decode all entities (named and numeric, e.g. &#160;)."""
    text = re.sub(r"<[^>]+>", " ", fragment)
    text = html_lib.unescape(text).replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


def fetch_fortinet_advisory(advisory_url: str) -> dict:
    """Fetch and parse a Fortinet PSIRT advisory page.

    advisory_url: full URL like https://fortiguard.fortinet.com/psirt/FG-IR-24-015,
    as found in NVD references for Fortinet CVEs.
    Also accepts a bare FG-IR ID (e.g. 'FG-IR-24-015').

    Returns a structured dict with: title, description, workaround, virtual_patch,
    affected_products [{product, affected_range, solution}], CVSS, known_exploited,
    dates, impact, attack_type, fg_ir_id, cve_id, advisory_url.
    """
    advisory_url = advisory_url.strip().rstrip("/")
    if re.match(r"^FG-IR-", advisory_url, re.IGNORECASE):
        advisory_url = f"{_FORTIGUARD_BASE}/psirt/{advisory_url}"

    try:
        resp = requests.get(
            advisory_url,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 404:
            return {"found": False, "error": f"No Fortinet advisory at {advisory_url}"}
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        return {"found": False, "error": str(e)}

    # ── Title ──
    title = ""
    title_m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL | re.IGNORECASE)
    if title_m:
        title = _html_text(title_m.group(1))

    # ── Summary section (paragraphs between <h3>Summary</h3> and next heading) ──
    description = ""
    workaround = ""
    virtual_patch = ""
    exploitation_note = ""

    summary_m = re.search(
        r"<h3[^>]*>\s*Summary\s*</h3>(.*?)(?=<h3[^>]*>|\Z)",
        html, re.DOTALL | re.IGNORECASE,
    )
    if summary_m:
        for p_html in re.findall(r"<p[^>]*>(.*?)</p>", summary_m.group(1), re.DOTALL | re.IGNORECASE):
            p = _html_text(p_html)
            if not p:
                continue
            pl = p.lower()
            if pl.startswith("workaround"):
                workaround = p
            elif "virtual patch" in pl:
                virtual_patch = p
            elif pl.startswith("note:") or "exploited in the wild" in pl:
                exploitation_note = p
            elif not description:
                description = p

    # ── Parse all tables ──
    affected_products: list[dict] = []
    fg_ir_id       = advisory_url.split("/")[-1]
    cve_id         = ""
    severity       = ""
    known_exploited = False
    date_published = ""
    date_updated   = ""
    impact         = ""
    attack_type    = ""
    cvss_score     = None

    for tbl_html in re.findall(r"<table[^>]*>(.*?)</table>", html, re.DOTALL | re.IGNORECASE):
        rows: list[list[str]] = []
        for row_html in re.findall(r"<tr[^>]*>(.*?)</tr>", tbl_html, re.DOTALL | re.IGNORECASE):
            cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row_html, re.DOTALL | re.IGNORECASE)
            cleaned = [_html_text(c) for c in cells]
            if any(cleaned):
                rows.append(cleaned)

        if not rows:
            continue

        # Version table: ≥3 cols, headers contain "version" + ("affected" or "solution")
        if len(rows) > 1 and len(rows[0]) >= 3:
            hdr = [c.lower() for c in rows[0]]
            if "version" in hdr and ("affected" in hdr or "solution" in hdr):
                for row in rows[1:]:
                    if len(row) >= 3 and row[0]:
                        affected_products.append({
                            "product":        row[0],
                            "affected_range": row[1],
                            "solution":       row[2],
                        })
                continue  # don't try to parse as metadata

        # Metadata table: 2 cols, key-value; identified by known labels
        if rows and all(len(r) == 2 for r in rows):
            meta: dict[str, str] = {r[0].lower().strip(): r[1].strip() for r in rows}
            if "ir number" in meta or "cve id" in meta:
                fg_ir_id        = meta.get("ir number", fg_ir_id)
                cve_id          = meta.get("cve id", "")
                severity        = meta.get("severity", "")
                date_published  = meta.get("published date", "")
                date_updated    = meta.get("updated date", "")
                impact          = meta.get("impact", "")
                attack_type     = meta.get("attack type", "")
                ke_raw          = meta.get("known exploited", "no")
                known_exploited = ke_raw.lower() not in ("no", "false", "", "n/a", "unknown")
                # CVSS score cell may contain a hyperlink — extract the numeric value
                cvss_raw = meta.get("cvssv3 score", meta.get("cvss score", ""))
                m = re.search(r"(\d+\.\d+)", cvss_raw)
                cvss_score = float(m.group(1)) if m else None

    # ── CVSS vector — embedded in NVD link href inside the page ──
    cvss_vector = None
    vec_m = re.search(r"[?&]vector=([A-Z0-9:./]+)", html)
    if vec_m:
        raw_vec = urllib.parse.unquote(vec_m.group(1))
        if not raw_vec.startswith("CVSS:"):
            ver_m = re.search(r"[?&]version=(\d+\.\d+)", html)
            if ver_m:
                raw_vec = f"CVSS:{ver_m.group(1)}/{raw_vec}"
        cvss_vector = raw_vec

    # Fallback CVE ID from anywhere in the page
    if not cve_id:
        cve_m = re.search(r"CVE-\d{4}-\d+", html)
        cve_id = cve_m.group(0) if cve_m else ""

    return {
        "found":            True,
        "advisory_url":     advisory_url,
        "fg_ir_id":         fg_ir_id,
        "cve_id":           cve_id,
        "title":            title,
        "description":      description,
        "workaround":       workaround,
        "virtual_patch":    virtual_patch,
        "exploitation_note": exploitation_note,
        "affected_products": affected_products,
        "cvss_score":       cvss_score,
        "cvss_severity":    severity,
        "cvss_vector":      cvss_vector,
        "known_exploited":  known_exploited,
        "date_published":   date_published,
        "date_updated":     date_updated,
        "impact":           impact,
        "attack_type":      attack_type,
    }


_CITRIX_SSR_BASE = "https://support.citrix.com/external/article"


def _flatten_advisory_html(html: str) -> list[str]:
    """Flatten advisory HTML into text lines, preserving headings (§ prefix)
    and list items (• prefix) so sections can be located by name.
    Used by the Citrix and Broadcom fetchers."""
    # Drop script/style/head noise
    html = re.sub(r"<(script|style|head)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    # Remove tables — parsed separately
    html = re.sub(r"<table[^>]*>.*?</table>", "\n", html, flags=re.DOTALL | re.IGNORECASE)
    # Structural markers
    html = re.sub(r"<h[1-6][^>]*>", "\n§ ", html, flags=re.IGNORECASE)
    html = re.sub(r"</h[1-6]>", "\n", html, flags=re.IGNORECASE)
    html = re.sub(r"<li[^>]*>", "\n• ", html, flags=re.IGNORECASE)
    html = re.sub(r"<(p|br|div|tr|ul|ol)[^>]*/?>", "\n", html, flags=re.IGNORECASE)
    lines = []
    for raw_line in html.split("\n"):
        line = _html_text(raw_line)
        if line:
            lines.append(line)
    return lines


def fetch_citrix_advisory(advisory_url: str) -> dict:
    """Fetch and parse a Citrix (Cloud Software Group) security bulletin.

    advisory_url: any URL containing a CTX article ID — typically the NVD reference
    'https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420'
    (a JS-rendered SPA). Also accepts a bare CTX ID (e.g. 'CTX693420').

    The CTX ID is extracted and the bulletin is fetched from the server-side-rendered
    endpoint /external/article/{CTX_ID}/x.html — no headless browser needed.

    Returns: title, severity, cves [{cve_id, description, preconditions, cwe,
    cvss_score, cvss_vector}], affected_versions, fixed_versions, remediation_text,
    mitigating_factors, exploitation_note, eol_note, references, dates, ctx_id,
    advisory_url. Returns {"found": False, "error": ...} on failure.
    """
    ctx_m = re.search(r"CTX\d+", advisory_url, re.IGNORECASE)
    if not ctx_m:
        return {"found": False, "error": f"No CTX article ID found in '{advisory_url}'"}
    ctx_id = ctx_m.group(0).upper()
    url = f"{_CITRIX_SSR_BASE}/{ctx_id}/cve.html"

    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 404:
            return {"found": False, "error": f"No Citrix bulletin found for {ctx_id}"}
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        return {"found": False, "error": str(e)}

    # ── Title ──
    title = ""
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.DOTALL | re.IGNORECASE)
    if title_m:
        title = _html_text(title_m.group(1))

    # ── Tables: CVE details + changelog ──
    cves: list[dict] = []
    date_published, date_updated = "", ""
    for tbl_html in re.findall(r"<table[^>]*>(.*?)</table>", html, re.DOTALL | re.IGNORECASE):
        rows: list[list[str]] = []
        for row_html in re.findall(r"<tr[^>]*>(.*?)</tr>", tbl_html, re.DOTALL | re.IGNORECASE):
            cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row_html, re.DOTALL | re.IGNORECASE)
            cleaned = [_html_text(c) for c in cells]
            if any(cleaned):
                rows.append(cleaned)
        if not rows:
            continue

        # Normalise header cells: "CVE ID", "CVE-ID", "**CVE-ID**" → "cveid"
        hdr = [re.sub(r"[^a-z]", "", c.lower()) for c in rows[0]]

        # CVE details table — header contains a CVE-ID column
        if any("cveid" in h for h in hdr):
            def _col(*needles):
                for i, h in enumerate(hdr):
                    if any(n in h for n in needles):
                        return i
                return None
            i_cve, i_desc = _col("cveid"), _col("description")
            i_pre, i_cwe, i_cvss = _col("pre"), _col("cwe"), _col("cvss")
            for row in rows[1:]:
                def _cell(i):
                    return row[i].strip() if i is not None and i < len(row) else ""
                cve_cell = _cell(i_cve)
                cve_id_m = re.search(r"CVE-\d{4}-\d+", cve_cell)
                if not cve_id_m:
                    continue
                # Row-wide fallbacks: cell indices occasionally shift (empty tds,
                # rowspans) — the patterns are unambiguous enough to search the row
                row_text = " | ".join(row)
                cwe = _cell(i_cwe)
                if not cwe:
                    cwe_m = re.search(r"CWE-\d+[^|]*", row_text)
                    cwe = cwe_m.group(0).strip() if cwe_m else ""
                score_m  = re.search(r"Base Score:\s*([\d.]+)", _cell(i_cvss) or row_text)
                vector_m = re.search(r"(CVSS:[\d.]+/[A-Za-z0-9:/.]+)", _cell(i_cvss) or row_text)
                cves.append({
                    "cve_id":        cve_id_m.group(0),
                    "description":   _cell(i_desc),
                    "preconditions": _cell(i_pre),
                    "cwe":           cwe,
                    "cvss_score":    float(score_m.group(1)) if score_m else None,
                    "cvss_vector":   vector_m.group(1) if vector_m else "",
                })
            continue

        # Changelog table — 2 columns, first cell starts with a date
        if all(len(r) == 2 for r in rows) and re.match(r"\d{2,4}-\d{2}-\d{2,4}", rows[0][0]):
            date_published = rows[0][0].split("T")[0].strip()
            date_updated   = rows[-1][0].split("T")[0].strip()

    # ── Flattened text for section parsing ──
    lines = _flatten_advisory_html(html)

    # Boilerplate sections are interleaved with content on Citrix KB pages —
    # skip them (until the next non-boilerplate heading) rather than truncate
    _SKIP_HEADINGS = ("what citrix is doing", "obtaining support", "subscribe to receive",
                      "reporting security vulnerabilities", "disclaimer", "acknowledgement",
                      "environment", "welcome to")
    main_lines: list[str] = []
    skipping = False
    for line in lines:
        if line.startswith("§"):
            bare = line.lstrip("§ ").strip().lower()
            skipping = any(bare.startswith(s) for s in _SKIP_HEADINGS)
            if skipping:
                continue
        if line.lower().startswith("was this article helpful"):
            break  # page footer — nothing of value below
        if not skipping:
            main_lines.append(line)

    text = "\n".join(main_lines)

    # ── Severity ──
    severity = ""
    sev_m = re.search(r"Severity\s*[-–:]\s*(Critical|High|Important|Medium|Moderate|Low)",
                      text, re.IGNORECASE)
    if sev_m:
        severity = sev_m.group(1).upper()

    # ── Affected versions: bullets following an "Affected Versions" marker ──
    def _bullets_after(pattern: str) -> list[str]:
        out: list[str] = []
        collecting = False
        for line in main_lines:
            if re.search(pattern, line, re.IGNORECASE):
                collecting = True
                continue
            if collecting:
                if line.startswith("•"):
                    out.append(line.lstrip("• ").strip())
                elif out:  # bullet run ended
                    break
        return out

    affected_versions = _bullets_after(r"^§?\s*Affected Versions")
    # Fixed versions: bullets after the standard CSG remediation phrase,
    # falling back to the remediation section heading
    fixed_versions = _bullets_after(r"install the relevant updated versions")
    if not fixed_versions:
        fixed_versions = _bullets_after(r"^§\s*(What Customers Should Do|Instructions)")

    # ── Remediation section text (post-upgrade commands, notes) ──
    remediation_text = ""
    in_section = False
    rem_lines: list[str] = []
    for line in main_lines:
        if line.startswith("§"):
            if re.search(r"(What Customers Should Do|Instructions)", line, re.IGNORECASE):
                in_section = True
                continue
            if in_section:
                break
        elif in_section:
            rem_lines.append(line.lstrip("• ").strip())
    remediation_text = "\n".join(rem_lines)[:4000]

    # ── Mitigating factors (heading variants: "Mitigating Factors",
    #    "Workarounds/ Mitigating Factors") ──
    mitigating_factors = ""
    mit_m = re.search(r"§[^\n]*Mitigating Factors[^\n]*\n(.*?)(?=\n§|\Z)", text, re.DOTALL | re.IGNORECASE)
    if mit_m:
        mitigating_factors = mit_m.group(1).strip()[:1000]

    # ── Exploitation + EOL notes ──
    exploitation_note = next(
        (l for l in main_lines
         if re.search(r"exploit", l, re.IGNORECASE)
         and re.search(r"observed|in the wild|aware of", l, re.IGNORECASE)),
        "",
    )
    eol_note = next(
        (l.lstrip("• ").strip() for l in main_lines
         if re.search(r"end[- ]of[- ]life|\bEOL\b", l, re.IGNORECASE)),
        "",
    )

    # ── References: vendor blog links from raw HTML ──
    references = sorted({
        u for u in re.findall(r'https?://www\.netscaler\.com/blog/[^\s"\'<>)]+', html)
    })

    result = {
        "found":              True,
        "ctx_id":             ctx_id,
        "advisory_url":       f"{_CITRIX_SSR_BASE}/{ctx_id}/cve.html",
        "title":              title,
        "severity":           severity,
        "cves":               cves,
        "affected_versions":  affected_versions,
        "fixed_versions":     fixed_versions,
        "remediation_text":   remediation_text,
        "mitigating_factors": mitigating_factors,
        "exploitation_note":  exploitation_note,
        "eol_note":           eol_note,
        "references":         references,
        "date_published":     date_published,
        "date_updated":       date_updated,
    }

    # Safety net: if structured parsing found nothing, return trimmed text so the
    # agent can still reason over the bulletin content
    if not (cves or affected_versions or fixed_versions):
        result["text_excerpt"] = text[:5000]

    return result


_BROADCOM_FIELD_LABELS = (
    "Description", "Known Attack Vectors", "Resolution", "Workarounds",
    "Additional Documentation", "Acknowledgements", "Notes",
)


def fetch_broadcom_advisory(advisory_url: str) -> dict:
    """Fetch and parse a Broadcom (VMware by Broadcom) VMSA security advisory.

    advisory_url: the NVD vendor-advisory reference, e.g.
    'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390'.
    The page serves full content without JavaScript.

    Returns: vmsa_id, synopsis, severity, cvss_range, impacted_products,
    cves [{cve_id, title, description, attack_vectors, resolution, workaround,
    notes, exploited_in_wild}], response_matrix [{product, version, running_on,
    cves, severity, fixed_version, workaround, docs}], references, dates,
    advisory_url. Returns {"found": False, "error": ...} on failure.
    """
    advisory_url = advisory_url.strip()

    try:
        resp = requests.get(
            advisory_url,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
        )
        if resp.status_code == 404:
            return {"found": False, "error": f"No Broadcom advisory at {advisory_url}"}
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        return {"found": False, "error": str(e)}

    # ── Tables: advisory metadata (2-col) + Response Matrix ──
    vmsa_id, severity, cvss_range, synopsis = "", "", "", ""
    issue_date, updated_on = "", ""
    cve_list: list[str] = []
    response_matrix: list[dict] = []

    for tbl_html in re.findall(r"<table[^>]*>(.*?)</table>", html, re.DOTALL | re.IGNORECASE):
        rows: list[list[str]] = []
        for row_html in re.findall(r"<tr[^>]*>(.*?)</tr>", tbl_html, re.DOTALL | re.IGNORECASE):
            cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row_html, re.DOTALL | re.IGNORECASE)
            cleaned = [_html_text(c) for c in cells]
            if any(cleaned):
                rows.append(cleaned)
        if not rows:
            continue

        # Advisory metadata table — 2 columns, keys like "Advisory ID:"
        if all(len(r) == 2 for r in rows):
            meta = {re.sub(r"[^a-z]", "", r[0].lower()): r[1].strip() for r in rows}
            if "advisoryid" in meta:
                vmsa_id    = meta.get("advisoryid", "")
                severity   = meta.get("severity", "").upper()
                cvss_range = meta.get("cvssvrange", meta.get("cvssv3range", meta.get("cvssrange", "")))
                synopsis   = meta.get("synopsis", "")
                issue_date = meta.get("issuedate", "")
                updated_on = meta.get("updatedon", "").split("(")[0].strip()
                cve_cell   = meta.get("cves", meta.get("cve", ""))
                cve_list   = re.findall(r"CVE-\d{4}-\d+", cve_cell)
                continue

        # Response Matrix — header contains "Fixed Version"
        hdr = [re.sub(r"[^a-z]", "", c.lower()) for c in rows[0]]
        if "fixedversion" in hdr:
            def _col(needle):
                for i, h in enumerate(hdr):
                    if needle in h:
                        return i
                return None
            i_prod, i_ver, i_run = _col("product"), _col("version"), _col("runningon")
            i_cve, i_sev, i_fix  = _col("cve"), _col("severity"), _col("fixedversion")
            i_wk, i_doc          = _col("workaround"), _col("documentation")
            for row in rows[1:]:
                def _cell(i):
                    return row[i].strip() if i is not None and i < len(row) else ""
                product = _cell(i_prod)
                if not product:
                    continue
                response_matrix.append({
                    "product":       product,
                    "version":       _cell(i_ver),
                    "running_on":    _cell(i_run),
                    "cves":          re.findall(r"CVE-\d{4}-\d+", _cell(i_cve)),
                    "severity":      _cell(i_sev),
                    "fixed_version": _cell(i_fix),
                    "workaround":    _cell(i_wk),
                    "docs":          _cell(i_doc),
                })

    # ── Flattened text for section parsing ──
    lines = _flatten_advisory_html(html)

    # ── Impacted products: bullets under "1. Impacted Products" ──
    impacted_products: list[str] = []
    collecting = False
    for line in lines:
        if line.startswith("§"):
            if re.search(r"Impacted Products", line, re.IGNORECASE):
                collecting = True
                continue
            if collecting:
                break
        elif collecting and line.startswith("•"):
            impacted_products.append(line.lstrip("• ").strip())

    # ── Per-CVE sections: "§ 3a. <title> (CVE-YYYY-NNNN)" ──
    cves: list[dict] = []
    section_starts: list[tuple[int, str, str]] = []  # (line idx, cve_id, title)
    for idx, line in enumerate(lines):
        if not line.startswith("§"):
            continue
        m = re.match(r"§\s*\d+[a-z]?\.\s*(.+?)\s*\((CVE-\d{4}-\d+)\)", line)
        if m:
            section_starts.append((idx, m.group(2), m.group(1)))

    for n, (start, cve_id, title) in enumerate(section_starts):
        end = section_starts[n + 1][0] if n + 1 < len(section_starts) else None
        if end is None:
            # Run until the next numbered section heading (e.g. "§ 4. References")
            end = next((i for i in range(start + 1, len(lines))
                        if lines[i].startswith("§")), len(lines))
        # Split section body into labelled fields
        fields: dict[str, list[str]] = {}
        current = None
        label_re = re.compile(
            r"^(" + "|".join(_BROADCOM_FIELD_LABELS) + r")\s*:\s*(.*)", re.IGNORECASE)
        for line in lines[start + 1:end]:
            lm = label_re.match(line.lstrip("• ").strip())
            if lm:
                current = lm.group(1).lower()
                fields[current] = [lm.group(2)] if lm.group(2).strip() else []
            elif current:
                fields[current].append(line.lstrip("• ").strip())

        def _field(key):
            return " ".join(fields.get(key, [])).strip()

        workaround = _field("workarounds")
        if workaround.lower().rstrip(".") == "none":
            workaround = ""
        notes = _field("notes")
        cves.append({
            "cve_id":            cve_id,
            "title":             title,
            "description":       _field("description")[:1500],
            "attack_vectors":    _field("known attack vectors")[:1000],
            "resolution":        _field("resolution")[:1000],
            "workaround":        workaround[:1500],
            "notes":             notes[:1000],
            "exploited_in_wild": bool(re.search(
                r"exploitation .{0,40}occurred in the wild", notes, re.IGNORECASE)),
        })

    if not cve_list:
        cve_list = [c["cve_id"] for c in cves]

    # ── References: techdocs / KB links from raw HTML ──
    references = []
    seen_refs: set = set()
    for u in re.findall(
            r'https?://(?:techdocs|knowledge)\.broadcom\.com/[^\s"\'<>)\]]+', html):
        u = u.rstrip(".,")
        if u not in seen_refs:
            seen_refs.add(u)
            references.append(u)
    references = references[:10]

    result = {
        "found":             True,
        "vmsa_id":           vmsa_id,
        "advisory_url":      advisory_url,
        "synopsis":          synopsis,
        "severity":          severity,
        "cvss_range":        cvss_range,
        "cve_list":          cve_list,
        "impacted_products": impacted_products,
        "cves":              cves,
        "response_matrix":   response_matrix,
        "references":        references,
        "date_published":    issue_date,
        "date_updated":      updated_on,
    }

    # Safety net: structured parse found nothing → return trimmed text
    if not (cves or response_matrix):
        text = "\n".join(lines)
        # Drop portal navigation noise before the advisory body if locatable
        body_m = re.search(r"VMSA-\d{4}-\d+", text)
        if body_m:
            text = text[body_m.start():]
        result["text_excerpt"] = text[:5000]

    return result


# ---------------------------------------------------------------------------
# Phase D — software package pipeline (supply chain)
# ---------------------------------------------------------------------------

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# User-facing ecosystem labels → OSV ecosystem names
_OSV_ECOSYSTEMS = {
    "npm":  "npm",
    "pypi": "PyPI",
    "pip":  "PyPI",
}


def query_package_vulns(ecosystem: str, package: str, version: str = "") -> dict:
    """Query OSV.dev for vulnerabilities AND malicious-package records affecting
    a package. With a version, returns only records affecting that version;
    without, returns the package's full known history.

    Compromise detection: OSV aggregates the OpenSSF malicious-packages feed —
    records with a MAL- prefix (or the 'malicious-package' related tag) mean the
    package itself was compromised/malware, not merely vulnerable.

    Returns per record: id, cve_aliases, is_malware, summary, severity/cvss,
    affected_ranges ({introduced, fixed}), fixed_versions, references (capped),
    published/modified dates.
    """
    eco = _OSV_ECOSYSTEMS.get(ecosystem.strip().lower())
    if not eco:
        return {"found": False,
                "error": f"Unsupported ecosystem '{ecosystem}' — use npm or pypi",
                "vulns": []}
    package = package.strip()
    # PyPI names are case/underscore-insensitive; OSV expects normalised form
    if eco == "PyPI":
        package = re.sub(r"[-_.]+", "-", package.lower())

    query: dict = {"package": {"name": package, "ecosystem": eco}}
    if version.strip():
        query["version"] = version.strip()

    records: list = []
    page_token = None
    try:
        for _ in range(3):  # max 3 pages — enough for any real package
            body = {**query, **({"page_token": page_token} if page_token else {})}
            resp = requests.post(_OSV_QUERY_URL, json=body, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            records.extend(data.get("vulns", []))
            page_token = data.get("next_page_token")
            if not page_token:
                break
    except Exception as e:
        return {"found": False, "error": str(e), "vulns": []}

    vulns = []
    for rec in records:
        rec_id   = rec.get("id", "")
        aliases  = rec.get("aliases", [])
        cve_aliases = sorted({a for a in aliases + [rec_id] if a.startswith("CVE-")})
        # Malware detection: MAL- records (OpenSSF feed) OR GitHub's own malware
        # advisories — GHSA-prefixed, not always MAL-aliased, but reliably named
        # "Malicious code in <pkg>" / "... contains malware"
        summary_text = (rec.get("summary") or rec.get("details", ""))
        is_malware = (
            rec_id.startswith("MAL-")
            or any(a.startswith("MAL-") for a in aliases)
            or bool(re.match(r"\s*malicious (code|package)", summary_text, re.IGNORECASE))
            or "contains malware" in summary_text.lower()
            or "embedded malware" in summary_text.lower()
        )

        # Severity — prefer CVSS v3 vector if present
        cvss_vector, severity_score = "", None
        for sev in rec.get("severity", []):
            if sev.get("type", "").startswith("CVSS"):
                cvss_vector = sev.get("score", "")
                break
        db_specific = rec.get("database_specific", {})
        severity_label = (db_specific.get("severity") or "").upper()

        # Affected ranges + fixed versions for THIS package
        affected_ranges: list = []
        fixed_versions: list = []
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("name", "").lower() != package.lower():
                continue
            for rng in aff.get("ranges", []):
                cur: dict = {}
                for ev in rng.get("events", []):
                    if "introduced" in ev:
                        cur = {"introduced": ev["introduced"]}
                    elif "fixed" in ev:
                        cur["fixed"] = ev["fixed"]
                        fixed_versions.append(ev["fixed"])
                        affected_ranges.append(cur)
                        cur = {}
                    elif "last_affected" in ev:
                        cur["last_affected"] = ev["last_affected"]
                        affected_ranges.append(cur)
                        cur = {}
                if cur:
                    affected_ranges.append(cur)
            for v in aff.get("versions", [])[:5]:
                affected_ranges.append({"version": v})

        vulns.append({
            "id":              rec_id,
            "cve_aliases":     cve_aliases,
            "ghsa_aliases":    sorted({a for a in aliases + [rec_id] if a.startswith("GHSA-")}),
            "is_malware":      is_malware,
            "summary":         (rec.get("summary") or rec.get("details", ""))[:300],
            "severity":        severity_label,
            "cvss_vector":     cvss_vector,
            "affected_ranges": affected_ranges[:8],
            "fixed_versions":  sorted(set(fixed_versions))[:8],
            "references":      [r.get("url") for r in rec.get("references", [])[:4] if r.get("url")],
            "published":       (rec.get("published") or "")[:10],
            "modified":        (rec.get("modified") or "")[:10],
        })

    # Malware records first, then by published date descending
    vulns.sort(key=lambda v: (not v["is_malware"], v["published"]), reverse=False)
    vulns.sort(key=lambda v: v["published"], reverse=True)
    vulns.sort(key=lambda v: not v["is_malware"])

    return {
        "found":          len(vulns) > 0,
        "ecosystem":      eco,
        "package":        package,
        "queried_version": version.strip() or None,
        "total":          len(vulns),
        "malware_count":  sum(1 for v in vulns if v["is_malware"]),
        "vulns":          vulns[:25],
    }


def query_package_registry(ecosystem: str, package: str) -> dict:
    """Fetch package health metadata from the npm or PyPI registry.

    Health signals for the compromise/abandonment verdict: does the package
    exist, latest version, deprecation flag, last publish date, maintainer
    count, repository link. A package that doesn't exist (typo?) or was
    recently transferred/deprecated is itself a finding.
    """
    eco = _OSV_ECOSYSTEMS.get(ecosystem.strip().lower())
    if not eco:
        return {"found": False, "error": f"Unsupported ecosystem '{ecosystem}'"}
    package = package.strip()

    try:
        if eco == "npm":
            resp = requests.get(
                f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@/')}",
                timeout=15)
            if resp.status_code == 404:
                return {"found": False, "ecosystem": "npm", "package": package,
                        "error": "Package not found in npm registry — check spelling (typosquat risk)"}
            resp.raise_for_status()
            data = resp.json()
            latest = data.get("dist-tags", {}).get("latest", "")
            latest_meta = data.get("versions", {}).get(latest, {})
            times = data.get("time", {})
            return {
                "found":           True,
                "ecosystem":       "npm",
                "package":         data.get("name", package),
                "latest_version":  latest,
                "deprecated":      bool(latest_meta.get("deprecated")),
                "deprecation_msg": latest_meta.get("deprecated") or "",
                "description":     (data.get("description") or "")[:200],
                "last_publish":    (times.get(latest) or times.get("modified", ""))[:10],
                "created":         (times.get("created") or "")[:10],
                "maintainers":     len(data.get("maintainers", [])),
                "repository":      (data.get("repository") or {}).get("url", "")
                                   if isinstance(data.get("repository"), dict)
                                   else str(data.get("repository") or ""),
                "version_count":   len(data.get("versions", {})),
            }

        # PyPI
        resp = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=15)
        if resp.status_code == 404:
            return {"found": False, "ecosystem": "PyPI", "package": package,
                    "error": "Package not found on PyPI — check spelling (typosquat risk)"}
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        latest = info.get("version", "")
        releases = data.get("releases", {})
        last_publish = ""
        files = releases.get(latest) or data.get("urls", [])
        if files:
            last_publish = (files[0].get("upload_time_iso_8601") or "")[:10]
        return {
            "found":           True,
            "ecosystem":       "PyPI",
            "package":         info.get("name", package),
            "latest_version":  latest,
            "deprecated":      bool(info.get("yanked")),
            "deprecation_msg": info.get("yanked_reason") or "",
            "description":     (info.get("summary") or "")[:200],
            "last_publish":    last_publish,
            "created":         "",
            "maintainers":     len((info.get("maintainer") or info.get("author") or "").split(",")) if (info.get("maintainer") or info.get("author")) else 0,
            "repository":      (info.get("project_urls") or {}).get("Source", "") or info.get("home_page", "") or "",
            "version_count":   len(releases),
        }
    except Exception as e:
        return {"found": False, "ecosystem": eco, "package": package, "error": str(e)}


_SOCKET_BASE = "https://api.socket.dev/v0"
_socket_org_slug: str | None = None   # discovered once per process


def _socket_headers() -> dict | None:
    key = os.getenv("SOCKET_API_KEY", "")
    if not key:
        return None
    import base64
    return {"Authorization": "Basic " + base64.b64encode(f"{key}:".encode()).decode()}


def fetch_socket_score(ecosystem: str, package: str, version: str) -> dict:
    """Fetch Socket.dev supply-chain risk analysis for an exact package version.

    Socket performs behavioral/static analysis of the artifact currently in the
    registry: install scripts, network/filesystem/env access, eval use,
    obfuscation, maintainer churn — risk signals that exist BEFORE any incident
    is recorded. It does NOT report historical compromises of purged artifacts
    (use query_package_vulns/OSV for incident history).

    QUOTA: one call costs ~100 of 500 units per refresh window — the function
    pre-checks quota (free) and declines politely when nearly exhausted.

    Returns: scores {overall, supplyChain, quality, maintenance, vulnerability,
    license} (0-1 floats), alerts [{type, severity, category, cve_id, ghsa_id,
    cvss_score, description}], counts by category, quota_remaining.
    """
    headers = _socket_headers()
    if headers is None:
        return {"found": False, "error": "SOCKET_API_KEY not configured"}

    eco = (ecosystem or "").strip().lower()
    eco = {"pip": "pypi"}.get(eco, eco)
    if eco not in ("npm", "pypi"):
        return {"found": False, "error": f"Unsupported ecosystem '{ecosystem}'"}
    package, version = package.strip(), version.strip()
    if not version:
        return {"found": False,
                "error": "Socket lookup needs an exact version — ask the user or use the registry's latest"}

    global _socket_org_slug
    try:
        # ── Quota pre-check (free) ──
        q = requests.get(f"{_SOCKET_BASE}/quota", headers=headers, timeout=10).json()
        if q.get("quota", 0) < 110:
            return {"found": False,
                    "error": f"Socket quota nearly exhausted ({q.get('quota')} units left, "
                             f"refreshes {q.get('nextWindowRefresh', 'soon')}) — skipping to preserve budget"}

        # ── Org slug (cached per process) ──
        if not _socket_org_slug:
            r = requests.get(f"{_SOCKET_BASE}/organizations", headers=headers, timeout=10)
            r.raise_for_status()
            orgs = r.json().get("organizations", {})
            first = next(iter(orgs.values()), {}) if isinstance(orgs, dict) else (orgs[0] if orgs else {})
            _socket_org_slug = first.get("slug")
            if not _socket_org_slug:
                return {"found": False, "error": "No Socket organization found for this API key"}

        # ── Batch PURL lookup (successor of batchpackagefetch) ──
        purl = f"pkg:{eco}/{package}@{version}"
        resp = requests.post(
            f"{_SOCKET_BASE}/orgs/{_socket_org_slug}/purl",
            headers={**headers, "Content-Type": "application/json"},
            params={"alerts": "true", "compact": "false"},
            json={"components": [{"purl": purl}]},
            timeout=30,
        )
        resp.raise_for_status()
    except Exception as e:
        return {"found": False, "error": str(e)}

    # NDJSON: one artifact per line
    artifacts = []
    for line in resp.text.strip().splitlines():
        if line.strip():
            try:
                artifacts.append(json.loads(line))
            except ValueError:
                pass
    if not artifacts:
        return {"found": False,
                "error": f"Socket has no analysis for {purl} (version may have been purged from the registry)"}

    art = artifacts[0]
    sev_map = {"middle": "medium"}  # Socket quirk

    alerts = []
    for al in art.get("alerts", []):
        props = al.get("props", {}) or {}
        cvss = props.get("cvss", {}) or {}
        alerts.append({
            "type":        al.get("type", ""),
            "severity":    sev_map.get(al.get("severity", ""), al.get("severity", "")),
            "category":    al.get("category", ""),
            "cve_id":      props.get("cveId", ""),
            "ghsa_id":     props.get("ghsaId", ""),
            "cvss_score":  cvss.get("score"),
            "description": (props.get("description") or "")[:400],
        })
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    alerts.sort(key=lambda a: sev_rank.get(a["severity"], 4))

    counts: dict = {}
    for a in alerts:
        counts[a["category"]] = counts.get(a["category"], 0) + 1

    scores = art.get("score") or {}
    try:
        quota_left = requests.get(f"{_SOCKET_BASE}/quota", headers=headers, timeout=10).json().get("quota")
    except Exception:
        quota_left = None

    return {
        "found":           True,
        "purl":            purl,
        "package":         art.get("name", package),
        "version":         art.get("version", version),
        "ecosystem":       eco,
        "scores":          {k: scores.get(k) for k in
                            ("overall", "supplyChain", "quality", "maintenance",
                             "vulnerability", "license") if k in scores},
        "alerts":          alerts[:20],
        "alert_counts":    counts,
        "authors":         art.get("author", []),
        "package_url":     f"https://socket.dev/{eco}/package/{package}/overview/{version}",
        "quota_remaining": quota_left,
    }


IOC_SEARCH_TYPE = "auto"  # probe v5 (2026-06-12): auto 17 IOCs/$0.007 with 0
                          # cross-CVE contamination; deep-lite 21/$0.012; deep
                          # 15/$0.012. auto wins on cost, deep-lite documented
                          # as the "more IOCs" alternative.

_IOC_TYPES = {"ip", "domain", "url", "hash", "filepath", "command", "ttp", "yara", "sigma"}
# url + command added 2026-06-12 (typing probe: a hard enum stopped artifacts —
# payloads/commands/URLs — leaking into ttp; 0 enum violations, 0 real leakage).
_MITRE_RE = _re.compile(r"\bT\d{4}(?:\.\d{3})?\b")  # ATT&CK technique / sub-technique


def _ioc_output_schema(cve_id: str) -> dict:
    """Best-practices compliant (depth ≤2, ≤10 props, no citation fields —
    grounding is automatic, descriptions on every field)."""
    return {
        "type": "object",
        "required": ["iocs"],
        "properties": {
            "iocs": {
                "type": "array",
                "description": f"Indicators of compromise attributed to exploitation of {cve_id}",
                "items": {
                    "type": "object",
                    "required": ["type", "value"],
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["ip", "domain", "url", "hash", "filepath",
                                     "command", "ttp", "yara", "sigma"],
                            "description": "The indicator category. Use `url` for URL/URI "
                                           "request paths, `command` for shell commands or "
                                           "tooling invocations, and `ttp` ONLY for an observed "
                                           "adversary behaviour or technique — NEVER for a raw "
                                           "payload, command, URL, or file (use url/command/filepath).",
                        },
                        "value": {
                            "type": "string",
                            "description": "The indicator value itself (IP, hash, MITRE technique ID, rule name, path)",
                        },
                        "context": {
                            "type": "string",
                            "description": "Brief context: what the indicator is and how it relates to this CVE",
                        },
                        "reference": {
                            "type": "string",
                            "description": "URL of the page where this indicator is published — "
                                           "e.g. the GitHub file or vendor blog hosting a YARA/Sigma "
                                           "rule, or the advisory documenting a hash/IP. Omit if unknown.",
                        },
                        "mitre_id": {
                            "type": "string",
                            "description": "For ttp items ONLY: the canonical MITRE ATT&CK technique "
                                           "ID (e.g. T1190 or T1059.001) IF AND ONLY IF one clearly and "
                                           "unambiguously applies to the described behaviour. Omit "
                                           "entirely if the item is a raw payload/command/indicator "
                                           "rather than a technique, or if no single technique fits. "
                                           "Do not guess — a wrong ID is worse than none.",
                        },
                    },
                },
            }
        },
    }


def _grounding_sources(grounding) -> list:
    """Defensively walk output.grounding (shape not contractually pinned) and
    collect every {url, title?} pair, deduplicated by URL, capped at 12."""
    found: list = []
    seen: set = set()

    def walk(node):
        if isinstance(node, dict):
            url = node.get("url")
            if isinstance(url, str) and url.startswith("http") and url not in seen:
                seen.add(url)
                title = node.get("title")
                found.append({"url": url,
                              "title": title if isinstance(title, str) else url})
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(grounding)
    return found[:12]


def search_iocs(cve_id: str) -> dict:
    """IOC pull via /search outputSchema.

    One call: Exa searches, synthesises {iocs: [...]} per the schema, and
    returns output.grounding — the pages that backed the IOCs, which become
    the Sources list (so a source row exists only because it contributed,
    killing cross-CVE reference pollution structurally). Replaces the former
    two-query search + parallel Haiku per-page extraction (probe v5: more
    IOCs, 0 contamination, ~half the cost).

    Returns {"found", "iocs": [{type, value, context}], "sources": [{url, title}]}.
    """
    api_key = os.getenv("EXA_API_KEY", "")
    if not api_key:
        return {"found": False, "error": "EXA_API_KEY not configured",
                "iocs": [], "sources": []}

    try:
        resp = requests.post(
            EXA_API_BASE,
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            json={
                "query": f"{cve_id} indicators of compromise IOCs threat intelligence",
                "type": IOC_SEARCH_TYPE,
                "numResults": 8,
                "outputSchema": _ioc_output_schema(cve_id),
                "systemPrompt": (
                    f"Only include indicators of compromise explicitly attributed "
                    f"to {cve_id}. Exclude indicators associated with other CVEs, "
                    f"generic malware not tied to this vulnerability, and "
                    f"example/placeholder values. Prefer official advisories and "
                    f"reputable threat intelligence reporting."
                ),
                "contents": {"highlights": True},
            },
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"found": False, "error": str(e), "iocs": [], "sources": []}

    output = data.get("output") or {}
    content = output.get("content")
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except Exception:
            content = {}
    raw_iocs = (content or {}).get("iocs", []) if isinstance(content, dict) else []

    iocs = []
    for i in raw_iocs:
        if not isinstance(i, dict):
            continue
        itype = (i.get("type") or "").strip().lower()
        value = (i.get("value") or "").strip()
        if itype in _IOC_TYPES and value:
            ref = (i.get("reference") or "").strip()
            # mitre_id (ttp only): Exa-inline mapper (probe 2026-06-12 — chosen over a
            # Haiku pass for higher precision). Validate to a clean T#### shape; a
            # missing/invalid id leaves the technique non-clickable, never mis-linked.
            mmatch = _MITRE_RE.search((i.get("mitre_id") or "").upper())
            iocs.append({"type": itype, "value": value,
                         "context": (i.get("context") or "").strip() or None,
                         "reference": ref if ref.startswith(("http://", "https://")) else None,
                         "mitre_id": mmatch.group(0) if mmatch else None})

    return {
        "found":   bool(iocs),
        "iocs":    iocs,
        "sources": _grounding_sources(output.get("grounding")),
    }


def search_news(query: str, start_published_date: str | None = None,
                num_results: int = 10, search_type: str = "auto",
                system_prompt: str | None = None,
                include_domains: list | None = None) -> dict:
    """Exa dated news search for CVE/package monitoring (Phase G).

    NOT an agent tool — triggered only by the monitor scheduler or the War Room
    'Check now' button, never by Sonnet (decided 2026-06-11). Lives outside the
    sources/ registry, same pattern as search_iocs + the /iocs routes.

    start_published_date: ISO date (YYYY-MM-DD) — articles on or after it.

    G5 probe findings (v1+v2, 2026-06-12, CVE-2025-5777):
      - category:"news" is actively harmful for CVE queries (0/10 on-topic vs
        4/10 without it) — NOT sent;
      - type:"keyword" returns 0 results with or without category — unusable;
        default is "auto" (best probe performer);
      - even "auto" returns lookalike CVE IDs (CVE-2025-57790 for -5777) and
        leaks pre-window dates — results are RAW; monitoring.poll_monitor
        applies the boundary-aware relevance + date post-filter. Do not
        consume this output unfiltered.
      - snippet capped generously (1500 chars) so the mention check has
        recall beyond the title.
      - system_prompt: /search's `systemPrompt` field — probe v4 verdict
        (2026-06-12): NO gain (4/5 baseline vs 4/5 with a leak / 3/5), so
        callers don't send it; kept for future probes. Bonus v4 finding:
        relevance is front-loaded — 5 results = 4/5 on-topic vs 4/10 at 10.
    """
    api_key = os.getenv("EXA_API_KEY", "")
    if not api_key:
        return {"found": False, "error": "EXA_API_KEY not configured", "results": []}

    payload = {
        "query": query,
        "type": search_type,
        "numResults": num_results,
        "contents": {"text": {"maxCharacters": 1500}},
    }
    if start_published_date:
        payload["startPublishedDate"] = start_published_date
    if system_prompt:
        payload["systemPrompt"] = system_prompt
    # NB feed fallback (HeroDevs has no RSS): restrict the search to the blog's
    # own domain so Exa returns that site's posts rather than the open web.
    if include_domains:
        payload["includeDomains"] = include_domains

    try:
        resp = requests.post(
            EXA_API_BASE,
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
        resp.raise_for_status()
    except Exception as e:
        return {"found": False, "error": str(e), "results": []}

    results = []
    for r in resp.json().get("results", []):
        url = r.get("url", "")
        if not url:
            continue
        results.append({
            "title":          r.get("title", ""),
            "url":            url,
            "snippet":        (r.get("text") or "")[:1500],
            "published_date": (r.get("publishedDate") or "")[:10],
        })
    return {"found": bool(results), "results": results}


def search_package_intel(ecosystem: str, package: str,
                         version: str | None = None) -> dict:
    """Exa fresh-web search for compromise/advisory reporting on a specific package.

    Modeled on search_news (plain results list), NOT search_iocs.
    - POST to EXA_API_BASE, type:"auto", contents.text capped ~1500 chars.
    - Returns {found, results:[{title, url, snippet, published_date}]}.
    - Missing EXA_API_KEY → graceful {found:False, error:..., results:[]}.

    WHY an agent tool (unlike search_news):
    search_news is scheduler-only — it runs on a fixed cadence for a known
    entity and its output is always post-filtered before storage. Here the
    *relevance judgement is Sonnet's*: Sonnet calls this during a live package
    analysis, reads the snippets, and cites only the URLs that are genuinely
    on-topic. The post-filter burden shifts from code to the model — appropriate
    because Sonnet can read the content, whereas the scheduler cannot. Keeping
    this outside search_news also avoids contaminating the monitor-news pipeline
    with on-demand agent calls (different consumers, different contracts).

    Query targets compromise/advisory reporting for this exact package and
    excludes generic hits. The lookalike-package relevance burden is on Sonnet's
    citation choice (per ADR, same as CVE-5777/-57790 lesson): results flow
    through Sonnet which reads the content, so a post-filter here would be
    redundant and could discard genuinely useful write-ups.
    """
    api_key = os.getenv("EXA_API_KEY", "")
    if not api_key:
        return {"found": False, "error": "EXA_API_KEY not configured", "results": []}

    eco_label = ecosystem.lower().replace("pip", "pypi")
    ver_clause = f" {version}" if version else ""
    query = (
        f"security advisory compromise malware supply-chain attack "
        f"{eco_label} package {package}{ver_clause}"
    )

    try:
        resp = requests.post(
            EXA_API_BASE,
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            json={
                "query": query,
                "type": "auto",
                "numResults": 8,
                "contents": {"text": {"maxCharacters": 1500}},
            },
            timeout=20,
        )
        resp.raise_for_status()
    except Exception as e:
        return {"found": False, "error": str(e), "results": []}

    results = []
    for r in resp.json().get("results", []):
        url = r.get("url", "")
        if not url:
            continue
        results.append({
            "title":          r.get("title", ""),
            "url":            url,
            "snippet":        (r.get("text") or "")[:1500],
            "published_date": (r.get("publishedDate") or "")[:10],
        })
    return {"found": bool(results), "results": results}

