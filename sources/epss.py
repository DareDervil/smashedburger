"""query_epss — FIRST EPSS exploitation probability."""
import db
import context as ctx
from tools import query_epss

NAME  = "query_epss"
ORDER = 20

TOOL_DEF = {
    "name": NAME,
    "description": "Fetch EPSS (Exploit Prediction Scoring System) scores from the FIRST API "
    "for one or more CVE IDs. "
    "EPSS measures the probability (0–1) that a CVE will be exploited in the wild within the "
    "next 30 days, updated daily. The percentile reflects how the CVE ranks relative to all "
    "other scored CVEs (e.g. 0.99 means it scores higher than 99% of CVEs). "
    "EPSS is a threat metric, not a risk score — use it alongside CVSS: "
    "high CVSS + high EPSS means patch immediately; high CVSS + low EPSS means monitor; "
    "low CVSS + high EPSS means investigate active exploitation despite low severity. "
    "Use this whenever the user asks about exploitation likelihood, EPSS score, or wants "
    "to prioritise remediation across multiple CVEs.",
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_ids": {
                "oneOf": [
                    {"type": "string",  "description": "A single CVE ID, e.g. 'CVE-2021-44228'"},
                    {"type": "array", "items": {"type": "string"},
                     "description": "A list of CVE IDs for a batch lookup"},
                ],
                "description": "One CVE ID or a list of CVE IDs to look up.",
            }
        },
        "required": ["cve_ids"],
    },
    "input_examples": [
        {"cve_ids": "CVE-2021-44228"},
        {"cve_ids": ["CVE-2021-44228", "CVE-2021-45046"]},
    ],
}

PROMPT = (
    "- **query_epss** — Call this alongside parse_nvd_cve. Returns exploitation probability and "
    "percentile. Always interpret CVSS and EPSS together: high CVSS + high EPSS = patch immediately; "
    "high CVSS + low EPSS = prioritise by exposure; low CVSS + high EPSS = investigate active exploitation."
)


def fetch(cve_ids) -> dict:
    result = query_epss(cve_ids)
    # Persist EPSS scores so the War Room panel can show them without re-fetching.
    # EPSS is updated daily by FIRST so we always overwrite with the latest value.
    for item in result.get("results", []):
        cve_id = item.get("cve")
        if cve_id:
            db.store_epss(cve_id, item["epss_score"], item["percentile"])
    return result
