"""search_cves_by_product — NVD keyword search for a vendor/product."""
from tools import search_cves_by_product

NAME  = "search_cves_by_product"
ORDER = 40

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Search the NVD for CVEs affecting a specific vendor and product. "
        "Use this when the user asks about CVE exposure, wants to scan their infrastructure, "
        "or asks what vulnerabilities affect a product they run. "
        "Returns up to 20 of the most recently published CVEs with CVSS scores, severities, "
        "descriptions, and structured version ranges (versionStartIncluding / versionEndExcluding) "
        "where NVD has them. "
        "Use the version ranges alongside the user's known version (from Known Infrastructure) "
        "to assess whether they are likely affected — if their version falls within a range they are "
        "affected; if no version is recorded, flag the uncertainty explicitly. "
        "Do NOT use this to look up a specific CVE ID — use parse_nvd_cve for that. "
        "Call this once per distinct product the user wants assessed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vendor": {
                "type": "string",
                "description": "Vendor name (e.g. 'Apache', 'Microsoft', 'Google')",
            },
            "product": {
                "type": "string",
                "description": "Product name (e.g. 'HTTP Server', 'Exchange Server', 'Chrome')",
            },
        },
        "required": ["vendor", "product"],
    },
}

# Bullet appears AFTER fetch_advisories in the prompt — preserved from the
# pre-refactor prompt ordering.
PROMPT_ORDER = 130
PROMPT = (
    "- **search_cves_by_product** — Call this when the user asks about CVE exposure for their "
    "infrastructure, wants a scan, or asks \"what CVEs affect X\". Call once per product. Returns up to "
    "20 recent CVEs with CVSS scores and version ranges. Use the version ranges alongside the user's "
    "known version from Known Infrastructure to assess applicability: if their version falls within a "
    "range they are likely affected; if the range covers all versions they are definitely affected; if "
    "no version is recorded, present the CVEs but flag that applicability cannot be confirmed without "
    "a version. Let the user decide which CVEs to investigate further — do not automatically call "
    "parse_nvd_cve for all results. Honour severity preferences: if the user asks for critical only, "
    "filter to CRITICAL; if they ask for high and above, include HIGH and CRITICAL; default to showing "
    "HIGH and CRITICAL and summarising any MEDIUM findings briefly."
)


def fetch(vendor: str, product: str) -> dict:
    return search_cves_by_product(vendor, product)
