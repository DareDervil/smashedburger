"""add_to_infrastructure — Sonnet passive discovery. Not an external
source; records ownership-language findings into the 3-table infra hierarchy."""
import re
import db
import context as ctx

NAME  = "add_to_infrastructure"
ORDER = 30

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Record a product or vendor as part of the user's environment. "
        "Call this whenever the user uses ownership language — 'our', 'we use', 'we run', "
        "'we have', 'we're patching', 'our Cisco', 'our Apache server' — that implies "
        "the product is part of their infrastructure. "
        "Add what you know: vendor is required at minimum; product and version are optional. "
        "Do not call this for hypothetical or generic examples. "
        "After calling this, continue your reply naturally — mention it briefly at most."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vendor": {
                "type": "string",
                "description": "Vendor or manufacturer name (e.g. 'Cisco', 'Apache', 'Microsoft')",
            },
            "product": {
                "type": "string",
                "description": "Product name if mentioned (e.g. 'Firewall', 'Log4j', 'Exchange Server'). Omit if not stated.",
            },
            "version": {
                "type": "string",
                "description": "Version string if mentioned (e.g. '2.14.1', '15.2'). Omit if not stated.",
            },
            "category": {
                "type": "string",
                "enum": ["software_library", "operating_system", "network", "application", "other"],
                "description": "Product category: 'network' for routers/firewalls/switches, 'operating_system' for OS/distros, 'software_library' for libraries/frameworks, 'application' for browsers/desktop apps/office suites.",
            },
        },
        "required": ["vendor"],
    },
}

# ── Vendor name normalisation ─────────────────────────────────────────────────
# Canonical names keyed by lowercase + all non-alphanumeric stripped.
# The model frequently passes website URLs or legal entity names; this maps them
# to the one true display name stored in the DB.
_CANONICAL: dict[str, str] = {
    "apache":                   "Apache Software Foundation",
    "apachesoftware":           "Apache Software Foundation",
    "apachesoftwarefoundation": "Apache Software Foundation",
    "microsoft":                "Microsoft",
    "microsoftcorporation":     "Microsoft",
    "google":                   "Google",
    "googlellc":                "Google",
    "alphabet":                 "Google",
    "oracle":                   "Oracle",
    "oraclecorporation":        "Oracle",
    "cisco":                    "Cisco",
    "ciscosystems":             "Cisco",
    "paloalto":                 "Palo Alto Networks",
    "paloaltonetworks":         "Palo Alto Networks",
    "fortinet":                 "Fortinet",
    "juniper":                  "Juniper Networks",
    "junipernetworks":          "Juniper Networks",
    "vmware":                   "VMware",
    "broadcom":                 "Broadcom",
    "ibm":                      "IBM",
    "redhat":                   "Red Hat",
    "canonical":                "Canonical",
    "debian":                   "Debian",
    "suse":                     "SUSE",
    "amazon":                   "Amazon",
    "amazonwebservices":        "Amazon Web Services",
    "aws":                      "Amazon Web Services",
    "nginx":                    "NGINX",
    "f5":                       "F5",
    "f5networks":               "F5",
    "splunk":                   "Splunk",
    "elastic":                  "Elastic",
    "hashicorp":                "HashiCorp",
    "crowdstrike":              "CrowdStrike",
    "sentinelone":              "SentinelOne",
    "openssl":                  "OpenSSL",
    "mozilla":                  "Mozilla",
    "mozillafoundation":        "Mozilla",
    "wordpress":                "WordPress",
    "automattic":               "Automattic",
    "atlassian":                "Atlassian",
    "github":                   "GitHub",
    "gitlab":                   "GitLab",
    "docker":                   "Docker",
    "linux":                    "Linux Kernel",
    "linuxkernel":              "Linux Kernel",
    "spring":                   "Spring (VMware)",
    "springframework":          "Spring (VMware)",
}

_RE_URL_PREFIX  = re.compile(r'^https?://(www\.)?', re.IGNORECASE)
_RE_TLD_SUFFIX  = re.compile(r'\.(com|org|net|io|dev|co|gov|edu)(/.*)?$', re.IGNORECASE)
_RE_LEGAL       = re.compile(
    r'\s*(,\s*)?(Inc\.?|LLC\.?|Corp\.?|Ltd\.?|GmbH|S\.A\.?|PLC|AG|B\.V\.)\s*$',
    re.IGNORECASE,
)


def _normalize_vendor(raw: str) -> str:
    """Clean a vendor string before storage.

    Pipeline:
      1. Strip URL scheme / www  — model sometimes passes the vendor website
      2. Strip TLD suffix (.com, .org, …)
      3. Strip legal suffixes (Inc., LLC, …)
      4. Canonical lookup — maps common abbreviations/variations to one name
      5. Title-case fallback for anything not in the table

    Security note: normalising here (not in db.py) keeps the DB layer dumb and
    testable; the source layer is the right boundary for LLM output sanitisation.
    """
    name = _RE_URL_PREFIX.sub("", raw.strip())
    name = _RE_TLD_SUFFIX.sub("", name).strip()
    name = _RE_LEGAL.sub("", name).strip()
    key  = re.sub(r"[^a-z0-9]", "", name.lower())
    return _CANONICAL.get(key, name.title() if name == name.lower() else name)


def fetch(vendor: str, product: str = "", version: str = "", category: str = "other") -> dict:
    """Sonnet calls this when it detects ownership language in the conversation."""
    if not vendor.strip():
        return {"ok": False, "error": "vendor required"}
    vendor    = _normalize_vendor(vendor)
    conv_id   = getattr(ctx.current_conv, "conv_id", "") or None
    vendor_id = db.upsert_vendor(vendor)
    product_id = None
    if product.strip():
        product_id = db.upsert_product(vendor_id, product, category or "other",
                                       conv_id=conv_id)
    # Block LLM-hallucinated non-versions that would pollute the graph.
    _VERSION_BLOCKLIST = {"", "unknown", "n/a", "na", "latest", "various",
                          "all", "any", "multiple", "unspecified", "tbd", "none"}
    if product_id and version.strip() and version.strip().lower() not in _VERSION_BLOCKLIST:
        db.upsert_version(product_id, version, conv_id)
    return {"ok": True, "vendor": vendor, "product": product, "version": version}
