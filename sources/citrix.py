"""fetch_citrix_advisory — Citrix/CSG bulletins via the SSR endpoint."""
from tools import fetch_citrix_advisory

NAME  = "fetch_citrix_advisory"
ORDER = 80

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch the official Citrix / Cloud Software Group security bulletin for a CVE. "
        "Returns structured data: per-CVE details (description, preconditions for "
        "exploitability, CWE, CVSS v4 score and vector), affected version branches, "
        "fixed versions, post-upgrade remediation steps, mitigating factors, "
        "exploitation-in-the-wild status, and EOL warnings for unsupported versions. "
        "Call this when the user explicitly asks for advisories, vendor guidance, "
        "or patch availability AND the CVE affects Citrix / NetScaler products "
        "(NetScaler ADC, NetScaler Gateway, NetScaler Console, Citrix Virtual Apps "
        "and Desktops, XenServer, Citrix Workspace, uberAgent, etc.). "
        "The advisory URL comes from NVD references — look for a support.citrix.com "
        "URL (any format containing a CTX article ID, e.g. "
        "support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420). "
        "The preconditions field matters: many NetScaler CVEs only apply with specific "
        "configurations (e.g. Gateway or AAA virtual server) — cross-check against "
        "what is known about the user's deployment."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "advisory_url": {
                "type": "string",
                "description": (
                    "Citrix advisory URL from NVD references — any URL containing a "
                    "CTX article ID, e.g. 'https://support.citrix.com/support-home/"
                    "kbsearch/article?articleNumber=CTX693420'. "
                    "Also accepts a bare CTX ID like 'CTX693420'."
                ),
            },
        },
        "required": ["advisory_url"],
    },
}

PROMPT = (
    "- **fetch_citrix_advisory** — Call this when the user explicitly asks for advisories, vendor "
    "guidance, patch availability, or workarounds AND the CVE affects Citrix / NetScaler products "
    "(NetScaler ADC, NetScaler Gateway, NetScaler Console, Citrix Virtual Apps and Desktops, "
    "XenServer, Citrix Workspace, etc.). Pass the advisory URL from NVD references (a "
    "support.citrix.com URL containing a CTX article ID). Pay attention to the preconditions field — "
    "many NetScaler CVEs only apply with specific configurations (Gateway, AAA virtual server); ask "
    "the user about their deployment configuration if unknown. Always flag EOL versions explicitly."
)


def fetch(advisory_url: str) -> dict:
    return fetch_citrix_advisory(advisory_url)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        links.append({
            "url":         result["advisory_url"],
            "source":      "citrix",
            "type":        "advisory",
            "title":       result.get("ctx_id", ""),
            "description": result.get("title", ""),
        })
        for ref_url in result.get("references", []):
            links.append({
                "url":         ref_url,
                "source":      "citrix",
                "type":        "reference",
                "title":       "NetScaler Blog",
                "description": ref_url.rstrip("/").split("/")[-1].replace("-", " "),
            })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions, blobs = [], []
    if result.get("found"):
        # Fixed versions → discrete patch items
        for ver in result.get("fixed_versions", []):
            actions.append({"text": f"Upgrade to {ver}",
                            "source": "citrix", "type": "patch"})
        # EOL warning → discrete admin item
        if result.get("eol_note"):
            actions.append({"text": result["eol_note"],
                            "source": "citrix", "type": "admin"})
        # Remediation section (post-upgrade commands, notes) → Haiku decomposition
        if result.get("remediation_text"):
            blobs.append((result["remediation_text"], "citrix"))
        # Mitigating factors — skip the common "None." placeholder
        mit = (result.get("mitigating_factors") or "").strip()
        if mit and mit.lower().rstrip(".") != "none":
            blobs.append((mit, "citrix"))
    return actions, blobs
