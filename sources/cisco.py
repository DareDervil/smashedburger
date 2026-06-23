"""fetch_cisco_advisory — Cisco PSIRT via OpenVuln API (OAuth2, key-gated)."""
from tools import fetch_cisco_advisory

NAME  = "fetch_cisco_advisory"
ORDER = 60

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch Cisco PSIRT advisories for a CVE via the Cisco OpenVuln API. "
        "Returns one or more matching advisories, each with: advisory ID, title, "
        "Security Impact Rating (SIR: Critical/High/Medium/Low), CVSS base score "
        "and vector, summary, workaround, affected product list, fixed versions, "
        "Cisco bug IDs, and publication URL. "
        "Call this when the user explicitly asks for advisories, vendor guidance, "
        "or patch availability AND the CVE affects Cisco products (IOS, IOS XE, "
        "NX-OS, ASA, FTD, Firepower, Catalyst, Nexus, AnyConnect, ISE, etc.)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE ID, e.g. 'CVE-2023-20198'",
            },
        },
        "required": ["cve_id"],
    },
}

PROMPT = (
    "- **fetch_cisco_advisory** — Call this when the user explicitly asks for advisories, vendor "
    "guidance, patch availability, or workarounds AND the CVE affects Cisco products (IOS, IOS XE, "
    "NX-OS, ASA, FTD, Firepower, Catalyst, Nexus, AnyConnect, ISE, etc.). Returns SIR rating, "
    "affected product list, fixed versions, and workaround per advisory."
)


def fetch(cve_id: str) -> dict:
    return fetch_cisco_advisory(cve_id)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        for adv in result.get("advisories", []):
            url = adv.get("publication_url", "")
            if url:
                links.append({
                    "url":         url,
                    "source":      "cisco",
                    "type":        "advisory",
                    "title":       adv.get("advisory_id", ""),
                    "description": adv.get("title", ""),
                })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions, blobs = [], []
    if result.get("found"):
        for adv in result.get("advisories", []):
            # Fixed versions → discrete patch items
            for ver in adv.get("fixed_versions", []):
                text = f"{adv.get('advisory_id', 'Cisco')}: upgrade to {ver}"
                actions.append({"text": text, "source": "cisco", "type": "patch"})
            # Workaround → Haiku decomposition
            if adv.get("workaround"):
                blobs.append((adv["workaround"], "cisco"))
    return actions, blobs
