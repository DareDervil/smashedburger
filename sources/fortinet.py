"""fetch_fortinet_advisory — FortiGuard PSIRT (SSR HTML parse)."""
from tools import fetch_fortinet_advisory

NAME  = "fetch_fortinet_advisory"
ORDER = 70

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch the official Fortinet PSIRT advisory page for a CVE. "
        "Returns structured data: per-product affected version ranges with exact fix versions, "
        "workaround, virtual patch (IPS signature), CVSS v3 score and vector, "
        "known exploitation status, and impact description. "
        "Call this when the user explicitly asks for advisories, vendor guidance, "
        "or patch availability AND the CVE affects Fortinet products (FortiOS, FortiGate, "
        "FortiProxy, FortiManager, FortiAnalyzer, FortiClient, FortiWeb, etc.). "
        "The advisory_url comes from NVD references — look for a URL matching "
        "fortiguard.fortinet.com/psirt/FG-IR-. "
        "Use affected_products to check whether the user's known version is in the affected range."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "advisory_url": {
                "type": "string",
                "description": (
                    "Full Fortinet advisory URL from NVD references, "
                    "e.g. 'https://fortiguard.fortinet.com/psirt/FG-IR-24-015'. "
                    "Also accepts a bare FG-IR ID like 'FG-IR-24-015'."
                ),
            },
        },
        "required": ["advisory_url"],
    },
}

PROMPT = (
    "- **fetch_fortinet_advisory** — Call this when the user explicitly asks for advisories, vendor "
    "guidance, patch availability, or workarounds AND the CVE affects Fortinet products (FortiOS, "
    "FortiGate, FortiProxy, FortiManager, FortiAnalyzer, FortiClient, FortiWeb, etc.). Pass the "
    "advisory URL from NVD references (matches fortiguard.fortinet.com/psirt/FG-IR-). Use "
    "affected_products to check whether the user's known version falls in the affected range."
)


def fetch(advisory_url: str) -> dict:
    return fetch_fortinet_advisory(advisory_url)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        links.append({
            "url":         result["advisory_url"],
            "source":      "fortinet",
            "type":        "advisory",
            "title":       result.get("fg_ir_id", ""),
            "description": result.get("title", ""),
        })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions, blobs = [], []
    if result.get("found"):
        # Patch items: one per product row — already discrete
        for p in result.get("affected_products", []):
            sol = p.get("solution", "").strip()
            if sol and sol.lower() not in ("", "n/a"):
                text = f"{p['product']}: {sol}"
                actions.append({"text": text, "source": "fortinet", "type": "patch"})
        # Workaround is a text blob — decompose via Haiku
        if result.get("workaround"):
            blobs.append((result["workaround"], "fortinet"))
        # Virtual patch → detect item
        if result.get("virtual_patch"):
            actions.append({"text": result["virtual_patch"],
                            "source": "fortinet", "type": "detect"})
    return actions, blobs
