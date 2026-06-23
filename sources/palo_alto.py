"""fetch_palo_alto_advisory — PAN PSIRT (CVE JSON 5.0 endpoint).

NOTE: pre-refactor, this tool's registry entry pointed at the RAW function, so
its link/action extraction never fired (latent bug). The uniform plugin wrapper
fixes that — extraction now works like every other source.
"""
from tools import fetch_palo_alto_advisory

NAME  = "fetch_palo_alto_advisory"
ORDER = 50

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch the official Palo Alto Networks PSIRT advisory for a CVE from "
        "security.paloaltonetworks.com. Returns structured data: affected PAN-OS / "
        "Prisma Access / GlobalProtect version branches with exact fix versions, "
        "required configuration for exposure, workaround (including Threat Prevention "
        "IDs where available), full solution with hotfix list, and exploitation status. "
        "Call this when Palo Alto Networks products (PAN-OS, GlobalProtect, Prisma Access, "
        "Cortex XDR, Panorama) appear in Known Infrastructure AND a CVE is under discussion. "
        "Always call this before generating remediation checklist items for Palo Alto products "
        "— do not rely on NVD data alone for patch versions."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE ID in the format CVE-YYYY-NNNNN (e.g. 'CVE-2024-3400')",
            },
        },
        "required": ["cve_id"],
    },
}

PROMPT = (
    "- **fetch_palo_alto_advisory** — Call this when the user explicitly asks for advisories, vendor "
    "guidance, patch availability, or workarounds AND the CVE affects Palo Alto Networks products "
    "(PAN-OS, GlobalProtect, Prisma Access, Cortex XDR, Panorama). Returns exact affected version "
    "branches, per-branch fix versions, required configuration for exposure, workaround with Threat "
    "Prevention IDs, and exploitation status. Use affected_versions list to check if the user's known "
    "version is impacted — if their version appears in the list they are affected; if not, state they "
    "are likely unaffected but confirm."
)


def fetch(cve_id: str) -> dict:
    return fetch_palo_alto_advisory(cve_id)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        links.append({
            "url":         result["advisory_url"],
            "source":      "palo_alto",
            "type":        "advisory",
            "title":       result.get("cve_id", ""),
            "description": result.get("title", ""),
        })
        for ref_url in result.get("references", []):
            links.append({
                "url":    ref_url,
                "source": "palo_alto",
                "type":   "reference",
                "title":  ref_url.split("/")[-1] or ref_url,
                "description": "",
            })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    blobs = []
    if result.get("found"):
        # Workaround and solution are rich text blobs — decompose via Haiku
        if result.get("workaround"):
            blobs.append((result["workaround"], "palo_alto"))
        if result.get("solution"):
            blobs.append((result["solution"], "palo_alto"))
    return [], blobs
