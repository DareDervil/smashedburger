"""fetch_broadcom_advisory — VMware by Broadcom VMSA advisories."""
from tools import fetch_broadcom_advisory

NAME  = "fetch_broadcom_advisory"
ORDER = 110

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch the official VMware by Broadcom (VMSA) security advisory. "
        "Returns structured data: per-CVE details (description, known attack "
        "vectors, resolution, workarounds, exploitation-in-the-wild status) and "
        "the Response Matrix — per product/version rows with exact fixed versions "
        "(build IDs like ESXi80U3d-24585383) and patch documentation links. "
        "One VMSA typically covers multiple CVEs; results include all of them. "
        "Call this when the user explicitly asks for advisories, vendor guidance, "
        "or patch availability AND the CVE affects VMware / Broadcom products "
        "(ESXi, vCenter, vSphere, Workstation, Fusion, NSX, Aria, Cloud Foundation, "
        "Horizon, Tanzu, Telco Cloud, etc.). "
        "The advisory URL comes from NVD references — look for a "
        "support.broadcom.com URL (path contains 'SecurityAdvisories')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "advisory_url": {
                "type": "string",
                "description": (
                    "Broadcom advisory URL from NVD references, e.g. "
                    "'https://support.broadcom.com/web/ecx/support-content-notification"
                    "/-/external/content/SecurityAdvisories/0/25390'"
                ),
            },
        },
        "required": ["advisory_url"],
    },
}

PROMPT = (
    "- **fetch_broadcom_advisory** — Call this when the user explicitly asks for advisories, vendor "
    "guidance, patch availability, or workarounds AND the CVE affects VMware / Broadcom products "
    "(ESXi, vCenter, vSphere, Workstation, Fusion, NSX, Aria, Cloud Foundation, Horizon, Tanzu, etc.). "
    "Pass the advisory URL from NVD references (a support.broadcom.com URL containing "
    "'SecurityAdvisories'). One VMSA covers multiple CVEs — focus your guidance on the CVE under "
    "discussion but flag the others. The Response Matrix gives exact fixed versions per product and "
    "version branch — cross-reference against Known Infrastructure. Check exploited_in_wild per CVE "
    "and escalate urgency accordingly."
)


def fetch(advisory_url: str) -> dict:
    return fetch_broadcom_advisory(advisory_url)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        links.append({
            "url":         result["advisory_url"],
            "source":      "broadcom",
            "type":        "advisory",
            "title":       result.get("vmsa_id", ""),
            "description": result.get("synopsis", ""),
        })
        for ref_url in result.get("references", [])[:6]:
            links.append({
                "url":         ref_url,
                "source":      "broadcom",
                "type":        "patch" if "release-notes" in ref_url else "reference",
                "title":       ref_url.rstrip("/").split("/")[-1].split("?")[0].replace("-", " ")[:60],
                "description": "Patch documentation",
            })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions, blobs = [], []
    if result.get("found"):
        # Response Matrix rows → discrete patch items
        for row in result.get("response_matrix", []):
            fix = row.get("fixed_version", "").strip()
            if not fix or fix.lower() in ("n/a", "none", "patch pending", "unaffected"):
                continue
            label = f"{row['product']} {row.get('version', '')}".strip()
            actions.append({"text": f"{label}: upgrade to {fix}",
                            "source": "broadcom", "type": "patch"})
        # Per-CVE workarounds → Haiku decomposition
        for c in result.get("cves", []):
            if c.get("workaround"):
                blobs.append((f"{c['cve_id']}: {c['workaround']}", "broadcom"))
    return actions, blobs
