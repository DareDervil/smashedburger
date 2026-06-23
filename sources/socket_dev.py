"""fetch_socket_score — Socket.dev behavioral supply-chain risk analysis.
Key-gated (SOCKET_API_KEY); quota-aware (~100 of 500 units per call, fast
refresh window). First source added under the plugin architecture.

Filename is socket_dev (not socket) to avoid any ambiguity with the stdlib.
"""
from tools import fetch_socket_score

NAME  = "fetch_socket_score"
ORDER = 105   # after the package tools it complements, before broadcom/tier1

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch Socket.dev supply-chain risk analysis for an EXACT package version "
        "(npm or PyPI). Socket statically analyses the artifact currently in the "
        "registry and returns 0-1 scores (overall, supplyChain, quality, maintenance, "
        "vulnerability, license) plus behavioral alerts: install scripts, network / "
        "filesystem / env access, eval use, obfuscated code, typosquats, maintainer "
        "churn. This catches risk that exists BEFORE any incident is recorded — the "
        "complement of query_package_vulns (which is the historical incident record; "
        "Socket does NOT see compromises whose artifacts were purged from the registry). "
        "EXPENSIVE: each call costs ~100 of 500 quota units (window refreshes "
        "frequently) — call at most once per package@version per conversation, only "
        "when the user wants a risk/trust assessment beyond known vulnerabilities, "
        "and never in bulk. Requires an exact version: take the user's version, or "
        "latest_version from query_package_registry."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ecosystem": {
                "type": "string", "enum": ["npm", "pypi"],
                "description": "Package ecosystem ('pip' accepted as alias for pypi)",
            },
            "package": {
                "type": "string",
                "description": "Package name, e.g. 'lodash'",
            },
            "version": {
                "type": "string",
                "description": "Exact version to analyse, e.g. '4.17.20'. Required.",
            },
        },
        "required": ["ecosystem", "package", "version"],
    },
    "input_examples": [
        {"ecosystem": "npm", "package": "lodash", "version": "4.17.20"},
    ],
}

PROMPT = (
    "- **fetch_socket_score** — Call this when the user wants a trust/risk assessment of a package "
    "beyond known vulnerabilities (\"can we adopt X?\", \"how risky is this dependency?\"), or when "
    "OSV shows nothing but suspicion remains. Behavioral analysis of the current artifact: 0-1 "
    "scores + alerts like install scripts, network access, eval, obfuscation, typosquat. Interpret "
    "scores: >0.8 healthy, 0.5-0.8 review, <0.5 concerning — supplyChain and overall matter most. "
    "It does NOT see purged historical compromises (OSV covers those). QUOTA: ~100 of 500 units per "
    "call — at most one call per package@version per conversation, never bulk, requires exact version."
)


def fetch(ecosystem: str, package: str, version: str) -> dict:
    return fetch_socket_score(ecosystem, package, version)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        scores = result.get("scores", {})
        overall = scores.get("overall")
        desc = (f"Socket scores — overall {overall:.2f}, supplyChain {scores.get('supplyChain', 0):.2f}"
                if isinstance(overall, (int, float)) else "Socket risk analysis")
        links.append({
            "url":         result["package_url"],
            "source":      "socket",
            "type":        "advisory",
            "title":       f"{result.get('package', '')}@{result.get('version', '')}",
            "description": desc,
        })
    return links


# Behavioral alert types that warrant a discrete action item
_RISK_ALERTS = {
    "installScripts":   ("admin",  "runs install scripts"),
    "networkAccess":    ("detect", "performs network access"),
    "filesystemAccess": ("detect", "accesses the filesystem"),
    "envVars":          ("detect", "reads environment variables"),
    "obfuscatedCode":   ("admin",  "contains obfuscated code"),
    "usesEval":         ("admin",  "uses eval()"),
    "didYouMean":       ("admin",  "possible typosquat of a popular package"),
    "malware":          ("admin",  "flagged as malware by Socket"),
    "gptMalware":       ("admin",  "flagged as likely malware by Socket AI analysis"),
    "shellAccess":      ("detect", "spawns shell processes"),
}


def extract_actions(result: dict) -> tuple[list, list]:
    actions = []
    if not result.get("found"):
        return actions, []
    pkg = f"{result.get('package', '')}@{result.get('version', '')}"
    eco = result.get("ecosystem", "")

    # Low overall/supplyChain score → review item
    scores = result.get("scores", {})
    for key in ("overall", "supplyChain"):
        val = scores.get(key)
        if isinstance(val, (int, float)) and val < 0.5:
            actions.append({
                "text": f"Review {eco} package {pkg} before further use — Socket {key} score {val:.2f} (<0.5)",
                "source": "socket", "type": "admin",
            })
            break  # one review item is enough

    # High-signal behavioral alerts (skip CVE alerts — OSV already covers those)
    seen_types = set()
    for al in result.get("alerts", []):
        atype = al.get("type", "")
        if atype in seen_types or atype not in _RISK_ALERTS:
            continue
        if al.get("severity") not in ("critical", "high", "medium"):
            continue
        seen_types.add(atype)
        action_type, phrase = _RISK_ALERTS[atype]
        actions.append({
            "text": f"{pkg} ({eco}): package {phrase} — assess whether this is expected for its function",
            "source": "socket", "type": action_type,
        })

    return actions, []
