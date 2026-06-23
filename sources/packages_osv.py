"""query_package_vulns — OSV.dev package vulnerabilities + malware records."""
from tools import query_package_vulns

NAME  = "query_package_vulns"
ORDER = 90

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Query OSV.dev for vulnerabilities AND malicious-package records affecting an "
        "npm or PyPI package. Records with is_malware=true mean the package itself was "
        "compromised (hijacked release, malware injection) — not merely vulnerable; "
        "treat that as an incident, not a patching exercise. "
        "With a version, returns only records affecting that version; without, the "
        "package's full history. Returns per record: OSV/GHSA/MAL id, CVE aliases, "
        "summary, severity, affected version ranges (introduced/fixed), fixed versions, "
        "references. Call this whenever the user asks about a software package's "
        "safety, vulnerabilities, or whether it has been compromised. "
        "Call query_package_registry alongside it for package health signals."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ecosystem": {
                "type": "string", "enum": ["npm", "pypi"],
                "description": "Package ecosystem ('pip' is accepted as alias for pypi)",
            },
            "package": {
                "type": "string",
                "description": "Package name, e.g. 'lodash' or 'requests'",
            },
            "version": {
                "type": "string",
                "description": "Specific version to check, e.g. '4.17.20'. Omit for full history.",
            },
        },
        "required": ["ecosystem", "package"],
    },
    "input_examples": [
        {"ecosystem": "npm", "package": "ua-parser-js", "version": "0.7.29"},
        {"ecosystem": "pypi", "package": "requests"},
    ],
}


def fetch(ecosystem: str, package: str, version: str = "") -> dict:
    return query_package_vulns(ecosystem, package, version)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        for v in result.get("vulns", [])[:10]:
            links.append({
                "url":         f"https://osv.dev/vulnerability/{v['id']}",
                "source":      "osv",
                "type":        "advisory",
                "title":       v["id"],
                "description": ("⚠ MALWARE — " if v.get("is_malware") else "") + v.get("summary", ""),
            })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions = []
    if result.get("found"):
        pkg = result.get("package", "")
        eco = result.get("ecosystem", "")
        for v in result.get("vulns", []):
            if v.get("is_malware"):
                # Compromise = incident, not patching
                actions.append({
                    "text": f"Remove or replace {eco} package {pkg} — compromised ({v['id']}): {v.get('summary', '')}",
                    "source": "osv", "type": "admin",
                })
                actions.append({
                    "text": f"Audit hosts and CI builds that installed affected versions of {pkg}; rotate credentials present in those environments",
                    "source": "osv", "type": "detect",
                })
        # Patch items: nearest fixed version per non-malware vuln (cap 3)
        for v in [v for v in result.get("vulns", []) if not v.get("is_malware")][:3]:
            if v.get("fixed_versions"):
                fix = v["fixed_versions"][-1]
                actions.append({
                    "text": f"Upgrade {pkg} ({eco}) to {fix} (fixes {v['id']})",
                    "source": "osv", "type": "patch",
                })
    return actions, []
