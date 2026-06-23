"""query_package_registry — npm/PyPI registry health metadata."""
from tools import query_package_registry

NAME  = "query_package_registry"
ORDER = 100

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch package health metadata from the npm or PyPI registry: existence "
        "(404 = possible typosquat), latest version, deprecation flag and message, "
        "last publish date, maintainer count, repository URL, version count. "
        "Health signals feed the compromise/abandonment assessment: a deprecated, "
        "maintainer-less, or long-unpublished package is a supply-chain risk even "
        "with zero CVEs. Always call this together with query_package_vulns."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ecosystem": {"type": "string", "enum": ["npm", "pypi"]},
            "package":   {"type": "string", "description": "Package name"},
        },
        "required": ["ecosystem", "package"],
    },
}


def fetch(ecosystem: str, package: str) -> dict:
    return query_package_registry(ecosystem, package)


def extract_links(result: dict) -> list:
    links = []
    if result.get("found"):
        eco, pkg = result.get("ecosystem", ""), result.get("package", "")
        url = (f"https://www.npmjs.com/package/{pkg}" if eco == "npm"
               else f"https://pypi.org/project/{pkg}/")
        links.append({
            "url":         url,
            "source":      "npm" if eco == "npm" else "pypi",
            "type":        "reference",
            "title":       pkg,
            "description": f"Registry — latest {result.get('latest_version', '?')}",
        })
    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions = []
    if result.get("found") and result.get("deprecated"):
        text = (f"{result['package']} ({result['ecosystem']}) is deprecated"
                + (f": {result['deprecation_msg']}" if result.get("deprecation_msg") else "")
                + " — plan a replacement")
        actions.append({"text": text,
                        "source": result["ecosystem"].lower(), "type": "admin"})
    return actions, []
