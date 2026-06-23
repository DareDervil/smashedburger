"""fetch_advisories — Tier 1 parallel fetch (GitHub / Red Hat / Ubuntu / MSRC).
Highest ORDER: sits last in the tools list and carries the prompt-cache
breakpoint (assigned by the assembler)."""
from advisories import fetch_advisories

NAME  = "fetch_advisories"
ORDER = 120

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Fetch security advisories for a CVE from four Tier 1 sources: "
        "GitHub Advisory Database (open source ecosystems: Maven, npm, PyPI, Go, etc.), "
        "Red Hat (RHEL, CentOS, Fedora — includes fix status per product, "
        "per-product impact override, statement, and mitigation steps), "
        "Ubuntu (Ubuntu releases — includes patch status per release, USN references "
        "with remediation instructions, and analyst notes), "
        "and Microsoft MSRC (Windows and Azure — includes per-product severity, KB articles, "
        "reboot requirements, workarounds, and mitigations). "
        "MSRC affected products include an is_esu field: when true, the product is under "
        "Extended Security Updates (end-of-life Windows requiring a paid ESU subscription "
        "to receive patches) — always flag this explicitly when reporting MSRC findings. "
        "Use this tool only when the user explicitly asks for advisories, "
        "vendor guidance, or patch availability. Do not call it automatically "
        "during a CVE briefing unless asked."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE ID to fetch advisories for, e.g. 'CVE-2021-44228'",
            }
        },
        "required": ["cve_id"],
    },
}

PROMPT = (
    "- **fetch_advisories** — Call this when the user asks for vendor guidance, patch availability, "
    "advisories, or workarounds. Queries GitHub Advisory Database, Red Hat, Ubuntu, and Microsoft MSRC "
    "in parallel. Never call this automatically during a briefing — only on explicit request."
)


def fetch(cve_id: str) -> dict:
    return fetch_advisories(cve_id)


def extract_links(result: dict) -> list:
    links = []

    github = result.get("github", {})
    if github.get("found"):
        for adv in github.get("advisories", []):
            ghsa_id = adv.get("ghsa_id", "")
            if ghsa_id:
                links.append({
                    "url": f"https://github.com/advisories/{ghsa_id}",
                    "source": "github", "type": "advisory",
                    "title": ghsa_id, "description": adv.get("summary", ""),
                })

    redhat = result.get("redhat", {})
    if redhat.get("found"):
        seen = set()
        for p in redhat.get("fixed_products", []):
            adv_id = p.get("advisory", "")
            if adv_id and adv_id not in seen:
                seen.add(adv_id)
                links.append({
                    "url": f"https://access.redhat.com/errata/{adv_id}",
                    "source": "redhat", "type": "advisory",
                    "title": adv_id, "description": p.get("product", ""),
                })

    ubuntu = result.get("ubuntu", {})
    if ubuntu.get("found"):
        for n in ubuntu.get("notices", []):
            links.append({
                "url": n["url"],
                "source": "ubuntu", "type": "advisory",
                "title": n["id"],
                "description": (n.get("summary") or "").split("\n")[0],
            })

    msrc = result.get("msrc", {})
    if msrc.get("found"):
        seen_urls = set()
        for p in msrc.get("affected_products", []):
            for kb in p.get("kb_articles", []):
                url = kb.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    links.append({
                        "url": url,
                        "source": "msrc", "type": "patch",
                        "title": kb.get("name", ""),
                        "description": p.get("product_family", ""),
                    })

    return links


def extract_actions(result: dict) -> tuple[list, list]:
    actions, blobs = [], []

    # ── Already discrete → direct ──
    github = result.get("github", {})
    if github.get("found"):
        seen_pkgs: set = set()
        for adv in github.get("advisories", []):
            for pkg in adv.get("packages", []):
                patched = pkg.get("patched_versions", [])
                if patched:
                    key = f"{pkg['ecosystem']}:{pkg['name']}"
                    if key not in seen_pkgs:
                        seen_pkgs.add(key)
                        text = f"Upgrade {pkg['name']} ({pkg['ecosystem']}) to {patched[0]}"
                        actions.append({"text": text, "source": "github", "type": "patch"})

    # ── Blobs → Haiku ──
    msrc = result.get("msrc", {})
    if msrc.get("found"):
        for w in msrc.get("workarounds", []):
            if w: blobs.append((w, "msrc"))
        for m in msrc.get("mitigations", []):
            if m: blobs.append((m, "msrc"))

    ubuntu = result.get("ubuntu", {})
    if ubuntu.get("found"):
        for n in ubuntu.get("notices", []):
            instr = (n.get("instructions") or "").strip()
            if instr:
                blobs.append((f"{n['id']}: {instr}", "ubuntu"))
        mitigation = (ubuntu.get("mitigation") or "").strip()
        if mitigation:
            blobs.append((mitigation, "ubuntu"))

    redhat = result.get("redhat", {})
    if redhat.get("found"):
        mitigation = (redhat.get("mitigation") or "").strip()
        if mitigation:
            blobs.append((mitigation, "redhat"))

    return actions, blobs
