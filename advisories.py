import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 20


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()


def _fetch_github(cve_id: str) -> dict:
    try:
        resp = requests.get(
            f"https://api.github.com/advisories?cve_id={cve_id}",
            headers={"Accept": "application/vnd.github+json"},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return {"found": False}
        data = resp.json()
        if not data:
            return {"found": False}

        advisories = []
        for adv in data:
            advisories.append({
                "ghsa_id": adv["ghsa_id"],
                "severity": adv["severity"],
                "summary": adv["summary"],
                "packages": [
                    {
                        "ecosystem": v["package"]["ecosystem"],
                        "name": v["package"]["name"],
                        "patched_versions": v.get("patched_versions", []),
                    }
                    for v in adv.get("vulnerabilities", [])
                ],
            })

        return {"found": True, "advisories": advisories}
    except Exception as e:
        return {"found": False, "error": str(e)}


def _fetch_redhat(cve_id: str) -> dict:
    try:
        resp = requests.get(
            f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json",
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False}
        if resp.status_code != 200:
            return {"found": False}
        data = resp.json()

        fixed_products = [
            {
                "product": r.get("product_name"),
                "package": r.get("package"),
                "advisory": r.get("advisory"),
                "impact": r.get("impact"),
            }
            for r in data.get("affected_release", [])
        ]

        unfixed_products = [
            {
                "product": s.get("product_name"),
                "package": s.get("package_name"),
                "fix_state": s.get("fix_state"),
            }
            for s in data.get("package_state", [])
        ]

        mitigation = data.get("mitigation", "")
        if isinstance(mitigation, dict):
            mitigation = mitigation.get("value", "")

        return {
            "found": True,
            "severity": data.get("threat_severity"),
            "statement": data.get("statement", ""),
            "mitigation": mitigation,
            "fixed_products": fixed_products,
            "unfixed_products": unfixed_products,
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


def _fetch_ubuntu(cve_id: str) -> dict:
    try:
        resp = requests.get(
            f"https://ubuntu.com/security/cves/{cve_id}.json",
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"found": False}
        if resp.status_code != 200:
            return {"found": False}
        data = resp.json()

        packages = [
            {
                "name": pkg["name"],
                "statuses": {
                    s["release_codename"]: {
                        "status": s["status"],
                        "version": s.get("description"),
                        "pocket": s.get("pocket"),
                    }
                    for s in pkg.get("statuses", [])
                    if s.get("status") != "DNE"
                },
            }
            for pkg in data.get("packages", [])
        ]

        notices = [
            {
                "id": n["id"],
                "url": f"https://ubuntu.com/security/notices/{n['id']}",
                "summary": n.get("summary", "").strip(),
                "instructions": (n.get("instructions") or "").strip(),
            }
            for n in data.get("notices", [])
        ]

        notes = [
            {"author": n.get("author"), "note": n.get("note", "").strip()}
            for n in data.get("notes", [])
        ]

        mitigation = (data.get("mitigation") or "").strip()

        priority = data.get("ubuntu_priority") or data.get("priority")
        return {
            "found": True,
            "priority": priority,
            "mitigation": mitigation,
            "notices": notices,
            "notes": notes,
            "packages": packages,
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


def _fetch_msrc(cve_id: str) -> dict:
    try:
        base = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
        headers = {"Accept": "application/json"}
        params = {"$filter": f"cveNumber eq '{cve_id}'"}

        vuln_resp = requests.get(
            f"{base}/vulnerability",
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )
        if vuln_resp.status_code != 200:
            return {"found": False}
        vuln_data = vuln_resp.json()
        if not vuln_data.get("value"):
            return {"found": False}
        vuln = vuln_data["value"][0]

        prod_resp = requests.get(
            f"{base}/affectedProduct",
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )
        products = []
        if prod_resp.status_code == 200:
            for p in prod_resp.json().get("value", []):
                family = p.get("productFamily", "")
                kb_articles = [
                    {
                        "name": kb.get("articleName"),
                        "url": kb.get("articleUrl"),
                        "reboot_required": kb.get("rebootRequired"),
                        "fixed_build": kb.get("fixedBuildNumber") or None,
                    }
                    for kb in p.get("kbArticles", [])
                ]
                products.append({
                    "product": p.get("product"),
                    "product_family": family,
                    "is_esu": family == "ESU",
                    "severity": p.get("severity"),
                    "impact": p.get("impact"),
                    "kb_articles": kb_articles,
                })

        # Fetch workarounds and mitigations from the CVRF document
        workarounds = []
        mitigations = []
        release_number = vuln.get("releaseNumber")
        if release_number:
            cvrf_resp = requests.get(
                f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{release_number}",
                headers={"Accept": "application/json"},
                timeout=TIMEOUT,
            )
            if cvrf_resp.status_code == 200:
                cvrf = cvrf_resp.json()
                vuln_entry = next(
                    (v for v in cvrf.get("Vulnerability", []) if v.get("CVE") == cve_id),
                    None,
                )
                if vuln_entry:
                    for r in vuln_entry.get("Remediations", []):
                        text = _strip_html(r.get("Description", {}).get("Value", ""))
                        if not text:
                            continue
                        if r.get("Type") == 0:
                            workarounds.append(text)
                        elif r.get("Type") == 1:
                            mitigations.append(text)

        return {
            "found": True,
            "exploited": vuln.get("exploited"),
            "publicly_disclosed": vuln.get("publiclyDisclosed"),
            "tag": vuln.get("tag"),
            "workarounds": workarounds,
            "mitigations": mitigations,
            "affected_products": products,
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


def fetch_advisories(cve_id: str) -> dict:
    """Query Tier 1 advisory sources for a CVE in parallel. Returns findings from
    GitHub Advisory Database, Red Hat, Ubuntu, and Microsoft MSRC."""
    sources = {
        "github": _fetch_github,
        "redhat": _fetch_redhat,
        "ubuntu": _fetch_ubuntu,
        "msrc": _fetch_msrc,
    }
    results = {}
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {executor.submit(fn, cve_id): name for name, fn in sources.items()}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return {"cve_id": cve_id, **results}
