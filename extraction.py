"""The Haiku extraction layer: silent post-processing of advisory
blobs, Sonnet replies, NVD results, and IOC pages into structured items.
Owns the Anthropic client (also used by main.py for the Sonnet loop).
"""
import json
import logging
import re
import time

import anthropic
import dotenv

logger = logging.getLogger(__name__)

import context as ctx
import telemetry

_ = dotenv.load_dotenv()

client = anthropic.Anthropic()

_HAIKU_MODEL = "claude-haiku-4-5-20251001"


def _timed_create(purpose: str, **kwargs):
    """OBS1 choke point 2: wrap a Haiku call so its `usage`/latency/outcome are
    captured. `purpose` is the telemetry name (haiku_actions / _iocs / _products
    / _title), letting OBS2 break load down by extraction job."""
    t0 = time.perf_counter()
    try:
        resp = client.messages.create(**kwargs)
    except Exception:
        telemetry.record_llm(purpose, kwargs.get("model"), None,
                             (time.perf_counter() - t0) * 1000, ok=False)
        raise
    telemetry.record_llm(purpose, getattr(resp, "model", kwargs.get("model")),
                         getattr(resp, "usage", None),
                         (time.perf_counter() - t0) * 1000, ok=True)
    return resp


def _haiku_json_list(system: str, content: str, max_tokens: int,
                     purpose: str = "haiku") -> list:
    """Call Haiku expecting a JSON array. Strips code fences. If output was
    truncated at max_tokens (which yields invalid JSON and previously failed
    SILENTLY as []), retry once with double the budget and log the event."""
    response = _timed_create(
        purpose,
        model=_HAIKU_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": content}],
    )
    if response.stop_reason == "max_tokens":
        logger.warning("haiku output truncated at %d tokens — retrying with %d",
                        max_tokens, max_tokens * 2)
        response = _timed_create(
            purpose,
            model=_HAIKU_MODEL,
            max_tokens=max_tokens * 2,
            system=system,
            messages=[{"role": "user", "content": content}],
        )
        if response.stop_reason == "max_tokens":
            logger.error("haiku still truncated at %d tokens — returning []", max_tokens * 2)
            return []
    raw = response.content[0].text.strip()
    raw = re.sub(r"^```[^\n]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw.strip())
    items = json.loads(raw)
    return items if isinstance(items, list) else []


# ── Action extraction ────────────────────────────────────────────────────────

_EXTRACTION_SYSTEM = """\
You extract discrete, actionable security items from text produced by a security consultant or advisory source.

Action types — assign exactly one per item:
- patch       : a specific versioned fix (package version, KB article, build number)
- workaround  : a temporary measure while patching is not possible (disable a service, block a port)
- mitigation  : a configuration change that reduces exposure (ACL, registry key, Group Policy, firewall rule)
- admin       : an operational or administrative control (access review, privilege audit, policy change, vendor notification)
- detect      : something to look for to identify exploitation (log source, event ID, process name, file path, SIEM query, IOC)

Rules:
- Extract only concrete, self-contained actionable items
- Discard: diagnostic checks, impact descriptions, explanatory prose, "for more information" text, severity ratings
- If the text presents multiple options (Option 1, Option 2), extract each as a separate item
- Each item must make sense on its own without surrounding context
- Return at most 15 items total. If you find more, keep the most specific and actionable ones.
- Keep each item under 40 words. Trim generalities; preserve the specific action and its exact parameters.
- Return a JSON array only. Each element: {"text": "...", "type": "..."}
- If nothing actionable, return []
- No markdown, no explanation — only the JSON array"""


def llm_extract_actions(text: str, source: str, max_tokens: int = 1024) -> list[dict]:
    """Use Haiku to decompose text into discrete actionable items.
    max_tokens=1024 for short advisory blobs; 3072 for full Sonnet replies."""
    if not text or not text.strip():
        return []
    try:
        items = _haiku_json_list(_EXTRACTION_SYSTEM, f"Source: {source}\n\n{text}",
                                 max_tokens, purpose="haiku_actions")
        return [
            {
                "id":     ctx.make_action_id(item["text"]),
                "text":   item["text"],
                "source": source,
                "type":   item.get("type", "mitigation"),
            }
            for item in items
            if isinstance(item, dict) and item.get("text")
        ]
    except Exception:
        return []


def decompose_blobs(blobs: list[tuple[str, str]]) -> list[dict]:
    """Decompose (text, source) blobs into action items via Haiku, in parallel.

    Uses gevent.joinall when a hub is active (gunicorn gevent worker) so greenlets
    cooperate with the event loop. Falls back to sequential in the Flask dev server.

    ThreadPoolExecutor is intentionally avoided: native OS threads inside a gevent
    worker don't yield to the hub, starving it of heartbeats and risking SIGKILL
    under load — the same class of bug that hit the prefetch path (see PROGRESS.md)."""
    if not blobs:
        return []
    try:
        import gevent
        results = [None] * len(blobs)
        def _run(i, text, source):
            results[i] = llm_extract_actions(text, source)
        greenlets = [gevent.spawn(_run, i, text, source)
                     for i, (text, source) in enumerate(blobs)]
        gevent.joinall(greenlets, timeout=60)
        actions: list[dict] = []
        for r in results:
            if r:
                actions.extend(r)
        return actions
    except Exception:
        # Fallback: sequential (dev server or gevent unavailable)
        actions = []
        for text, source in blobs:
            actions.extend(llm_extract_actions(text, source))
        return actions


# ── IOC extraction ───────────────────────────────────────────────────────────

_IOC_EXTRACTION_SYSTEM = """\
You extract Indicators of Compromise (IOCs) from threat intelligence text about a specific CVE.

IOC types — assign exactly one per item:
- ip       : IPv4 or IPv6 address used as C2, attack source, or malicious infrastructure
- domain   : domain name used in exploitation, C2, or malware delivery
- hash     : file hash (MD5, SHA1, or SHA256) of a malware sample or exploit payload
- filepath : file path, filename, or registry key created or used by the exploit/malware
- ttp      : MITRE ATT&CK technique ID (e.g. T1190, T1059.001)
- yara     : YARA rule name or reference
- sigma    : Sigma rule name or reference

Rules:
- Extract only concrete, specific values — skip generic descriptions
- For hashes, note the hash type (MD5/SHA1/SHA256) in context
- Each value must be exact and copy-pasteable (IPs, hashes, domain names verbatim)
- Return a JSON array only. Each element: {"type": "...", "value": "...", "context": "brief note"}
- If nothing concrete found, return []
- No markdown, no explanation — only the JSON array"""


def llm_extract_iocs(cve_id: str, text: str) -> list[dict]:
    """Use Haiku to extract structured IOCs from a threat intelligence text snippet."""
    if not text or not text.strip():
        return []
    try:
        items = _haiku_json_list(_IOC_EXTRACTION_SYSTEM, f"CVE: {cve_id}\n\n{text}", 2048,
                                 purpose="haiku_iocs")
        return [
            {
                "type":    item.get("type", "other"),
                "value":   str(item.get("value", "")).strip(),
                "context": str(item.get("context", "")).strip(),
            }
            for item in items
            if isinstance(item, dict) and item.get("value")
        ]
    except Exception:
        return []


# ── Product extraction (auto-infra, ) ─────────────────────────────────

_PRODUCT_EXTRACTION_SYSTEM = """\
You extract the primary affected software product from an NVD CVE description.

The NVD description names the actual vulnerable software — the library, component, or \
application that contains the flaw. It does not describe OS distributions that happen to \
package it. Extract only the root vulnerable software, not its distributors.

Return a JSON array only, no other text:
[{"product": "...", "vendor": "...", "version": "...", "ecosystem": "..."}]

Rules:
- product: the software name (e.g. "Log4j", "OpenSSL", "Apache HTTP Server")
- vendor: the vendor or maintainer. Use the canonical short name — "Google" not "Google LLC", "Microsoft" not "Microsoft Corporation", "Apache" not "Apache Software Foundation". Use "" if unknown.
- version: the affected version or range from the description (e.g. "2.0–2.14.1", "< 3.0.7"). Use "unknown" if not stated.
- ecosystem: one of — java, npm, python, ruby, go, dotnet, windows, linux, network, browser, application, other
  Use "browser" for web browsers (Chrome, Firefox, Safari, Edge). Use "application" for desktop/mobile apps, office suites, productivity software. Use "network" for routers, firewalls, switches, VPN appliances.
- Extract the PRIMARY vulnerable component only — not OS distributions (RHEL, Ubuntu, Debian) \
unless the OS component itself is what is vulnerable (e.g. Linux kernel CVE, Windows RDP CVE)
- PLATFORM ADD-ONS are the exception to the vendor rule: when the vulnerable software is a \
plugin, theme, module, or extension FOR a platform (WordPress plugin, Drupal module, Joomla \
extension, browser extension, VS Code extension, Jenkins plugin), set vendor to the PLATFORM \
name ("WordPress", "Drupal", "Chrome", "Jenkins") and product to the add-on's own name, \
ecosystem "application". Rationale: the user discussing an add-on CVE runs the platform — \
that is environment signal worth capturing — while the vulnerable component stays the add-on. \
Do NOT emit the platform as a separate entry, and do NOT mark the platform itself vulnerable.
- If the description names multiple distinct products, include each
- If nothing can be identified, return []
- No markdown, no explanation — only the JSON array"""


def llm_extract_products(nvd_result: dict) -> list[dict]:
    """Call Haiku to extract the primary affected product from a raw NVD result dict."""
    if not nvd_result:
        return []
    try:
        items = _haiku_json_list(_PRODUCT_EXTRACTION_SYSTEM, json.dumps(nvd_result), 1024,
                                 purpose="haiku_products")
        return [
            {
                "product":   item.get("product", "").strip(),
                "vendor":    item.get("vendor", "").strip(),
                "version":   item.get("version", "unknown").strip() or "unknown",
                "ecosystem": item.get("ecosystem", "other").strip() or "other",
            }
            for item in items
            if isinstance(item, dict) and item.get("product")
        ]
    except Exception as exc:
        logger.error("haiku llm_extract_products failed: %s", exc)
        return []


def llm_extract_products_from_cve_id(cve_id: str, assigner: str = "") -> list[dict]:
    """Fallback product extraction when NVD data is unavailable (e.g. timeout).
    Uses only the CVE ID and EUVD assigner field as a hint to Haiku's training
    knowledge. Works well for well-known CVEs; returns [] for obscure/recent ones
    where Haiku has no training signal — callers must treat [] as 'unknown'."""
    if not cve_id:
        return []
    hint = f"\nAssigner: {assigner}" if assigner else ""
    content = (
        f"CVE-ID: {cve_id}{hint}\n"
        "Full NVD description not available. Use your training knowledge to identify "
        "the primary affected software product. Return [] if uncertain or unknown."
    )
    try:
        items = _haiku_json_list(_PRODUCT_EXTRACTION_SYSTEM, content, 512,
                                 purpose="haiku_products")
        return [
            {
                "product":   item.get("product", "").strip(),
                "vendor":    item.get("vendor", "").strip(),
                "version":   item.get("version", "unknown").strip() or "unknown",
                "ecosystem": item.get("ecosystem", "other").strip() or "other",
            }
            for item in items
            if isinstance(item, dict) and item.get("product")
        ]
    except Exception as exc:
        logger.error("haiku llm_extract_products_from_cve_id failed for %s: %s", cve_id, exc)
        return []


# ── Conversation titles ──────────────────────────────────────────────────────

_TITLE_SYSTEM = """\
You generate short titles for security consultant conversations.

Rules:
- 4-7 words maximum
- If a CVE ID is present, always include it verbatim — do not comment on whether you \
know the CVE, do not say it is outside your training data, just use the ID
- If the CVE has a well-known common name from before 2024, lead with it: \
"Log4Shell — CVE-2021-44228", "Heartbleed — CVE-2014-0160", "EternalBlue — CVE-2017-0144"
- For CVEs you do not recognise, use the ID alone: "CVE-2025-12101 Analysis" or \
"CVE-2025-12101 RCE Discussion" (add a brief descriptor only if the message makes it obvious)
- If no CVE, summarise the topic concisely: "Apache HTTP Server RCE Discussion"
- Return the title only — no quotes, no trailing punctuation, no explanation, \
no "I don't have information" text"""


def generate_title(message: str) -> str:
    """Call Haiku to produce a meaningful conversation title from the first user message."""
    try:
        response = _timed_create(
            "haiku_title",
            model=_HAIKU_MODEL,
            max_tokens=32,
            system=_TITLE_SYSTEM,
            messages=[{"role": "user", "content": message}],
        )
        title = response.content[0].text.strip().strip('"').strip("'")
        return title if title else message[:60]
    except Exception:
        return message[:60]
