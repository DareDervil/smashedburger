"""search_package_intel — Exa fresh-web search for package compromise/advisory
write-ups not yet in OSV or other structured databases.

source file: drop this file → tool disappears from Sonnet's toolkit.

WHY this is an agent tool (unlike search_news / search_iocs):
  search_news is scheduler-only, called by the monitor daemon on a fixed cadence.
  search_iocs uses Exa's /search outputSchema so Exa itself synthesises IOCs.
  THIS tool is a plain results-list fetch whose relevance filtering is done by
  Sonnet at citation time — the model reads snippets and cites only genuinely
  on-topic URLs. That design is intentional: Sonnet's reading comprehension is
  a better relevance gate than a keyword post-filter for narrative write-ups.
  Results surface as reply-link tiles via the existing _extract_reply_links path
  in main.py — no new tile route or DB schema required.
"""
from tools import search_package_intel

fetch = search_package_intel

NAME  = "search_package_intel"
ORDER = 106   # after socket_dev (105), before broadcom/tier1

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Search the web for fresh compromise reports, incident write-ups, and security "
        "advisories about a specific package that may not yet appear in OSV or Socket. "
        "Returns a list of {title, url, snippet, published_date} results from Exa. "
        "Use during package analysis when you want recent reporting beyond the structured "
        "databases — e.g. a blog post about a typosquat campaign, a Socket/Snyk/Aikido "
        "advisory not yet in OSV, or a supply-chain incident write-up. "
        "Cite only URLs whose snippet is genuinely about this package; skip off-topic "
        "results. At most one call per package per conversation. "
        "Requires EXA_API_KEY (gracefully absent → found:false)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ecosystem": {
                "type": "string",
                "enum": ["npm", "pypi", "pip"],
                "description": "Package ecosystem. 'pip' is accepted as alias for 'pypi'.",
            },
            "package": {
                "type": "string",
                "description": "Exact package name, e.g. 'lodash' or 'requests'.",
            },
            "version": {
                "type": "string",
                "description": "Version string if known, e.g. '4.17.20'. Optional.",
            },
        },
        "required": ["ecosystem", "package"],
    },
    "input_examples": [
        {"ecosystem": "npm",   "package": "lodash",   "version": "4.17.20"},
        {"ecosystem": "pypi",  "package": "requests",  "version": "2.25.0"},
    ],
}

PROMPT = (
    "- **search_package_intel** — During package analysis, optionally call this to fetch "
    "fresh compromise/advisory write-ups from the open web (Snyk blog, Socket reports, "
    "security researcher posts, incident narratives) that may not yet appear in OSV or "
    "Socket's structured data. Cite the genuinely relevant URLs inline in your reply — "
    "they will surface as source tiles for the user. Abstain if nothing in the results "
    "is clearly about this package. At most one call per package per conversation."
)
