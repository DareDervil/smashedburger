"""NB6/NB7 — learning recommendation engine.


The novel "tutor" layer: once a day, analyse the user's own conversations,
detect recurring topics at the CONCEPT/CLASS level (CVE-2023-3519 +
CVE-2025-5777 → "memory disclosure in TLS appliances"), and for topics that
cross a weight threshold and haven't been taught yet, run ONE *evergreen*
educational search and surface a "Recommended reading" card with full
provenance (NB7: "suggested because you dug into this in [A], [B]").

Design is the direct output of the NB6 probe (tests/test_nb6_probe.py, verdict
2026-06-13, amendment):
  - concept-lift is ONE Sonnet call (quality > cost — a single daily call);
  - the teaching search is OPEN-WEB and date-LESS (the opposite of the news
    monitor) because the canonical explainers (OWASP, PortSwigger, FIRST.org)
    live on the open web — the probe showed hard-restricting to the NB5 *news*
    feeds degrades to CVE-specific blog posts. NB6 has its OWN teaching pool,
    SOFT-preferred (re-ranked up), never a hard includeDomains filter;
  - explicit "I don't know X" is the strongest learning signal and is weighted
    at question level, above a plain statement.

NOT an agent tool (same rule as news.py/kev.py): only the daily 'learning'
sentinel and the /recommendations/run route call analyze_conversations().
Sandbox blocks api.anthropic.com + api.exa.ai → fixture-tested offline, run live.
"""
import logging
import os
import re

import db
from tools import search_news

logger = logging.getLogger(__name__)

LEARNING_MODEL = os.getenv("NB6_MODEL", "claude-sonnet-4-6")
LEARN_WEIGHT_THRESHOLD = float(os.getenv("NB6_THRESHOLD", "4.0"))
MAX_NEW_TOPICS_PER_RUN = 3        # quality over quantity (NB6 principle)
SEARCH_POOL_RESULTS = 6           # pull a few, then re-rank + keep the best
KEEP_PER_TOPIC = 2                # 1-2 results per topic — a tutor, not a feed
LEARNING_CADENCE_HOURS = 24

# Intent-density weights (probe-tuned). Questions AND explicit-ignorance both
# count as high learning intent; plain user statements mid; assistant text low.
W_HIGH = 3.0
W_USER_STATEMENT = 2.0
W_ASSISTANT = 1.0
RECURRENCE_BONUS = 0.5

# NB6 teaching pool — DISTINCT from NB5's news feeds. These domains proved
# teaching-grade in the probe (concept explainers/tutorials, not news). Used as
# a SOFT preference (re-rank), never a hard filter.
TEACHING_POOL = (
    "owasp.org", "cheatsheetseries.owasp.org", "portswigger.net",
    "first.org", "learn.snyk.io", "huntress.com",
)

_Q_WORDS = ("what", "why", "how", "which", "where", "when", "who", "is ", "are ",
            "should", "can ", "could", "do ", "does", "did ", "would")
# Explicit learning-desire / ignorance — the strongest signal (probe finding).
_LEARN_PHRASES = ("i don't know", "i dont know", "i'm not familiar", "im not familiar",
                  "not familiar with", "never heard", "explain", "teach me",
                  "unfamiliar", "don't understand", "dont understand", "no idea",
                  "what is", "what are", "how does", "how do")


def classify_question(text: str) -> bool:
    t = text.strip().lower()
    if "?" in t or any(t.startswith(w) for w in _Q_WORDS):
        return True
    return any(p in t for p in _LEARN_PHRASES)


def _is_high_intent(quote: str, is_question) -> bool:
    """A mention is high-intent if the LLM flagged it a question OR the quote
    carries explicit learning desire — so 'I don't know anything about X' (a
    statement) still outranks a plain statement (probe refinement)."""
    if is_question:
        return True
    return any(p in (quote or "").lower() for p in _LEARN_PHRASES)


def _text_from_content(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return ""
        return "\n".join(b["text"] for b in content
                         if isinstance(b, dict) and b.get("type") == "text" and b.get("text"))
    return ""


def build_corpus(conversations: list, since: str | None = None) -> list:
    """Flatten the DB to authored prose only (tool plumbing dropped). When
    `since` (an ISO timestamp) is given, only conversations updated strictly
    after it are included — the incremental window that keeps each daily run's
    prompt small instead of re-feeding the whole history (cost + truncation)."""
    corpus = []
    for conv in conversations:
        if since and (conv.get("updated_at") or "") <= since:
            continue
        turns = []
        msgs, _ = db.load_messages(conv["id"])
        for msg in msgs:
            text = _text_from_content(msg["content"]).strip()
            if not text:
                continue
            role = msg["role"]
            turns.append({"role": role, "text": text,
                          "is_question": role == "user" and classify_question(text)})
        if turns:
            corpus.append({"conv_id": conv["id"], "conv": conv.get("title") or conv["id"],
                           "theme": conv.get("cvss_severity") or "", "turns": turns})
    return corpus


def compute_weight(mentions: list) -> float:
    score, convs = 0.0, set()
    for m in mentions:
        convs.add(m.get("conv") or m.get("conv_title"))
        if m.get("role") == "user" and _is_high_intent(m.get("quote", ""), m.get("is_question")):
            score += W_HIGH
        elif m.get("role") == "user":
            score += W_USER_STATEMENT
        else:
            score += W_ASSISTANT
    return round(score * (1.0 + RECURRENCE_BONUS * max(0, len(convs) - 1)), 2)


# ── Concept extraction (Sonnet) ───────────────────────────────────────────────

_CONCEPT_SYSTEM = """\
You analyse a security analyst's past consultation conversations to find the \
recurring LEARNING TOPICS — at the CONCEPT / CLASS level, not the surface level.

LIFT specifics into the underlying class:
- "CVE-2023-3519" + "CVE-2025-5777" → "Memory disclosure in TLS/VPN appliances"
- "lodash prototype pollution" → "Prototype pollution in JavaScript dependencies"
A good concept teaches something that transfers to the NEXT case, not just the one seen.

Signals of a worthwhile topic, strongest first:
1. The analyst's OWN QUESTIONS or explicit "I don't know X" statements (learning intent).
2. It recurs ACROSS multiple conversations.
3. The analyst makes statements about it.
(Assistant text alone is the weakest signal.)

Return ONLY a JSON array. Each element:
{
  "concept": "the class-level topic, phrased as something teachable",
  "class": "2-4 word tag",
  "specifics": ["the concrete CVEs/products/terms this generalises"],
  "mentions": [{"conv": "<conversation title>", "role": "user"|"assistant", "is_question": true|false, "quote": "short verbatim snippet"}],
  "why_teach": "one line: what the analyst would gain"
}

Rules:
- Only concepts that recur (>=2 mentions) OR show clear question/learning intent.
- Prefer FEWER, higher-quality concepts. Return [] if nothing recurs.
- mentions must be real — cite the conversation each came from.
- No markdown, no preamble — only the JSON array."""


def _format_corpus(corpus: list) -> str:
    lines = []
    for c in corpus:
        lines.append(f"### Conversation: {c['conv']}" + (f"  (severity {c['theme']})" if c["theme"] else ""))
        for t in c["turns"]:
            tag = "USER-QUESTION" if t["is_question"] else ("USER" if t["role"] == "user" else "ASSISTANT")
            snippet = t["text"] if len(t["text"]) <= 800 else t["text"][:800] + "…"
            lines.append(f"[{tag}] {snippet}")
        lines.append("")
    return "\n".join(lines)


def _salvage_objects(raw: str) -> list:
    """Recover complete top-level {...} objects from a JSON array that may have
    been truncated mid-element (a long corpus can blow the token budget). Scans
    for balanced braces outside strings and parses each object individually,
    silently dropping a trailing incomplete one. Better to keep the concepts
    that DID serialise than to abort the whole daily run."""
    import json
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(raw):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    out.append(json.loads(raw[start:i + 1]))
                except Exception:
                    pass
                start = None
    return out


def _parse_json_array(raw: str) -> list:
    import json
    raw = re.sub(r"^```[^\n]*\n?", "", raw.strip())
    raw = re.sub(r"\n?```$", "", raw.strip())
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        # Truncated/malformed → salvage whatever complete objects are present.
        salvaged = _salvage_objects(raw)
        if salvaged:
            logger.warning("learning salvaged %d concept(s) from malformed JSON", len(salvaged))
        return salvaged


def extract_concepts(corpus: list) -> list:
    """ONE Sonnet pass → class-level concepts. Imported lazily so the module
    loads without the Anthropic client (keeps fixture tests offline). Retries
    once at double budget on truncation (the corpus grows over time), then falls
    back to salvaging complete objects from partial JSON."""
    from extraction import client
    budget = 4096
    resp = client.messages.create(
        model=LEARNING_MODEL, max_tokens=budget,
        system=_CONCEPT_SYSTEM,
        messages=[{"role": "user", "content": _format_corpus(corpus)}],
    )
    if resp.stop_reason == "max_tokens":
        logger.warning("learning concept-lift truncated at %d tokens — retrying at %d",
                        budget, budget * 2)
        resp = client.messages.create(
            model=LEARNING_MODEL, max_tokens=budget * 2,
            system=_CONCEPT_SYSTEM,
            messages=[{"role": "user", "content": _format_corpus(corpus)}],
        )
    concepts = _parse_json_array(resp.content[0].text)
    # Backfill conv_id onto each mention by matching the conversation title, so
    # NB7 provenance can link to the actual conversation.
    title_to_id = {c["conv"]: c["conv_id"] for c in corpus}
    for concept in concepts:
        concept["weight"] = compute_weight(concept.get("mentions", []))
        for m in concept.get("mentions", []):
            m["conv_id"] = title_to_id.get(m.get("conv"))
    return sorted(concepts, key=lambda c: c.get("weight", 0), reverse=True)


# ── Evergreen teaching search (open web, no date, soft-prefer teaching pool) ───

def _domain(url: str) -> str:
    m = re.search(r"https?://([^/]+)", url or "")
    return m.group(1).replace("www.", "") if m else ""


def _in_pool(url: str) -> bool:
    d = _domain(url)
    return any(d == p or d.endswith("." + p) for p in TEACHING_POOL)


def find_reading(concept: str) -> list:
    """ONE evergreen search (NO date filter), then SOFT-prefer teaching-pool
    domains by stable re-rank, keep the best 1-2. Open web is primary because
    the canonical explainers live there (probe verdict)."""
    query = f"{concept} — how it works and how to defend against it"
    raw = search_news(query, num_results=SEARCH_POOL_RESULTS)  # no start date = evergreen
    results = raw.get("results", [])
    # Stable sort: teaching-pool hits float to the top, original order otherwise.
    results = sorted(results, key=lambda r: 0 if _in_pool(r.get("url", "")) else 1)
    out = []
    for r in results[:KEEP_PER_TOPIC]:
        if not r.get("url"):
            continue
        out.append({
            "title":   r.get("title", ""),
            "url":     r["url"],
            "source":  _domain(r["url"]),
            "snippet": (r.get("snippet") or "")[:400],
        })
    return out


# ── Orchestration ──────────────────────────────────────────────────────────────

def _merge_mentions(existing: list, fresh: list) -> list:
    """Union of stored + new mentions, deduped by (conv_id, quote). Lets a
    topic's weight ACCUMULATE across daily runs even though each run only feeds
    the new conversations — so cross-run recurrence still builds toward the
    threshold instead of resetting every run."""
    merged, seen = [], set()
    for m in [*existing, *fresh]:
        key = (m.get("conv_id"), (m.get("quote") or "")[:120])
        if key in seen:
            continue
        seen.add(key)
        merged.append(m)
    return merged


def _analyze_for_user(user_id: str, cutoff: str | None) -> dict:
    """Inner per-user analysis pass. Topics and recs are scoped to user_id so
    different users' learning histories never bleed into each other."""
    corpus = build_corpus(db.list_conversations(user_id=user_id), since=cutoff)
    if not corpus:
        return {"ok": True, "new_topics": 0, "new_recs": 0, "note": "no new activity"}

    concepts = extract_concepts(corpus)

    new_topics = new_recs = 0
    for c in concepts:
        concept = c.get("concept", "").strip()
        if not concept or db.is_topic_taught(concept, user_id):
            continue   # already recommended — don't re-teach
        tid = db.topic_id(concept, user_id)
        merged = _merge_mentions(db.get_topic_mentions(tid), c.get("mentions", []))
        weight = compute_weight(merged)
        db.upsert_topic(concept, c.get("class", ""), weight, user_id=user_id)
        db.replace_topic_mentions(tid, merged)
        if weight < LEARN_WEIGHT_THRESHOLD:
            continue   # not yet worth teaching — keep accumulating
        if new_topics >= MAX_NEW_TOPICS_PER_RUN:
            continue   # cap recs/run, but the topic is persisted for next time
        reading = find_reading(concept)
        if reading:
            new_recs += db.upsert_learning_recs(tid, concept, c.get("why_teach", ""), reading,
                                                user_id=user_id)
            db.mark_topic_taught(tid)
            new_topics += 1
    return {"ok": True, "new_topics": new_topics, "new_recs": new_recs}


def analyze_conversations(monitor: dict | None = None, user_id: str | None = None) -> dict:
    """Daily/ad-hoc entry. INCREMENTAL: only conversations updated since the last
    run feed the concept-lift (the prompt stays small). ACCUMULATIVE: each
    topic's mentions are merged with what's stored and the weight recomputed over
    the union, so recurrence builds across runs; a topic is taught (gets recs)
    only once its accumulated weight crosses the threshold, and never re-surfaces
    after. Mirrors the poll_* contract: {ok, new_topics, new_recs, error?}.

    When user_id is given: analyse only that user (ad-hoc route call, no cutoff).
    When user_id is None (scheduler): iterate all users using the sentinel cutoff."""
    try:
        learn_mon = monitor or db.get_monitor("learning", "all")
        cutoff = (learn_mon or {}).get("last_polled_at")

        if user_id:
            # Ad-hoc for one user: ignore cutoff so they always see their full history.
            result = _analyze_for_user(user_id, cutoff=None)
        else:
            # Scheduled pass: cover all users with the incremental cutoff.
            user_ids = db.get_all_user_ids()
            total_topics = total_recs = 0
            for uid in user_ids:
                r = _analyze_for_user(uid, cutoff)
                total_topics += r.get("new_topics", 0)
                total_recs   += r.get("new_recs", 0)
            result = {"ok": True, "new_topics": total_topics, "new_recs": total_recs}

        if learn_mon and not user_id:
            # Only advance the sentinel on scheduler runs; ad-hoc should not move the window.
            db.set_monitor_polled(learn_mon["id"])
        return result
    except Exception as e:
        logger.error("learning analyze failed: %s", e)
        return {"ok": False, "new_topics": 0, "new_recs": 0, "error": str(e)}
