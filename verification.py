"""GV — grounded verification pass. Optional anti-hallucination gate.

After Sonnet drafts a briefing, a DIFFERENT model (Groq openai/gpt-oss-120b — speed +
error-diversity) checks the draft against the EXACT tool outputs Sonnet reasoned
from THIS turn (the new_messages tool_result blocks + ctx.nvd_store) — it NEVER
re-fetches. Claims that contradict or aren't supported by that corpus are flagged,
and Sonnet revises ONCE. No referee, no accept/reject: draft → critique-vs-sources
→ revise once (see PROGRESS GV section for why the referee topology was rejected).

Lives entirely outside the `sources/` registry and the agentic loop — it is a
post-reply gate in /send only. Graceful-skip when GROQ_API_KEY is absent: the
draft passes through untouched.

Educational note — *why a different model and why grounded against tool output*:
an LLM grading its own prose is sycophantic (it rationalises its own claims), so
GV uses a separate vendor/model for error-diversity. And the corpus is fixed to
what Sonnet actually saw — re-fetching would let the verifier "correct" the draft
against NEW facts, conflating two different jobs (was the draft faithful to its
sources? vs. were the sources complete?). GV only answers the first. Completeness
("Sonnet should have called tool X") is a separate, deliberately out-of-scope
feature.
"""
import json
import logging
import os
import re
import time

import requests

logger = logging.getLogger(__name__)

# ── Groq client config ───────────────────────────────────────────────────────
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")  # reasoning model

# Gate: only verify substantive replies (the ISSUE-H1 "don't run on thin turns"
# lesson). Short conversational acknowledgements carry no grounded claims worth
# checking.
MIN_REPLY_CHARS = 400

# Corpus cap — the verifier prompt should stay focused; huge tool dumps (Red Hat
# Log4Shell = 40+ releases) are truncated rather than blowing the context.
CORPUS_MAX_CHARS = 14000

# Tools whose output is NOT ground truth to check a briefing against.
# - add_to_infrastructure: writes to inventory, asserts nothing about the vulnerability.
# - ask_advisor: Opus reasoning is not a primary source — GV must not verify
#   Sonnet's reply against Opus's advice as if it were factual CVE data.
_NON_GROUNDING_TOOLS = {"add_to_infrastructure", "ask_advisor"}


# ── Circuit breaker ──────────────────────────────────────────────────────────
# Tracks consecutive Groq failures in-process. After CB_THRESHOLD failures the
# verifier is skipped for CB_COOLDOWN seconds, preventing 60s×N hangs on every
# user turn when Groq is down. Resets to 0 on the first successful call.
# In-memory only — resets on process restart, which is the right behaviour
# (a fresh deploy should retry rather than stay tripped from a previous outage).
CB_THRESHOLD = 3
CB_COOLDOWN  = 300  # seconds

_cb_failures    = 0
_cb_disabled_until = 0.0   # unix timestamp; 0 = not tripped


def _cb_record_success() -> None:
    global _cb_failures, _cb_disabled_until
    _cb_failures       = 0
    _cb_disabled_until = 0.0


def _cb_record_failure() -> None:
    global _cb_failures, _cb_disabled_until
    _cb_failures += 1
    if _cb_failures >= CB_THRESHOLD:
        _cb_disabled_until = time.time() + CB_COOLDOWN
        logger.warning(
            "GV circuit breaker OPEN — %d consecutive failures, skipping GV for %ds",
            _cb_failures, CB_COOLDOWN,
        )


def _cb_is_open() -> bool:
    """Returns True when the breaker is tripped and the cooldown hasn't expired."""
    global _cb_disabled_until
    if _cb_disabled_until and time.time() < _cb_disabled_until:
        return True
    if _cb_disabled_until and time.time() >= _cb_disabled_until:
        # Cooldown expired — move to half-open (allow one attempt through)
        logger.info("GV circuit breaker HALF-OPEN — retrying Groq")
        _cb_disabled_until = 0.0
    return False


def is_available() -> bool:
    """GV runs only when a Groq key is configured AND the circuit breaker is closed."""
    return bool(os.getenv("GROQ_API_KEY")) and not _cb_is_open()


# ── Corpus assembly (the EXACT tool outputs Sonnet reasoned from) ─────────────

def _block_attr(block, name, default=None):
    """Blocks may be SDK pydantic objects (fresh this turn) or plain dicts
    (rehydrated from SQLite). Read either shape uniformly."""
    if isinstance(block, dict):
        return block.get(name, default)
    return getattr(block, name, default)


def _tool_name_map(new_messages) -> dict:
    """tool_use_id → tool name, harvested from this turn's assistant tool_use
    blocks, so each tool_result can be labelled with the tool that produced it."""
    names = {}
    for msg in new_messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if not isinstance(content, (list, tuple)):
            continue
        for block in content:
            if _block_attr(block, "type") == "tool_use":
                names[_block_attr(block, "id")] = _block_attr(block, "name")
    return names


def grounding_tool_called(new_messages) -> bool:
    """True if this turn called at least one grounding tool (anything that
    fetched vulnerability data — i.e. any tool except the inventory writer)."""
    for msg in new_messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if not isinstance(content, (list, tuple)):
            continue
        for block in content:
            if _block_attr(block, "type") == "tool_use" and \
               _block_attr(block, "name") not in _NON_GROUNDING_TOOLS:
                return True
    return False


def build_corpus(new_messages, nvd_result=None, max_chars: int = CORPUS_MAX_CHARS) -> str:
    """Assemble the grounding corpus from this turn's tool_result blocks (labelled
    with their tool name) plus ctx.nvd_store. The verifier checks the draft against
    THIS and nothing else — never a re-fetch."""
    names  = _tool_name_map(new_messages)
    chunks = []
    for msg in new_messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if not isinstance(content, (list, tuple)):
            continue
        for block in content:
            if _block_attr(block, "type") != "tool_result":
                continue
            tool_id = _block_attr(block, "tool_use_id")
            name    = names.get(tool_id, "tool")
            if name in _NON_GROUNDING_TOOLS:
                continue
            payload = _block_attr(block, "content", "")
            if isinstance(payload, (list, tuple)):
                # content can itself be a list of text blocks
                payload = " ".join(str(_block_attr(p, "text", p)) for p in payload)
            chunks.append(f"### {name}\n{str(payload).strip()}")

    if nvd_result:
        chunks.append("### primary CVE source (ctx.cve_store)\n" +
                      json.dumps(nvd_result, default=str))

    corpus = "\n\n".join(chunks).strip()
    if len(corpus) > max_chars:
        corpus = corpus[:max_chars] + "\n…[corpus truncated]"
    return corpus


def should_verify(new_messages, reply: str, on_demand: bool = False) -> bool:
    """Gate. Auto: a grounding tool was called this turn AND the reply is
    substantive. On-demand ("verify this"): bypass the gate — but the caller
    still needs a non-empty corpus to verify against."""
    if on_demand:
        return True
    if not reply or len(reply.strip()) < MIN_REPLY_CHARS:
        return False
    return grounding_tool_called(new_messages)


# ── The verifier (Groq) ──────────────────────────────────────────────────────

VERIFIER_SYSTEM = """You are a grounding verifier for security vulnerability briefings. \
You are given SOURCE DATA (the exact tool outputs a consultant reasoned from) and a DRAFT \
briefing. Your only job: identify claims in the draft that CONTRADICT the source data, or that \
assert specifics (versions, CVSS scores, exploitation status, affected products) which the \
source data does not support.

Rules:
- Flag a claim ONLY if it conflicts with the source data, or states a specific fact absent from it.
- Do NOT flag reasonable security inferences, general best-practice recommendations, or style.
- Do NOT flag claims that are consistent with the source data.

Return STRICT JSON: {"supported": true|false, "issues": [{"claim": "...", "problem": "..."}]}. \
If everything checks out, return {"supported": true, "issues": []}. Output JSON only."""


def _groq_post(payload: dict, max_retries: int = 6) -> dict:
    """POST with 429 backoff — Groq's free tier rate-limits bursts. Honours the
    Retry-After header when present, else exponential backoff.
    Records success/failure for the circuit breaker."""
    key = os.getenv("GROQ_API_KEY", "")
    for attempt in range(max_retries):
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=payload, timeout=60)
        if resp.status_code == 429:
            wait = float(resp.headers.get("retry-after", 2 ** attempt))
            time.sleep(wait)
            continue
        resp.raise_for_status()
        _cb_record_success()
        return resp.json()
    resp.raise_for_status()   # raises — caller records failure
    return resp.json()        # unreachable


def _parse_verdict(content: str) -> dict:
    """Robust to reasoning models: strip <think>…</think>, code fences, and any
    prose around the JSON object. Defensive even though reasoning_format:hidden
    should keep <think> out of the content."""
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
    content = re.sub(r"^```[^\n]*\n?|\n?```$", "", content.strip())
    try:
        return json.loads(content)
    except Exception:
        m = re.search(r"\{.*\}", content, flags=re.S)   # first { … last }
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        # Un-parseable verdict = treat as supported (fail-open: never corrupt a
        # draft on a verifier glitch).
        return {"supported": True, "issues": [], "_parse_error": content[:200]}


def verify(corpus: str, draft: str) -> dict:
    """Run the Groq verifier on (corpus, draft). Returns the parsed verdict dict
    {"supported": bool, "issues": [...]}. Fail-open on any error."""
    payload = {
        "model": GROQ_MODEL,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": VERIFIER_SYSTEM},
            {"role": "user", "content": f"SOURCE DATA:\n{corpus}\n\nDRAFT BRIEFING:\n{draft}"},
        ],
        "response_format": {"type": "json_object"},
        # gpt-oss-120b is a reasoning model — keep its <think> out of the content.
        "reasoning_format": "hidden",
    }
    try:
        data = _groq_post(payload)
        return _parse_verdict(data["choices"][0]["message"]["content"])
    except Exception as e:
        _cb_record_failure()
        return {"supported": True, "issues": [], "_error": str(e)}


def flagged(verdict: dict) -> bool:
    return verdict.get("supported") is False or bool(verdict.get("issues"))


def _issues_str(verdict: dict) -> str:
    return "\n".join(
        f"- {i.get('claim','')}: {i.get('problem','')}" for i in verdict.get("issues", [])
    )


# ── The revise step (Sonnet, one shot, no tools) ──────────────────────────────

REVISE_SYSTEM = """You are revising a security vulnerability briefing you drafted. A grounding \
verifier compared your draft against the SOURCE DATA (the exact tool outputs that were available \
to you) and flagged claims that contradict or are not supported by it.

Produce a corrected version of the briefing that:
- fixes ONLY the flagged claims, using the SOURCE DATA as the ground truth
- corrects or removes any specific claim the source data does not support (do not replace one \
unsupported specific with another — if the source gives no fixed version, do not invent one)
- preserves everything else: the structure, tone, section headings, and all correct content

Output the corrected briefing prose only. No preamble, no list of changes, no tool calls."""


def revise(client, model: str, draft: str, corpus: str, verdict: dict,
           max_tokens: int = 4096) -> str:
    """One Sonnet pass that rewrites the draft to fix the flagged issues. Standalone
    messages.create — NOT the agentic loop, no tools — so GV never re-enters tool
    use. On any error, returns the original draft (fail-open)."""
    user = (f"SOURCE DATA:\n{corpus}\n\n"
            f"FLAGGED ISSUES:\n{_issues_str(verdict)}\n\n"
            f"YOUR DRAFT:\n{draft}")
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=REVISE_SYSTEM,
            messages=[{"role": "user", "content": user}],
        )
        for block in resp.content:
            if getattr(block, "type", None) == "text" and block.text.strip():
                return block.text.strip()
        return draft
    except Exception:
        return draft


# ── Orchestrator ──────────────────────────────────────────────────────────────

def _replace_final_assistant_text(messages, new_text: str) -> bool:
    """Replace the last assistant message (the end_turn final prose) with the
    revised text so conversation history + persistence reflect what the user saw.
    Returns True if a message was replaced."""
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            messages[i] = {"role": "assistant", "content": new_text}
            return True
    return False


def run_gv(client, model: str, reply: str, new_messages, nvd_result=None,
           messages=None, on_demand: bool = False) -> dict:
    """The full GV pass for one turn.

    Flow: gate → verify-against-corpus → (if flagged) Sonnet revises once → final.
    The caller substitutes the returned `reply` for the draft and runs Haiku
    extraction on it (Haiku must see the REVISED prose, not the draft).

    `messages` (the live CVEChat history list) is mutated in place when a revision
    happens, so persistence and future turns reflect the corrected reply.

    Returns:
      reply   — final prose (revised, or the original draft)
      ran     — whether GV actually ran (passed the gate + had a key + corpus)
      revised — whether the reply was changed
      verdict — the verifier verdict (or None)
      reason  — why GV skipped, when ran is False
    """
    if not is_available():
        return {"reply": reply, "ran": False, "revised": False,
                "verdict": None, "reason": "no_groq_key"}

    if not should_verify(new_messages, reply, on_demand=on_demand):
        return {"reply": reply, "ran": False, "revised": False,
                "verdict": None, "reason": "gate_not_met"}

    corpus = build_corpus(new_messages, nvd_result)
    if not corpus:
        # On-demand with nothing grounded this turn, or a tool-less turn.
        return {"reply": reply, "ran": False, "revised": False,
                "verdict": None, "reason": "empty_corpus"}

    verdict = verify(corpus, reply)
    if not flagged(verdict):
        return {"reply": reply, "ran": True, "revised": False,
                "verdict": verdict, "reason": None}

    revised = revise(client, model, reply, corpus, verdict)
    changed = revised.strip() != reply.strip()
    if changed and messages is not None:
        _replace_final_assistant_text(messages, revised)
    return {"reply": revised, "ran": True, "revised": changed,
            "verdict": verdict, "reason": None}
