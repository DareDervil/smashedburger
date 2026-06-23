"""ask_advisor — mid-generation Opus consult for security judgement and infra questions.

Sonnet calls this tool when the user's question requires reasoning about their
specific environment or security posture — not generic CVE facts. Opus receives
the full conversation history, current turn tool results, and the infra snapshot,
then returns targeted advice which Sonnet incorporates into its reply.

Architecture note: Opus is called via a plain Anthropic API call (no tools, no
agentic loop). It cannot write to DB or call any tools — it returns text only.
Sonnet remains the orchestrator; Opus is a one-shot consult, not a replacement.

Capped at 2 calls per turn via ctx.advisor_store.count (thread-local, reset each request).
"""
import json
import logging
import os
import time

import anthropic

import context as ctx
import db

logger = logging.getLogger(__name__)

NAME  = "ask_advisor"
ORDER = 99  # High ORDER → last in assembled tool list, preserving cache_control
            # on the real source tools that precede it.

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Consult a senior security advisor (Opus) for questions that require reasoning "
        "about the user's specific infrastructure or security posture. "
        "Call this ONLY when the user asks: "
        "(1) whether their specific environment is exposed to a vulnerability, "
        "(2) which CVE or risk to prioritise given their stack, "
        "(3) for a security judgement or recommendation tailored to their situation. "
        "Do NOT call this for general CVE facts, CVSS scores, patch notes, or any "
        "question answerable from the already-fetched source data. "
        "One focused question per call. Maximum 2 calls per turn."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": (
                    "The specific security or infra question to consult Opus on. "
                    "Be precise — include the CVE ID and relevant context from this session."
                ),
            },
        },
        "required": ["question"],
    },
}

_ADVISOR_SYSTEM = """\
You are a senior security consultant advising on a specific client environment.
You will be given:
- INFRASTRUCTURE: the client's known vendor/product stack
- CONVERSATION: the full advisory session so far, including CVE data fetched from NVD, KEV, ExploitDB etc.
- QUESTION: what the consultant needs your judgement on

Your job: give a concise, specific, actionable answer grounded in the client's actual stack and the CVE data shown.
Do not hedge with generic advice. Do not repeat facts already stated in the conversation.
Focus on the delta — what the consultant needs to know to answer the client's question well.
Maximum 4 sentences. Be direct."""

_CONV_CAP = 12_000   # chars — tail of conversation passed to Opus
_TOOL_CAP  = 2_000   # chars per tool result block


def _infra_text(infra: list) -> str:
    if not infra:
        return "No infrastructure recorded yet."
    lines = []
    for v in infra:
        products = ", ".join(
            p["name"] + (f" ({p['category']})" if p["category"] != "other" else "")
            for p in v["products"]
        ) or "—"
        lines.append(f"  {v['name']}: {products}")
    return "\n".join(lines)


def _conv_text(messages: list) -> str:
    """Flatten conversation + tool results to plain text, capped at _CONV_CAP chars."""
    parts = []
    for m in messages:
        role    = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, str):
            parts.append(f"[{role.upper()}] {content}")
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    parts.append(f"[{role.upper()}] {block['text']}")
                elif btype == "tool_use":
                    parts.append(
                        f"[TOOL CALL: {block.get('name')}] "
                        f"{json.dumps(block.get('input', {}))}"
                    )
                elif btype == "tool_result":
                    for inner in (block.get("content") or []):
                        if isinstance(inner, dict) and inner.get("type") == "text":
                            parts.append(f"[TOOL RESULT] {inner['text'][:_TOOL_CAP]}")
    text = "\n\n".join(parts)
    # Take the tail — most recent context is most relevant to the current question
    return text[-_CONV_CAP:] if len(text) > _CONV_CAP else text


def fetch(question: str) -> dict:
    """Called by Sonnet mid-generation. Consults Opus and returns its advice as text."""
    # ── Rate limit: max 2 calls per turn ────────────────────────────────────
    count = getattr(ctx.advisor_store, "count", 0)
    if count >= 2:
        logger.warning("ask_advisor: cap reached (2/turn), skipping Opus call")
        return {"advice": "Advisor already consulted twice this turn. Use the guidance already provided."}

    ctx.advisor_store.count  = count + 1
    ctx.advisor_store.called = True

    # ── Build Opus context ───────────────────────────────────────────────────
    infra     = db.get_infrastructure()
    messages  = getattr(ctx.conv_messages, "messages", [])

    user_content = (
        f"INFRASTRUCTURE:\n{_infra_text(infra)}\n\n"
        f"CONVERSATION:\n{_conv_text(messages)}\n\n"
        f"QUESTION:\n{question}"
    )

    # ── Call Opus (plain messages.create — no tools, no loop) ───────────────
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))
    n = ctx.advisor_store.count
    logger.info("send Advisor → Opus consult (call %d/2) question=%d chars", n, len(question))
    _t0 = time.perf_counter()
    try:
        response = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=512,
            system=_ADVISOR_SYSTEM,
            messages=[{"role": "user", "content": user_content}],
        )
        advice = response.content[0].text.strip()
        logger.info("send Advisor ✓ %.1fs advice=%d chars (call %d/2)",
                    time.perf_counter() - _t0, len(advice), n)
        return {"advice": advice}
    except Exception as exc:
        logger.error("send Advisor ✗ %.1fs %s", time.perf_counter() - _t0, exc)
        ctx.advisor_store.count -= 1   # Don't penalise the cap on API failure
        return {"advice": f"Advisor unavailable ({exc}). Proceed with available data."}
