"""OBS3 — self-observability advisory engine.

Twice a day, take the deterministic OBS2 telemetry digest and run ONE Opus-4.8
advisory call that proposes architecture / token / load improvements GROUNDED in
the measured numbers. The hard rule — every suggestion must cite a specific
metric, or it is dropped — is enforced both in the prompt AND in code
(`_parse_suggestions` discards any suggestion with no `metric`), so generic
horoscope advice can't reach the suggestion tray.

Probe-verified before building (tests/test_obs3_probe.py, verdict 2026-06-14):
Opus-4.8 at effort=high independently surfaced ISSUE-H1 (Haiku fires on every
reply) and the cache-hit-rate issue from real telemetry, every suggestion tied
to a digest metric. Gate passed → built.

NOT an agent tool (same rule as learning.py / news.py / kev.py): only the 12h
'telemetry' sentinel and the /suggestions/run route call run_advisory().
Opus 4.8 uses adaptive thinking + output_config.effort (manual budget_tokens was
retired — 400s on this model). Sandbox can't reach api.anthropic.com → the
advisory call is user-run; persistence/dedup is fixture-tested offline.
"""
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import db
import telemetry

logger = logging.getLogger(__name__)

# Reasoning-heavy, ~2/day over a compact digest → cost is trivial, so use the
# best model at a deep effort. Opus 4.8: thinking is 'adaptive', depth via
# output_config.effort (low|medium|high|xhigh|max); 'high' is the floor for
# reasoning-heavy work. Overridable for A/B during probing.
OBS_MODEL = os.getenv("OBS3_MODEL", "claude-opus-4-8")
OBS_EFFORT = os.getenv("OBS3_EFFORT", "high")
OBS_CADENCE_HOURS = 12          # 2×/day (OBS4)
MAX_SUGGESTIONS = 4
WINDOW_MAX_DAYS = 7             # cap so long downtime doesn't drag in stale data

_ADVISORY_SYSTEM = """\
You are the self-observability advisor for a local security-consultant app built on \
the Anthropic API. You advise the app's BUILDER on how to reduce cost and improve \
architecture. You are given a deterministic telemetry digest — exact token counts, \
costs, latencies, and call loads captured from the app's own LLM and tool calls.

Your job: propose at most 4 concrete improvements.

HARD RULE — every suggestion MUST cite the specific metric from the digest that \
motivates it (the number, the purpose name, the model). If you cannot tie a \
suggestion to a specific measured value in the digest, DO NOT make it. No generic \
advice. No metric, no suggestion.

Context you may reason from:
- `by_purpose` names map to call sites: `sonnet_loop` is the main reasoning model; \
`haiku_*` are silent extraction calls (actions/products/title) that run as \
post-processing on the SAME turn — if a haiku purpose's call count rivals \
`sonnet_loop`, it is firing on every reply.
- `cache.hit_rate` reflects whether the static prompt-prefix cache (system prompt + \
tool definitions) is paying off; a low value means caching is not helping.
- `cost.monthly_projection_usd` linearly extrapolates the window — treat it as \
unreliable when `window.days` is small.

Return ONLY a JSON array, no prose, no markdown fences. Each element:
{"key": "...", "title": "...", "category": "arch|token|load", "metric": "the exact \
metric + value you are citing", "rationale": "why this follows from that metric", \
"impact": "what improves and roughly how much"}

- key: a STABLE canonical kebab-case identifier for the UNDERLYING issue, so the \
SAME issue gets the SAME key across runs even when you reword the title. Derive it \
from the issue itself, never from the metric's live numbers. Prefer one of these when \
it fits: haiku-extraction-volume, sonnet-tail-latency, prefix-cache-hitrate, \
projection-noise, tool-failure-rate. If none fits, coin a concise stable slug."""


def _slugify(text: str) -> str:
    """Kebab-case a string for use as a stable dedup key."""
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", text.strip().lower())).strip("-")


def _parse_suggestions(raw: str) -> list:
    """Parse the advisory JSON and ENFORCE grounding in code: any suggestion
    without a cited `metric` is dropped (backstop to the prompt rule). Each item
    gets a normalised canonical `key` (from the model, else slugged from the
    title) — that key, not the free-form title, is the dedup identity, since the
    model rewords titles run-to-run. Caps at MAX_SUGGESTIONS."""
    raw = re.sub(r"^```[^\n]*\n?", "", raw.strip())
    raw = re.sub(r"\n?```$", "", raw.strip())
    try:
        data = json.loads(raw)
    except Exception:
        logger.warning("obs advisory returned non-JSON — no suggestions stored")
        return []
    if not isinstance(data, list):
        return []
    out = []
    for s in data:
        if not (isinstance(s, dict) and s.get("title") and s.get("metric")):
            continue   # no metric → not grounded → discard
        item = {k: str(s.get(k, "")).strip()
                for k in ("key", "title", "category", "metric", "rationale", "impact")}
        item["key"] = _slugify(item["key"] or item["title"])   # canonical dedup identity
        out.append(item)
    return out[:MAX_SUGGESTIONS]


def generate_suggestions(digest: dict) -> list:
    """ONE Opus-4.8 advisory call over the digest. Client imported lazily so the
    module loads without the Anthropic client (keeps fixture tests offline)."""
    from extraction import client
    resp = client.messages.create(
        model=OBS_MODEL,
        max_tokens=12000,
        thinking={"type": "adaptive"},
        output_config={"effort": OBS_EFFORT},
        system=_ADVISORY_SYSTEM,
        messages=[{"role": "user",
                   "content": "Telemetry digest:\n\n" + json.dumps(digest)}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    return _parse_suggestions(text)


def run_advisory(monitor: dict | None = None) -> dict:
    """Daily/ad-hoc entry. The window anchors to the sentinel's last successful
    run (not "last 12h"), so a missed check just widens the next digest — nothing
    is lost — capped at WINDOW_MAX_DAYS so long downtime can't drag in stale data.
    Dedup is structural: db.upsert_suggestions INSERT-OR-IGNOREs on uuid5(title),
    so a dismissed/done suggestion never re-surfaces. Mirrors the poll_* contract:
    {ok, new_suggestions, error?}. Failures do NOT advance last_polled_at → the
    run stays due and retries (offline-resilient, )."""
    try:
        mon = monitor or db.get_monitor("telemetry", "advisor")
        cutoff = (mon or {}).get("last_polled_at")
        now = datetime.now(timezone.utc)
        floor = (now - timedelta(days=WINDOW_MAX_DAYS)).isoformat()
        since = max(cutoff, floor) if cutoff else None   # clamp the anchor to the cap

        digest = telemetry.aggregate(since=since, max_window_days=WINDOW_MAX_DAYS)
        if digest["load"]["total_calls"] == 0:
            if mon:
                db.set_monitor_polled(mon["id"])
            return {"ok": True, "new_suggestions": 0, "note": "no telemetry in window"}

        suggestions = generate_suggestions(digest)
        new = db.upsert_suggestions(suggestions)
        if mon:
            db.set_monitor_polled(mon["id"])
        return {"ok": True, "new_suggestions": new, "returned": len(suggestions)}
    except Exception as e:
        logger.error("obs advisory run failed: %s", e)
        return {"ok": False, "new_suggestions": 0, "error": str(e)}
