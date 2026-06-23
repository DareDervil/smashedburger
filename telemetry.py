"""OBS1 + OBS2 — self-observability telemetry.

Core principle: **measurement is deterministic code, never an LLM.** The
Anthropic API returns exact `usage` per call, so token counts, latency, and
outcome are captured verbatim at three choke points and aggregated with plain
arithmetic. An LLM (OBS3, built later) only *interprets* this digest — it never
estimates a number that can be measured.

  OBS1 — capture: `record_llm` / `record_tool` write append-only rows. Recording
         must NEVER break the request it instruments, so every write is wrapped
         and swallows its own errors.
  OBS2 — aggregate: `aggregate()` turns raw events into the compact cost/load/
         delta digest that is OBS3's only input.

Cost is computed here, on read — never stored. A price change therefore
re-prices all history for free. Prices live in ONE config constant below
(they drift; confirm at build) and nowhere else.
"""
import logging
import math
from datetime import datetime, timedelta, timezone

import context as ctx

logger = logging.getLogger(__name__)
import db

# ── OBS2 price config — the single source of truth for token prices ───────────
# USD per token (list price ÷ 1e6). Confirmed against Anthropic API pricing on
# 2026-06-14. Prices drift — re-confirm when models change, edit ONLY here.
#   Opus 4.8    $5 / $25   per Mtok (in/out)
#   Sonnet 4.6  $3 / $15
#   Haiku 4.5   $1 / $5
MODEL_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-8":           {"input": 5.00 / 1e6, "output": 25.00 / 1e6},
    "claude-sonnet-4-6":         {"input": 3.00 / 1e6, "output": 15.00 / 1e6},
    "claude-haiku-4-5-20251001": {"input": 1.00 / 1e6, "output":  5.00 / 1e6},
}
# Anthropic's `usage.input_tokens` EXCLUDES cached/cache-creation tokens, so the
# three input buckets are priced independently:
CACHE_READ_MULT  = 0.10   # reading from cache is 90% cheaper than fresh input
CACHE_WRITE_MULT = 1.25   # writing the 5-minute cache costs 25% more than input

PROJECTION_DAYS = 30      # monthly projection horizon


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── OBS1 — capture ────────────────────────────────────────────────────────────

def _conv_id() -> str | None:
    """Active conversation, if a Flask /send set it (chat/extraction choke points
    run inside a request). None for background jobs."""
    return getattr(ctx.current_conv, "conv_id", None)


def record_llm(name: str, model: str | None, usage, latency_ms: float,
               ok: bool = True, conv_id: str | None = None) -> None:
    """Capture one LLM call. `usage` is an Anthropic Usage object (or None on a
    failed call); token fields are read defensively so a shape change degrades to
    zeros rather than raising into the request."""
    try:
        db.insert_telemetry_event(
            kind="llm", name=name, model=model,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            latency_ms=round(latency_ms), ok=ok,
            conv_id=conv_id if conv_id is not None else _conv_id(),
        )
    except Exception as exc:  # telemetry must never break the instrumented call
        logger.warning("telemetry record_llm dropped: %s", exc)


def record_tool(name: str, latency_ms: float, ok: bool = True,
                conv_id: str | None = None) -> None:
    """Capture one tool call (no tokens — tools are deterministic HTTP/CPU work)."""
    try:
        db.insert_telemetry_event(
            kind="tool", name=name, model=None,
            latency_ms=round(latency_ms), ok=ok,
            conv_id=conv_id if conv_id is not None else _conv_id(),
        )
    except Exception as exc:
        logger.warning("telemetry record_tool dropped: %s", exc)


# ── OBS2 — cost + aggregation ─────────────────────────────────────────────────

def event_cost(row: dict) -> float:
    """USD for one llm event. Tool/crud events cost nothing here. Unknown models
    cost 0 (and are flagged by aggregate so a missing price is visible, not silent)."""
    if row.get("kind") != "llm":
        return 0.0
    p = MODEL_PRICING.get(row.get("model") or "")
    if not p:
        return 0.0
    return (
        row.get("input_tokens", 0)          * p["input"]
        + row.get("output_tokens", 0)       * p["output"]
        + row.get("cache_read_tokens", 0)   * p["input"] * CACHE_READ_MULT
        + row.get("cache_creation_tokens", 0) * p["input"] * CACHE_WRITE_MULT
    )


def _pct(values: list[float], p: float) -> float:
    """Nearest-rank percentile (deterministic, no interpolation)."""
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, math.ceil(p / 100 * len(s)) - 1)
    return s[k]


def _window_days(since: str, until: str) -> float:
    span = (datetime.fromisoformat(until) - datetime.fromisoformat(since)).total_seconds()
    return max(span / 86400, 1e-9)  # guard divide-by-zero on a zero-width window


def _summarise(rows: list[dict], since: str, until: str) -> dict:
    """Pure arithmetic over a row set → cost + load digest for one window."""
    total_cost = sum(event_cost(r) for r in rows)
    cost_by_model: dict[str, float] = {}
    unpriced_models: set[str] = set()
    for r in rows:
        if r.get("kind") != "llm":
            continue
        model = r.get("model") or "unknown"
        cost_by_model[model] = cost_by_model.get(model, 0.0) + event_cost(r)
        if (r.get("model") or "") not in MODEL_PRICING:
            unpriced_models.add(model)

    by_purpose: dict[str, dict] = {}
    for r in rows:
        b = by_purpose.setdefault(r["name"], {"calls": 0, "failures": 0, "_lat": []})
        b["calls"] += 1
        if not r.get("ok", 1):
            b["failures"] += 1
        b["_lat"].append(r.get("latency_ms", 0))
    for name, b in by_purpose.items():
        lat = b.pop("_lat")
        b["p50_latency_ms"] = _pct(lat, 50)
        b["p95_latency_ms"] = _pct(lat, 95)

    tool_rows = [r for r in rows if r.get("kind") == "tool"]
    tool_failures = sum(1 for r in tool_rows if not r.get("ok", 1))

    # Cache economics — are the system-prompt + tools cache breakpoints hitting?
    # `input_tokens` is fresh (uncached) input; cache_read is served from cache;
    # cache_creation is the one-time 5-min write. hit_rate = read / (read + fresh),
    # i.e. of the input that could be cached, how much actually was.
    fresh_in = sum(r.get("input_tokens", 0) for r in rows if r.get("kind") == "llm")
    cache_read = sum(r.get("cache_read_tokens", 0) for r in rows if r.get("kind") == "llm")
    cache_write = sum(r.get("cache_creation_tokens", 0) for r in rows if r.get("kind") == "llm")
    cacheable = cache_read + fresh_in

    days = _window_days(since, until)
    daily_rate = total_cost / days
    return {
        "window": {"since": since, "until": until, "days": round(days, 4)},
        "cache": {
            "fresh_input_tokens": fresh_in,
            "cache_read_tokens": cache_read,
            "cache_creation_tokens": cache_write,
            "hit_rate": round(cache_read / cacheable, 4) if cacheable else 0.0,
        },
        "cost": {
            "total_usd": round(total_cost, 6),
            "by_model": {m: round(c, 6) for m, c in cost_by_model.items()},
            "daily_rate_usd": round(daily_rate, 6),
            "monthly_projection_usd": round(daily_rate * PROJECTION_DAYS, 4),
            "unpriced_models": sorted(unpriced_models),
        },
        "load": {
            "total_calls": len(rows),
            "by_purpose": by_purpose,
            "tool_calls": len(tool_rows),
            "tool_failures": tool_failures,
            "tool_failure_rate": round(tool_failures / len(tool_rows), 4) if tool_rows else 0.0,
            "advisor_calls": sum(1 for r in tool_rows if r.get("name") == "ask_advisor"),
        },
    }


def aggregate(since: str | None = None, until: str | None = None,
              max_window_days: float = 7.0) -> dict:
    """OBS2 digest. Window is [since, until); when `since` is omitted it anchors to
    the earliest event (capped at `max_window_days` so long downtime doesn't drag
    in stale data — OBS4's "anchor to last run, cap the window" rule). Also returns
    deltas vs the immediately-preceding equal-length window."""
    until = until or _now()
    if since is None:
        earliest = db.first_telemetry_ts()
        cap_floor = (datetime.fromisoformat(until)
                     - timedelta(days=max_window_days)).isoformat()
        since = max(earliest, cap_floor) if earliest else cap_floor

    rows = db.get_telemetry_events(since, until)
    digest = _summarise(rows, since, until)

    # Deltas vs the previous window of identical length.
    span = datetime.fromisoformat(until) - datetime.fromisoformat(since)
    prev_since = (datetime.fromisoformat(since) - span).isoformat()
    prev_rows = db.get_telemetry_events(prev_since, since)
    prev = _summarise(prev_rows, prev_since, since)
    digest["deltas"] = {
        "prev_window": {"since": prev_since, "until": since},
        "cost_total_usd": round(digest["cost"]["total_usd"] - prev["cost"]["total_usd"], 6),
        "total_calls": digest["load"]["total_calls"] - prev["load"]["total_calls"],
        "tool_failures": digest["load"]["tool_failures"] - prev["load"]["tool_failures"],
    }
    return digest
