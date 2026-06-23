# Architecture Decision Records

Decisions are recorded in the order they were made. Each entry states the decision, the alternatives considered, and why it was chosen.

---

## ADR-001 — Thread-local stores for per-request state

**Decision:** Use `threading.local()` for per-request accumulators (links, actions, CVE store, package store).

**Why:** Flask with gevent runs multiple requests concurrently in the same process. Module-level dicts would let requests cross-contaminate each other's accumulators. `threading.local()` gives each greenlet its own slot with no locking.

---

## ADR-002 — Haiku as a silent extraction layer

**Decision:** Run `claude-haiku-4-5` as a silent post-processing pass for action extraction, IOC extraction, and conversation titles. Never block the reply on it.

**Why:** These tasks are structurally simple (JSON list output, no reasoning) and high-volume. Haiku is ~10× cheaper and faster than Sonnet. Failures return `[]` silently — extraction is best-effort, never load-bearing.

---

## ADR-003 — Deterministic IDs via uuid5

**Decision:** Use `uuid5(namespace, content)` for action IDs, suggestion dedup keys, and IOC PKs.

**Alternatives considered:** Sequential IDs, random UUIDs, near-hash dedup, embeddings.

**Why:** The same action text always produces the same ID. This makes dedup structural — `INSERT OR IGNORE` is sufficient. No similarity threshold to tune, no semantic drift, no extra dependency.

---

## ADR-004 — Deterministic infra extraction, no LLM

**Decision:** Extract affected vendors and products from CVE.org CPE fields and EUVD product arrays directly. No Haiku call in the infra pipeline.

**Why:** The data is already structured — parsing `cpe:2.3:<type>:<vendor>:<product>:...` is a string split. Running Haiku to re-extract structured data from structured data adds cost and latency with no benefit. The platform-addon exception (WordPress plugin CVE → vendor=WordPress) is handled by a prompt rule in the product extraction system, not the infra pipeline.

---

## ADR-005 — Sonnet passive infra discovery via tool

**Decision:** Expose `add_to_infrastructure` as an agent tool. Sonnet calls it when it detects ownership language in the conversation.

**Alternatives considered:** Haiku post-processing of the reply text, regex over the conversation.

**Why:** Sonnet already reads the full conversation. It can distinguish "our Cisco router" (ownership) from "Cisco routers are affected" (generic). Regex and Haiku would both produce false positives that a reading-comprehension model avoids. The tool call is cheap — it only writes vendor/product/version.

---

## ADR-006 — Deterministic user IDs via uuid5(email)

**Decision:** User IDs are `uuid5(namespace, email)`. Never sequential, never random.

**Why:** The same email always maps to the same ID. This means restoring a database from backup, or re-registering after a wipe, produces the same user row. Foreign keys in conversations and checklists survive a user delete/recreate cycle without orphaned rows.

---

## ADR-007 — Citrix advisory via SSR endpoint

**Decision:** Fetch Citrix bulletins via their server-side-rendered endpoint, not the JS-rendered page.

**Why:** The public Citrix advisory pages are client-rendered. The SSR endpoint returns the same content as plain HTML. Avoids a headless browser dependency.

---

## ADR-008 — Broadcom/VMware advisories via direct HTML parse

**Decision:** Parse VMSA advisory pages directly from `support.broadcom.com`. No Firecrawl.

**Why:** The pages serve full content without JavaScript. A direct `requests.get` + BeautifulSoup parse is sufficient and eliminates an external dependency for this source.

---

## ADR-009 — Source plugin architecture

**Decision:** Each external data source is a Python module in `sources/` declaring `NAME`, `ORDER`, `TOOL_DEF`, and `fetch()`. Auto-discovered, sorted by ORDER, assembled at startup. A uniform wrapper applies telemetry, context stamping, and link/action extraction to every source.

**Alternatives considered:** Keeping all source logic in `tools.py` and `main.py`.

**Why:** `main.py` had grown to 1,300 lines. Adding or removing a source required editing the route, the tool list, the system prompt, and the assembler. Under ADR-009, adding a source is one file. Removing one is `rm sources/name.py` or setting `ENABLED_SOURCES`. The wrapper makes it impossible to forget telemetry or context stamping — it's structural, not convention.

---

## ADR-010 — Tailwind CSS, compiled static file

**Decision:** Use Tailwind CSS compiled to a static `static/tailwind.css`. No CDN Play mode in production.

**Why:** The CDN Play mode scans the DOM at runtime, which is slow and unavailable offline. A compiled file is a single dependency-free asset. Templates use only the pre-compiled class set.

---

## ADR-011 — Due-based scheduling, not cron

**Decision:** The background scheduler checks every 60 seconds whether each monitor is due (`last_polled_at + cadence ≤ now`). No cron expression, no fixed clock times.

**Alternatives considered:** APScheduler with fixed cron triggers, a separate cron job.

**Why:** If the server is offline past a due time, the monitor runs once on next startup — no catch-up storm. Cron would either skip the missed run (silent gap) or fire multiple catch-up runs (storm). Due-based scheduling is self-healing with zero configuration.

---

## ADR-012 — Structured IOC pull via Exa outputSchema

**Decision:** `search_iocs` calls Exa with an `outputSchema` that returns structured IOC fields directly. Haiku per-page fan-out was removed.

**Alternatives considered:** Search + Haiku fan-out over each result page (original implementation). Search + regex extraction.

**Why:** Probe v5: outputSchema returned 17 IOCs / 0 cross-CVE contamination at half the cost of the Haiku fan-out (one call vs 2 searches + ~6 Haiku calls). Source attribution comes from `output.grounding` — each IOC is tied to the URL that produced it, eliminating cross-CVE pollution structurally. Haiku `llm_extract_iocs` is kept as a documented fallback.

---

## ADR-013 — CISA KEV via single catalog fetch

**Decision:** Download the full KEV catalog JSON once and cache it for 6 hours. One fetch serves all War Room CVEs.

**Alternatives considered:** Per-CVE API lookup, Firecrawl page monitoring.

**Why:** The catalog is a single structured JSON file (~1,300 entries). One fetch is cheaper and faster than N per-CVE lookups. Firecrawl was rejected because the feed is already machine-readable. The 6-hour cache means a daily sweep over N CVEs costs one download.

---

## ADR-014 — VirusTotal on-demand, not scheduled

**Decision:** VirusTotal hash lookups are triggered by a button in the War Room, not run automatically.

**Why:** VirusTotal's free tier has a strict rate limit. Running it automatically for every IOC hash would exhaust the quota. On-demand lookup is explicit and quota-friendly. Results are cached in `vt_cache` to avoid re-fetching the same hash.

---

## ADR-015 — Self-observability: measure deterministically, advise with LLM

**Decision:** Token counts, latency, and tool outcomes are captured at three fixed instrumentation points and stored in an append-only table. A separate Opus advisory pass reads an aggregated digest and produces suggestions. The measurement code never calls an LLM.

**Why:** The Anthropic API returns exact `usage` per call — there is no reason to estimate what can be measured. Separating measurement (deterministic) from interpretation (LLM) means the telemetry is always correct even when the advisory model is wrong. Cost is computed at read time from token counts, so a price change re-prices all history for free.

---

## ADR-016 — News feed: feedparser for RSS/Atom, Exa fallback for feed-less blogs

**Decision:** Use `feedparser` for RSS 2.0, Atom, and JSON Feed sources. Fall back to an Exa domain-pinned search for blogs with no published feed.

**Alternatives considered:** A headless browser for all sources, Firecrawl, hand-rolled RSS parsers per format.

**Why:** feedparser handles RSS 2.0, Atom, and JSON Feed in one library. Exa fills the gap for blogs that don't publish a feed (e.g. HeroDevs). A headless browser for everything would be slow and fragile. The hybrid keeps the dependency surface small.

---

## ADR-017 — Grounded verification: different model family, corpus fixed to tool outputs

**Decision:** After Sonnet drafts a reply, Groq `qwen/qwen3-32b` checks it against the exact `tool_result` blocks from that turn. If issues are flagged, Sonnet revises once. No re-fetching. No accept/reject referee.

**Alternatives considered:** Sonnet self-checking its own reply. A referee model that accepted or rejected the draft outright. Re-fetching live data for the verifier.

**Why:** A model grading its own prose is sycophantic — it rationalises its own claims. A different vendor/model family produces independent errors. The corpus is fixed to what Sonnet actually saw because re-fetching would conflate two questions: "was the draft faithful to its sources?" (GV's job) and "were the sources complete?" (out of scope). The accept/reject referee topology was rejected — it added latency without improving output quality. Revision is one shot: a second revision loop would risk overcorrection and adds cost.

---
