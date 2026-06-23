"""Per-request runtime state shared between the Flask routes and the source
modules: thread-local accumulators for links/actions, the active conversation
and CVE, and deterministic action IDs.

threading.local() prevents concurrent Flask requests from cross-contaminating
each other's accumulators.
"""
import threading
import uuid

# ── Thread-local stores ──────────────────────────────────────────────────────
link_store     = threading.local()   # .pending: {url: link_obj}
action_store   = threading.local()   # .pending: {action_id: action_obj}
cve_store      = threading.local()   # .result: last primary CVE lookup result (auto-infra)
euvd_store     = threading.local()   # .result: last fetch_euvd_cve result (fallback)
cve_retry      = threading.local()   # .cve_id: CVE that failed primary lookup, needs background retry

# Backward-compat aliases — remove once all callers migrated
nvd_store = cve_store
nvd_retry = cve_retry
pkg_store      = threading.local()   # .results: [{ecosystem, package, version}] from package tool calls
current_conv   = threading.local()   # .conv_id: active conversation
current_cve_id = threading.local()   # .value: CVE most recently parsed this request
prefetch_cache = threading.local()   # .cache: dict warmed by gevent prefetch greenlets
advisor_store  = threading.local()   # .called: bool, .count: int — per-turn Opus consult tracking
conv_messages  = threading.local()   # .messages: live message list reference set by main.py

# Stable namespace for deterministic action IDs (uuid5 of action text)
_ACTION_NS = uuid.UUID("7f4a3b2c-1d5e-4f6a-8b9c-0d1e2f3a4b5c")


def make_action_id(text: str) -> str:
    return str(uuid.uuid5(_ACTION_NS, text))


# ── Prefetch cache (gevent-native; see sources/nvd._spawn_prefetch) ────────────

def init_prefetch() -> dict:
    """Fresh per-request cache dict. Spawned prefetch greenlets hold this
    reference directly — greenlet-local storage isn't shared across greenlets,
    so the dict object is passed by reference at spawn time."""
    prefetch_cache.cache = {}
    return prefetch_cache.cache


def get_prefetch(source: str, cve_id: str):
    """Return a prefetched raw API response for source+CVE, or None on miss.
    A miss (greenlet still running, failed, or no hub to run it) falls back to a
    live fetch in the caller — identical result, just not pre-warmed."""
    cache = getattr(prefetch_cache, "cache", None)
    if cache is None:
        return None
    return cache.get(f"{source}:{cve_id.upper()}")


# ── Links ────────────────────────────────────────────────────────────────────

def reset_links():
    link_store.pending = {}


def add_links(links: list):
    if not hasattr(link_store, "pending"):
        link_store.pending = {}
    for link in links:
        link_store.pending[link["url"]] = link


def flush_links() -> dict:
    return getattr(link_store, "pending", {})


# ── Actions ──────────────────────────────────────────────────────────────────

def reset_actions():
    action_store.pending = {}


def add_actions(actions: list):
    if not hasattr(action_store, "pending"):
        action_store.pending = {}
    current_cve = getattr(current_cve_id, "value", None)
    for action in actions:
        if current_cve and "cve_id" not in action:
            action = {**action, "cve_id": current_cve}
        action_store.pending[action["id"]] = action


def flush_actions() -> dict:
    return getattr(action_store, "pending", {})
