"""Source plugin loader + assembler (ISSUE-A1).

Each module in this package is one agent tool. Contract:
  NAME           — tool name (str, required)
  ORDER          — position in the tools list (int, required; the highest ORDER
                   is last and receives the prompt-cache breakpoint)
  TOOL_DEF       — Anthropic ToolParam dict (required; cache_control stripped
                   and reassigned by the assembler)
  fetch(**kw)    — the tool callable (required)
  extract_links(result)   -> list[link]                        (optional)
  extract_actions(result) -> (list[action], list[(text, src)]) (optional;
                   actions may omit "id" — the assembler adds it; blobs are
                   decomposed via Haiku)
  PROMPT         — bullet for the system prompt "## Tools" section (optional)
  PROMPT_ORDER   — bullet position, defaults to ORDER (optional)

Removing a source = deleting its file (or excluding it via the
ENABLED_SOURCES env var, comma-separated NAMEs).
"""
import importlib
import pkgutil
import time

import context as ctx
import extraction
import telemetry


def load(enabled: set[str] | None = None) -> list:
    """Import every module in this package that defines TOOL_DEF, optionally
    filtered by NAME, ordered by ORDER."""
    mods = []
    for info in pkgutil.iter_modules(__path__):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{__name__}.{info.name}")
        if not hasattr(mod, "TOOL_DEF"):
            continue
        if enabled is not None and mod.NAME not in enabled:
            continue
        mods.append(mod)
    mods.sort(key=lambda m: m.ORDER)
    return mods


def _make_tracked(mod):
    """Uniform wrapper: run the fetch, then capture links and actions into the
    per-request thread-local stores. Every source gets this — no
    more per-source wrapper functions."""
    def tracked(**kwargs):
        # OBS1 choke point 3: every agent tool flows through this one wrapper, so
        # tool telemetry (latency + outcome — tools have no tokens) drops in here.
        _t0 = time.perf_counter()
        try:
            result = mod.fetch(**kwargs)
        except Exception:
            telemetry.record_tool(mod.NAME, (time.perf_counter() - _t0) * 1000, ok=False)
            raise
        telemetry.record_tool(mod.NAME, (time.perf_counter() - _t0) * 1000, ok=True)
        # Package auto-infra: capture ecosystem+package+version
        # from query_package_vulns results so main.py can save them to the infra
        # hierarchy without an extra Haiku call.
        if mod.NAME == "query_package_vulns" and result.get("found"):
            if not hasattr(ctx.pkg_store, "results"):
                ctx.pkg_store.results = []
            ctx.pkg_store.results.append({
                "ecosystem": result.get("ecosystem", ""),
                "package":   result.get("package", ""),
                "version":   kwargs.get("version", ""),
            })
        if hasattr(mod, "extract_links"):
            ctx.add_links(mod.extract_links(result))
        if hasattr(mod, "extract_actions"):
            actions, blobs = mod.extract_actions(result)
            for a in actions:
                a.setdefault("id", ctx.make_action_id(a["text"]))
            ctx.add_actions(actions)
            if blobs:
                ctx.add_actions(extraction.decompose_blobs(blobs))
        return result
    tracked.__name__ = f"tracked_{mod.NAME}"
    return tracked


def assemble(mods: list) -> tuple[list, dict, list]:
    """Build (tools list, TOOL_REGISTRY, prompt bullets) from loaded modules.
    The last tool definition carries the prompt-cache breakpoint."""
    tools_list, registry, bullets = [], {}, []
    for mod in mods:
        tool_def = {k: v for k, v in mod.TOOL_DEF.items() if k != "cache_control"}
        tools_list.append(tool_def)
        registry[mod.NAME] = _make_tracked(mod)
        prompt = getattr(mod, "PROMPT", None)
        if prompt:
            bullets.append((getattr(mod, "PROMPT_ORDER", mod.ORDER), prompt))
    if tools_list:
        tools_list[-1]["cache_control"] = {"type": "ephemeral"}
    bullets.sort(key=lambda b: b[0])
    return tools_list, registry, [b[1] for b in bullets]
