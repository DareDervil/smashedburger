"""graph.py — Local attack graph computation.

Converts the flat infra/CVE data model into a weighted directed graph suitable
for the force-graph renderer. All edge weights are computed server-side; the
renderer is a pure visual layer.

Node ID scheme (stable, lowercase):
  cve:<cve-id>                    e.g. cve:cve-2021-44228
  product:<vendor>:<product>      e.g. product:apache:log4j
  os:<vendor>:<product>           e.g. os:canonical:ubuntu
  zone:<name>                     e.g. zone:internet, zone:dmz, zone:internal

Weight formula (multiplicative — any factor near 0 collapses the weight):
  weight = (cvss/10) × av_reach × scope_mult × epss × constraint × confidence × hop_decay^(hops-1)

  av_reach    : AV:N→1.0  AV:A→0.7  AV:L→0.4  AV:P→0.1
                NOTE: for intra-layer edges (library inside app) AV:L is boosted to 0.9
                because the attacker is already inside the same process boundary.
  scope_mult  : S:C→1.3  S:U→1.0   (Changed scope = cross-boundary propagation)
  epss        : 0–1 exploitation probability (defaults to 0.5 when unknown)
  constraint  : air_gap→0.0  port_restriction(blocking)→0.1  firewall→0.6  waf→0.8  none→1.0
  confidence  : user_confirmed→1.0  inferred→0.7
  hop_decay   : 0.8 per hop beyond the first (max 3 hops total)
"""
import re
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_AV_REACH = {"N": 1.0, "A": 0.7, "L": 0.4, "P": 0.1}
_AV_REACH_INTRA = {"N": 1.0, "A": 0.9, "L": 0.9, "P": 0.5}  # same process/host
_SCOPE_MULT = {"C": 1.3, "U": 1.0}
_CONSTRAINT_FACTOR = {
    "air_gap":         0.0,
    "port_restriction":0.1,   # refined per-CVE below if ports match
    "firewall":        0.6,
    "dmz":             0.85,
    "waf":             0.8,
}
_DEFAULT_EPSS    = 0.5   # used when EPSS not yet fetched
_INFERRED_CONF   = 0.7
_CONFIRMED_CONF  = 1.0
_HOP_DECAY       = 0.8
_MAX_HOPS        = 3


# ── Node ID helpers ───────────────────────────────────────────────────────────

def _slug(s: str) -> str:
    """Lowercase, collapse non-alphanumeric runs to underscore."""
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _vendor_slug(vendor_name: str) -> str:
    """Use first meaningful word of the vendor name as the slug component.
    'Apache Software Foundation' → 'apache', 'Canonical Ltd.' → 'canonical'.
    This matches what Sonnet naturally writes in node IDs."""
    first = vendor_name.strip().split()[0] if vendor_name.strip() else vendor_name
    return _slug(first)


def product_node_id(vendor_name: str, product_name: str, category: str = "") -> str:
    prefix = "os" if category == "operating_system" else "product"
    return f"{prefix}:{_vendor_slug(vendor_name)}:{_slug(product_name)}"


def cve_node_id(cve_id: str) -> str:
    return f"cve:{cve_id.lower()}"


# ── CVSS vector parsing ───────────────────────────────────────────────────────

def _parse_vector(vector: str | None) -> dict:
    """Extract AV and S fields from a CVSS v3 vector string.
    e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' → {'AV': 'N', 'S': 'C'}
    Returns empty dict for v2 vectors or None input."""
    if not vector:
        return {}
    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v
    return parts


# ── Weight computation ────────────────────────────────────────────────────────

def _constraint_factor(node_id: str, constraints_by_node: dict) -> float:
    """Aggregate constraint factor for a node. Multiple constraints compound."""
    node_constraints = constraints_by_node.get(node_id, [])
    if not node_constraints:
        return 1.0
    factor = 1.0
    for c in node_constraints:
        factor *= _CONSTRAINT_FACTOR.get(c["constraint_type"], 1.0)
    return factor


def _compute_weight(cvss_score: float | None,
                    vector_fields: dict,
                    epss: float | None,
                    constraint_f: float,
                    confidence_f: float,
                    hops: int,
                    intra_layer: bool = False) -> float:
    """Core weight formula. Returns 0.0–1.0 (clamped)."""
    base       = (cvss_score or 0.0) / 10.0
    av         = vector_fields.get("AV", "N")
    reach_map  = _AV_REACH_INTRA if intra_layer else _AV_REACH
    av_reach   = reach_map.get(av, 1.0)
    scope_mult = _SCOPE_MULT.get(vector_fields.get("S", "U"), 1.0)
    epss_f     = epss if epss is not None else _DEFAULT_EPSS
    decay      = _HOP_DECAY ** max(0, hops - 1)

    weight = base * av_reach * scope_mult * epss_f * constraint_f * confidence_f * decay
    return round(min(max(weight, 0.0), 1.0), 4)


# ── Main entry point ──────────────────────────────────────────────────────────

def build_attack_graph(cves: list, infra: list,
                       relationships: list, constraints: list) -> dict:
    """Build the full node + edge payload for the attack graph renderer.

    Args:
        cves          : list of CVE dicts from get_cve_dashboard()
        infra         : list of vendor dicts from get_infrastructure()
        relationships : list of infra_relationship dicts from get_attack_graph_data()
        constraints   : list of network_constraint dicts from get_attack_graph_data()

    Returns:
        {"nodes": [...], "edges": [...]}
    """
    nodes = {}   # node_id → node dict (dedup)
    edges = []

    # ── Index constraints by node_id ─────────────────────────────────────────
    constraints_by_node: dict[str, list] = defaultdict(list)
    for c in constraints:
        constraints_by_node[c["node_id"]].append(c)

    # ── Index relationships for traversal ─────────────────────────────────────
    # adj[source] = list of {target, rel_type, user_confirmed}
    adj: dict[str, list] = defaultdict(list)
    for r in relationships:
        adj[r["source_node_id"]].append({
            "target":        r["target_node_id"],
            "rel_type":      r["relationship_type"],
            "user_confirmed":bool(r["user_confirmed"]),
            "rel_id":        r["id"],
        })

    # ── Build infra product nodes ─────────────────────────────────────────────
    for vendor in infra:
        for product in vendor["products"]:
            nid = product_node_id(vendor["name"], product["name"], product["category"])
            nodes[nid] = {
                "id":       nid,
                "type":     product["category"] or "product",
                "label":    product["name"],
                "vendor":   vendor["name"],
                "category": product["category"],
                "versions": [v["version"] for v in product.get("versions", [])],
            }

    # ── Build structural relationship edges ───────────────────────────────────
    for r in relationships:
        src, tgt = r["source_node_id"], r["target_node_id"]
        conf_f = _CONFIRMED_CONF if r["user_confirmed"] else _INFERRED_CONF

        # Ensure zone nodes exist even if not in infra table
        for nid in (src, tgt):
            if nid not in nodes and nid.startswith("zone:"):
                label = nid.split(":", 1)[1].replace("_", " ").title()
                nodes[nid] = {"id": nid, "type": "zone", "label": label}

        edges.append({
            "source":        src,
            "target":        tgt,
            "type":          r["relationship_type"],
            "weight":        conf_f,   # structural edges: weight = confidence only
            "propagated":    False,
            "user_confirmed":bool(r["user_confirmed"]),
            "rel_id":        r["id"],
        })

    # ── Build CVE nodes + direct + propagated threat edges ───────────────────
    for cve in cves:
        cid  = cve["cve_id"]
        nid  = cve_node_id(cid)
        epss = cve.get("epss_score")
        vec  = _parse_vector(cve.get("cvss_vector"))
        score = cve.get("cvss_score")

        nodes[nid] = {
            "id":           nid,
            "type":         "cve",
            "label":        cid,
            "cvss_score":   score,
            "cvss_severity":cve.get("cvss_severity"),
            "epss_score":   epss,
            "epss_pct":     f"{epss*100:.1f}%" if epss is not None else None,
            "description":  cve.get("description"),
            "conv_id":      cve.get("conv_id"),
        }

        # Find which infra product this CVE belongs to via conv_id → infra link.
        # The infra table has a conv_id column on products seeded during CVE analysis.
        # We match by looking for products whose conv_id matches this CVE's conv_id.
        direct_targets: list[str] = []
        for vendor in infra:
            for product in vendor["products"]:
                if product.get("conv_id") == cve.get("conv_id"):
                    pid = product_node_id(vendor["name"], product["name"], product["category"])
                    direct_targets.append(pid)
                    intra = product["category"] == "software_library"
                    cf = _constraint_factor(pid, constraints_by_node)
                    w  = _compute_weight(score, vec, epss, cf, _CONFIRMED_CONF, 1,
                                         intra_layer=intra)
                    edges.append({
                        "source":        nid,
                        "target":        pid,
                        "type":          "affects",
                        "weight":        w,
                        "propagated":    False,
                        "user_confirmed":True,
                        "reason":        f"CVE directly affects this component",
                    })

        # ── Propagate threat through relationship graph (BFS, max _MAX_HOPS) ──
        # Only propagate if Scope=Changed or AV=N (network-reachable).
        scope = vec.get("S", "U")
        av    = vec.get("AV", "N")
        if scope == "C" or av == "N":
            visited = set(direct_targets)
            frontier = [(t, 1) for t in direct_targets]
            while frontier:
                current, hops = frontier.pop(0)
                if hops >= _MAX_HOPS:
                    continue
                for hop in adj.get(current, []):
                    next_nid = hop["target"]
                    if next_nid in visited:
                        continue
                    visited.add(next_nid)
                    conf_f = _CONFIRMED_CONF if hop["user_confirmed"] else _INFERRED_CONF
                    cf     = _constraint_factor(next_nid, constraints_by_node)
                    w      = _compute_weight(score, vec, epss, cf, conf_f, hops + 1)

                    # air_gap: still draw the edge but mark as blocked
                    blocked = any(c["constraint_type"] == "air_gap"
                                  for c in constraints_by_node.get(next_nid, []))

                    edges.append({
                        "source":        nid,
                        "target":        next_nid,
                        "type":          "threatens",
                        "weight":        w,
                        "propagated":    True,
                        "blocked":       blocked,
                        "via":           current,
                        "hops":          hops + 1,
                        "user_confirmed":hop["user_confirmed"],
                        "reason": (
                            f"{'S:Changed — ' if scope == 'C' else ''}"
                            f"AV:{av} propagates via {current} "
                            f"({hop['rel_type']}) — hop {hops+1}"
                        ),
                    })
                    if not blocked:
                        frontier.append((next_nid, hops + 1))

    logger.info("attack graph: %d nodes  %d edges", len(nodes), len(edges))
    return {"nodes": list(nodes.values()), "edges": edges}
