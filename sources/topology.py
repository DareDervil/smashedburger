"""add_topology_fact — Sonnet passive discovery of infra relationships and network controls.

Complements add_to_infrastructure: where that tool records *what* is in the environment,
this one records *how things relate* and *what controls are in place*.

Two fact types:
  relationship   — "Log4j runs inside our Tomcat app", "Tomcat sits on Ubuntu"
  network_control — "only ports 80 and 443 are open", "we're behind a WAF", "air-gapped"

Node IDs follow the scheme: product:<vendor>:<product>, os:<vendor>:<product>, zone:<name>.
Sonnet builds these from what it already knows about the infra (vendor/product names).
"""
import logging
import re
import db

logger = logging.getLogger(__name__)

NAME  = "add_topology_fact"
ORDER = 31   # Fires just after add_to_infrastructure (ORDER=30)

# Valid relationship types and their meaning in the attack graph
_REL_TYPES = {
    "runs_on":    "component runs on top of target (library inside app, app on OS)",
    "depends_on": "component depends on target at runtime",
    "exposed_via":"component is reachable through a network zone or interface",
    "hosts":      "target hosts/runs the source component",
}

# Valid network control types and how they affect edge weights
_CONSTRAINT_TYPES = {
    "firewall":        "generic firewall present",
    "port_restriction":"only specific ports are open — provide ports in detail",
    "waf":             "web application firewall in front of the node",
    "dmz":             "node sits in a DMZ segment",
    "air_gap":         "node is physically isolated from other networks",
}

TOOL_DEF = {
    "name": NAME,
    "description": (
        "Record how infrastructure components relate to each other, or what network "
        "controls protect them. Call this when the user states: "
        "(1) a relationship between components — 'Log4j runs inside our Tomcat app', "
        "'Tomcat sits on Ubuntu', 'our API is exposed via the internet'; "
        "(2) a network or security control — 'only ports 80 and 443 are open', "
        "'we have a WAF in front', 'that segment is air-gapped', 'it's behind a firewall'. "
        "Call add_to_infrastructure first if the component isn't recorded yet. "
        "Use this alongside add_to_infrastructure — they are complementary. "
        "After calling this, continue your reply naturally."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "fact_type": {
                "type": "string",
                "enum": ["relationship", "network_control"],
                "description": (
                    "'relationship' for component-to-component links; "
                    "'network_control' for firewall rules, WAF, DMZ, air-gap, port restrictions."
                ),
            },
            "source_node_id": {
                "type": "string",
                "description": (
                    "Stable node ID for the source component. "
                    "Format: 'product:<vendor>:<product>' (e.g. 'product:apache:log4j'), "
                    "'os:<vendor>:<product>' (e.g. 'os:canonical:ubuntu'), "
                    "'zone:<name>' (e.g. 'zone:internet', 'zone:dmz', 'zone:internal'). "
                    "Required for fact_type='relationship'. "
                    "Also used as the node_id for fact_type='network_control'."
                ),
            },
            "target_node_id": {
                "type": "string",
                "description": (
                    "Stable node ID for the target component. "
                    "Same format as source_node_id. "
                    "Required for fact_type='relationship'."
                ),
            },
            "relationship_type": {
                "type": "string",
                "enum": ["runs_on", "depends_on", "exposed_via", "hosts"],
                "description": (
                    "runs_on: source runs on/inside target (Log4j runs_on Tomcat). "
                    "depends_on: source needs target at runtime. "
                    "exposed_via: source is reachable through target network zone. "
                    "hosts: target hosts the source (OS hosts app). "
                    "Required for fact_type='relationship'."
                ),
            },
            "constraint_type": {
                "type": "string",
                "enum": ["firewall", "port_restriction", "waf", "dmz", "air_gap"],
                "description": "Required for fact_type='network_control'.",
            },
            "detail": {
                "type": "string",
                "description": (
                    "Optional detail. For port_restriction: comma-separated ports e.g. '80,443'. "
                    "For other types: any clarifying note."
                ),
            },
        },
        "required": ["fact_type", "source_node_id"],
    },
}

PROMPT = (
    "- **add_topology_fact** — Call when the user states how components relate "
    "('Log4j runs in Tomcat', 'Tomcat sits on Ubuntu', 'exposed via internet') "
    "or describes a network control ('behind a WAF', 'only 80/443 open', 'air-gapped'). "
    "Always call add_to_infrastructure first for any new component, then add_topology_fact "
    "to record the relationship or control. These two tools build the attack graph."
)


def _normalise_node_id(node_id: str) -> str:
    """Lowercase and strip whitespace. Keep the type: prefix intact."""
    return node_id.strip().lower()


def fetch(fact_type: str, source_node_id: str,
          target_node_id: str = "", relationship_type: str = "",
          constraint_type: str = "", detail: str = "") -> dict:

    source_node_id = _normalise_node_id(source_node_id)

    if fact_type == "relationship":
        if not target_node_id or not relationship_type:
            return {"ok": False, "error": "relationship requires target_node_id and relationship_type"}
        target_node_id = _normalise_node_id(target_node_id)
        if relationship_type not in _REL_TYPES:
            return {"ok": False, "error": f"unknown relationship_type: {relationship_type}"}

        rel_id = db.store_relationship(source_node_id, target_node_id, relationship_type,
                                       user_confirmed=False)
        logger.info("topology: relationship %s -[%s]-> %s (id=%s)",
                    source_node_id, relationship_type, target_node_id, rel_id)
        return {
            "ok":               True,
            "fact_type":        "relationship",
            "source_node_id":   source_node_id,
            "target_node_id":   target_node_id,
            "relationship_type":relationship_type,
            "rel_id":           rel_id,
        }

    elif fact_type == "network_control":
        if not constraint_type:
            return {"ok": False, "error": "network_control requires constraint_type"}
        if constraint_type not in _CONSTRAINT_TYPES:
            return {"ok": False, "error": f"unknown constraint_type: {constraint_type}"}

        db.store_network_constraint(source_node_id, constraint_type, detail or None)
        logger.info("topology: constraint [%s] %s detail=%r",
                    constraint_type, source_node_id, detail)
        return {
            "ok":             True,
            "fact_type":      "network_control",
            "node_id":        source_node_id,
            "constraint_type":constraint_type,
            "detail":         detail,
        }

    return {"ok": False, "error": f"unknown fact_type: {fact_type}"}


def extract_links(result: dict) -> list:
    return []


def extract_actions(result: dict) -> tuple[list, list]:
    return [], []
