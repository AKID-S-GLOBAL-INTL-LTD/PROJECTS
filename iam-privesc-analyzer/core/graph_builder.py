# Copyright (c) AKID's Global Cybersecurity Tools
# Module: graph_builder.py
# Purpose: Builds a directed graph of the IAM environment where nodes are
#          identities (users/roles) and groups, and edges represent:
#            - group membership ("member_of")
#            - role assumption allowed by trust policy ("can_assume")
#            - a detected privilege-escalation technique ("can_escalate_to")
#          This mirrors the attack-path-graph approach used by tools like
#          BloodHound, applied to AWS IAM instead of Active Directory.

import logging

import networkx as nx

from core.permissions import effective_actions_for_identity, action_allowed
from rules.escalation_rules import evaluate_identity

logger = logging.getLogger("iam_privesc.graph")

ADMIN_SIGNATURES = {
    "*",              # full wildcard action
    "iam:*",
    "administratoraccess",  # matched separately via policy name below
}

ADMIN_POLICY_NAMES = {"administratoraccess"}


def _is_admin_equivalent(effective_actions, attached_policy_names):
    if action_allowed(effective_actions, "*"):
        return True
    if action_allowed(effective_actions, "iam:*") and action_allowed(effective_actions, "sts:assumerole"):
        return True
    names = {n.lower() for n in attached_policy_names}
    if names & ADMIN_POLICY_NAMES:
        return True
    return False


def build_graph(inventory):
    """
    inventory: output of IAMCollector.collect_all()
    Returns: (graph, node_metadata)
      graph: networkx.DiGraph
      node_metadata: dict of node_id -> {type, name, arn, is_admin, effective_actions, matched_rules}
    """
    g = nx.DiGraph()
    meta = {}

    # --- Groups as nodes (membership pass-through) ---
    group_effective = {}
    for grp in inventory["groups"]:
        node_id = f"group:{grp['name']}"
        eff = effective_actions_for_identity(grp)
        group_effective[grp["name"]] = eff
        g.add_node(node_id, type="group", name=grp["name"])
        meta[node_id] = {
            "type": "group",
            "name": grp["name"],
            "arn": grp.get("arn"),
            "effective_actions": sorted(eff),
        }

    # --- Users as nodes ---
    for user in inventory["users"]:
        node_id = f"user:{user['name']}"
        eff = effective_actions_for_identity(user)

        # Inherit group permissions for admin-check + escalation purposes
        combined = set(eff)
        for gname in user.get("groups", []):
            combined |= group_effective.get(gname, set())

        attached_names = list(user.get("attached_policies", {}).keys())
        is_admin = _is_admin_equivalent(combined, attached_names)
        matched_rules = evaluate_identity(combined)

        g.add_node(node_id, type="user", name=user["name"], is_admin=is_admin)
        meta[node_id] = {
            "type": "user",
            "name": user["name"],
            "arn": user.get("arn"),
            "is_admin": is_admin,
            "effective_actions": sorted(combined),
            "matched_rules": matched_rules,
        }

        for gname in user.get("groups", []):
            g.add_edge(node_id, f"group:{gname}", relation="member_of")

        # Self-escalation edge: if this identity can reach admin via a rule,
        # draw an edge to a synthetic "ADMIN" sink to represent that path.
        if matched_rules and not is_admin:
            g.add_node("ADMIN", type="sink")
            for rule in matched_rules:
                g.add_edge(node_id, "ADMIN", relation="can_escalate_to", rule_id=rule["id"], title=rule["title"], severity=rule["severity"])

    # --- Roles as nodes + trust policy edges (who can assume this role) ---
    for role in inventory["roles"]:
        node_id = f"role:{role['name']}"
        eff = effective_actions_for_identity(role)
        attached_names = list(role.get("attached_policies", {}).keys())
        is_admin = _is_admin_equivalent(eff, attached_names)
        matched_rules = evaluate_identity(eff)

        g.add_node(node_id, type="role", name=role["name"], is_admin=is_admin)
        meta[node_id] = {
            "type": "role",
            "name": role["name"],
            "arn": role.get("arn"),
            "is_admin": is_admin,
            "effective_actions": sorted(eff),
            "matched_rules": matched_rules,
        }

        if matched_rules and not is_admin:
            g.add_node("ADMIN", type="sink")
            for rule in matched_rules:
                g.add_edge(node_id, "ADMIN", relation="can_escalate_to", rule_id=rule["id"], title=rule["title"], severity=rule["severity"])

        if is_admin:
            g.add_node("ADMIN", type="sink")
            g.add_edge(node_id, "ADMIN", relation="is_admin_equivalent")

        # Trust policy: who can assume this role (sts:AssumeRole edges)
        trust = role.get("trust_policy") or {}
        for stmt in trust.get("Statement", []) if isinstance(trust.get("Statement"), list) else [trust.get("Statement")] if trust.get("Statement") else []:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            aws_principals = principal.get("AWS") if isinstance(principal, dict) else None
            if not aws_principals:
                continue
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                # Match against known users/roles by ARN suffix
                for other_id, other_meta in meta.items():
                    other_arn = other_meta.get("arn")
                    if other_arn and (other_arn == p or p.endswith(":root")):
                        if other_id != node_id:
                            g.add_edge(other_id, node_id, relation="can_assume")

    # Mark admin-equivalent users/roles with a direct edge to ADMIN sink too
    for node_id, m in meta.items():
        if m.get("is_admin") and "ADMIN" in g.nodes:
            if not g.has_edge(node_id, "ADMIN"):
                g.add_edge(node_id, "ADMIN", relation="is_admin_equivalent")

    return g, meta
