# Copyright (c) AKID's Global Cybersecurity Tools
# Module: path_analyzer.py
# Purpose: Traverses the IAM graph to find all paths from non-admin
#          identities to the synthetic ADMIN sink, including multi-hop
#          paths (e.g. User -> can_assume -> Role -> can_escalate_to -> ADMIN).

import networkx as nx


def find_escalation_paths(graph, meta, max_path_length=6):
    """
    Returns a list of findings:
    {
      "source": node_id,
      "source_name": str,
      "path": [node_id, ...],
      "path_relations": [(from, to, relation, extra), ...],
      "hops": int,
      "max_severity": str,
      "rule_ids": [str, ...],
    }
    Only includes paths ending at 'ADMIN' where the source is not already
    admin-equivalent (those are reported separately as "already admin").
    """
    if "ADMIN" not in graph.nodes:
        return []

    findings = []
    severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}

    for node_id, m in meta.items():
        if m.get("type") not in ("user", "role"):
            continue
        if m.get("is_admin"):
            continue  # already admin, not an escalation finding
        if not nx.has_path(graph, node_id, "ADMIN"):
            continue

        try:
            paths = list(nx.all_simple_paths(graph, node_id, "ADMIN", cutoff=max_path_length))
        except nx.NetworkXNoPath:
            continue

        for path in paths:
            relations = []
            rule_ids = []
            max_sev = "low"
            for i in range(len(path) - 1):
                edge_data = graph.get_edge_data(path[i], path[i + 1])
                relations.append((path[i], path[i + 1], edge_data.get("relation"), edge_data))
                if edge_data.get("rule_id"):
                    rule_ids.append(edge_data["rule_id"])
                sev = edge_data.get("severity")
                if sev and severity_rank.get(sev, 0) > severity_rank.get(max_sev, 0):
                    max_sev = sev

            findings.append({
                "source": node_id,
                "source_name": m.get("name"),
                "source_type": m.get("type"),
                "path": path,
                "path_relations": relations,
                "hops": len(path) - 1,
                "max_severity": max_sev if rule_ids else "info",
                "rule_ids": rule_ids,
            })

    # Sort: most severe & shortest paths first
    findings.sort(key=lambda f: (-severity_rank.get(f["max_severity"], -1), f["hops"]))
    return findings


def summarize(findings, meta):
    total_identities = sum(1 for m in meta.values() if m.get("type") in ("user", "role"))
    already_admin = [nid for nid, m in meta.items() if m.get("type") in ("user", "role") and m.get("is_admin")]
    at_risk = {f["source"] for f in findings}

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        by_severity[f["max_severity"]] = by_severity.get(f["max_severity"], 0) + 1

    return {
        "total_identities": total_identities,
        "already_admin_count": len(already_admin),
        "already_admin": already_admin,
        "identities_with_escalation_path": len(at_risk),
        "total_paths_found": len(findings),
        "findings_by_severity": by_severity,
    }
