# Copyright (c) AKID's Global Cybersecurity Tools
# Module: permissions.py
# Purpose: Flatten IAM policy documents (inline + managed) into a normalized
#          set of effective allowed actions per identity. This is a
#          simplified evaluator: it collects Allow actions and subtracts
#          explicit Deny actions found in the SAME identity's policies.
#          It does not fully model SCPs, permission boundaries, or
#          resource-level conditions — see README "Limitations".

import fnmatch


def _as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def extract_actions(policy_document):
    """
    Given a single IAM policy document, return (allow_actions, deny_actions)
    as sets of lowercase 'service:action' strings (wildcards preserved).
    """
    allow, deny = set(), set()
    if not policy_document:
        return allow, deny

    statements = _as_list(policy_document.get("Statement"))
    for stmt in statements:
        effect = stmt.get("Effect", "Deny")
        actions = _as_list(stmt.get("Action"))
        actions += _as_list(stmt.get("NotAction"))  # tracked but not fully modeled
        actions = {a.lower() for a in actions}
        if effect == "Allow":
            allow |= actions
        else:
            deny |= actions
    return allow, deny


def effective_actions_for_identity(identity):
    """
    identity: dict with 'inline_policies' and 'attached_policies', each a
    dict of {policy_name: policy_document}.
    Returns a set of effective allowed 'service:action' strings.
    """
    allow_total, deny_total = set(), set()

    for doc in identity.get("inline_policies", {}).values():
        a, d = extract_actions(doc)
        allow_total |= a
        deny_total |= d

    for doc in identity.get("attached_policies", {}).values():
        a, d = extract_actions(doc)
        allow_total |= a
        deny_total |= d

    return allow_total - deny_total


def action_allowed(effective_actions, action):
    """
    Checks whether `action` (e.g. 'iam:passrole') is granted by a set of
    effective actions, respecting wildcard patterns like 'iam:*' or '*'.
    """
    action = action.lower()
    for granted in effective_actions:
        if fnmatch.fnmatch(action, granted):
            return True
    return False


def has_any(effective_actions, required_actions):
    return any(action_allowed(effective_actions, a) for a in required_actions)


def has_all(effective_actions, required_actions):
    return all(action_allowed(effective_actions, a) for a in required_actions)
