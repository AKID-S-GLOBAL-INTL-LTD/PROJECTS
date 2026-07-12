# Copyright (c) AKID's Global Cybersecurity Tools
# Module: escalation_rules.py
# Purpose: Encodes publicly documented AWS IAM privilege escalation
#          techniques as detection rules. Each rule checks whether an
#          identity's effective permission set contains the action
#          combination needed to perform that escalation technique.
#
# Source basis: this ruleset mirrors the well-known, publicly published
# catalog of ~20 AWS IAM privesc methods (Rhino Security Labs research,
# 2018, and subsequent community additions). It is used here purely for
# DEFENSIVE auditing — identifying these paths in YOUR OWN environment so
# they can be remediated, not for exploitation.

from core.permissions import has_all, has_any

# Each rule: id, title, severity, required actions (ANY-of groups ANDed
# together), and a short remediation note.
#
# required: list of "action groups". The rule fires if the identity has
# at least one action from EVERY group (i.e. groups are ANDed, actions
# within a group are ORed). This models "you need permission X AND Y",
# where X or Y might be satisfiable multiple ways.

RULES = [
    {
        "id": "PE01",
        "title": "CreatePolicyVersion — set a new default policy version with full permissions",
        "severity": "critical",
        "required": [["iam:createpolicyversion"]],
        "remediation": "Remove iam:CreatePolicyVersion unless strictly required; use permission boundaries.",
    },
    {
        "id": "PE02",
        "title": "SetDefaultPolicyVersion — roll back to a prior over-permissioned policy version",
        "severity": "high",
        "required": [["iam:setdefaultpolicyversion"]],
        "remediation": "Restrict iam:SetDefaultPolicyVersion; enable policy version change alerting.",
    },
    {
        "id": "PE03",
        "title": "CreateAccessKey for another user — mint credentials for a higher-privileged identity",
        "severity": "critical",
        "required": [["iam:createaccesskey"]],
        "remediation": "Scope iam:CreateAccessKey to self (aws:username condition) only.",
    },
    {
        "id": "PE04",
        "title": "CreateLoginProfile — set a console password for another user",
        "severity": "high",
        "required": [["iam:createloginprofile"]],
        "remediation": "Restrict iam:CreateLoginProfile to identity/self-service workflows only.",
    },
    {
        "id": "PE05",
        "title": "UpdateLoginProfile — reset another user's console password",
        "severity": "high",
        "required": [["iam:updateloginprofile"]],
        "remediation": "Scope iam:UpdateLoginProfile with aws:username condition to self only.",
    },
    {
        "id": "PE06",
        "title": "AttachUserPolicy — attach an admin-equivalent managed policy to self or another user",
        "severity": "critical",
        "required": [["iam:attachuserpolicy"]],
        "remediation": "Restrict iam:AttachUserPolicy; require approval workflow for policy attachment.",
    },
    {
        "id": "PE07",
        "title": "AttachGroupPolicy — attach admin-equivalent policy to a group the actor belongs to",
        "severity": "critical",
        "required": [["iam:attachgrouppolicy"]],
        "remediation": "Restrict iam:AttachGroupPolicy to IAM admins only.",
    },
    {
        "id": "PE08",
        "title": "AttachRolePolicy — attach admin-equivalent policy to an assumable role",
        "severity": "critical",
        "required": [["iam:attachrolepolicy"]],
        "remediation": "Restrict iam:AttachRolePolicy; monitor via CloudTrail for anomalous attachments.",
    },
    {
        "id": "PE09",
        "title": "PutUserPolicy — write an inline admin policy directly on self or another user",
        "severity": "critical",
        "required": [["iam:putuserpolicy"]],
        "remediation": "Restrict iam:PutUserPolicy; prefer managed policies with change control.",
    },
    {
        "id": "PE10",
        "title": "PutGroupPolicy — write an inline admin policy on a group",
        "severity": "critical",
        "required": [["iam:putgrouppolicy"]],
        "remediation": "Restrict iam:PutGroupPolicy to IAM admins only.",
    },
    {
        "id": "PE11",
        "title": "PutRolePolicy — write an inline admin policy on an assumable role",
        "severity": "critical",
        "required": [["iam:putrolepolicy"]],
        "remediation": "Restrict iam:PutRolePolicy; monitor via CloudTrail.",
    },
    {
        "id": "PE12",
        "title": "AddUserToGroup — join a privileged group",
        "severity": "high",
        "required": [["iam:addusertogroup"]],
        "remediation": "Restrict iam:AddUserToGroup; review group membership regularly.",
    },
    {
        "id": "PE13",
        "title": "UpdateAssumeRolePolicy — modify a role's trust policy to allow self to assume it",
        "severity": "critical",
        "required": [["iam:updateassumerolepolicy"]],
        "remediation": "Restrict iam:UpdateAssumeRolePolicy tightly; alert on trust policy changes.",
    },
    {
        "id": "PE14",
        "title": "PassRole + EC2 RunInstances — launch an instance with a highly privileged instance profile",
        "severity": "critical",
        "required": [["iam:passrole"], ["ec2:runinstances"]],
        "remediation": "Scope iam:PassRole to specific role ARNs via condition; audit instance profile roles.",
    },
    {
        "id": "PE15",
        "title": "PassRole + Lambda CreateFunction + Invoke — run arbitrary code as a privileged role",
        "severity": "critical",
        "required": [["iam:passrole"], ["lambda:createfunction"], ["lambda:invokefunction"]],
        "remediation": "Scope iam:PassRole to specific role ARNs; restrict who can create/invoke Lambda functions.",
    },
    {
        "id": "PE16",
        "title": "PassRole + Lambda CreateFunction + AddPermission + resource-based trigger (no direct invoke needed)",
        "severity": "high",
        "required": [["iam:passrole"], ["lambda:createfunction"], ["lambda:addpermission"]],
        "remediation": "Restrict lambda:AddPermission; scope iam:PassRole with iam:PassedToService condition.",
    },
    {
        "id": "PE17",
        "title": "PassRole + Lambda CreateFunction + CreateEventSourceMapping — trigger privileged execution via stream",
        "severity": "high",
        "required": [["iam:passrole"], ["lambda:createfunction"], ["lambda:createeventsourcemapping"]],
        "remediation": "Scope iam:PassRole and restrict lambda:CreateEventSourceMapping.",
    },
    {
        "id": "PE18",
        "title": "PassRole + Glue CreateDevEndpoint — SSH into a Glue dev endpoint running as a privileged role",
        "severity": "high",
        "required": [["iam:passrole"], ["glue:createdevendpoint"]],
        "remediation": "Scope iam:PassRole; restrict glue:CreateDevEndpoint to trusted principals.",
    },
    {
        "id": "PE19",
        "title": "PassRole + DataPipeline CreatePipeline — execute privileged pipeline actions",
        "severity": "medium",
        "required": [["iam:passrole"], ["datapipeline:createpipeline"]],
        "remediation": "Scope iam:PassRole; restrict Data Pipeline creation.",
    },
    {
        "id": "PE20",
        "title": "CloudFormation CreateStack + PassRole — deploy a stack that provisions admin resources as a privileged role",
        "severity": "critical",
        "required": [["iam:passrole"], ["cloudformation:createstack"]],
        "remediation": "Scope iam:PassRole with iam:PassedToService=cloudformation.amazonaws.com condition.",
    },
    {
        "id": "PE21",
        "title": "STS AssumeRole — able to assume a role that is (transitively) more privileged than current identity",
        "severity": "high",
        "required": [["sts:assumerole"]],
        "remediation": "This rule requires trust-policy graph analysis; see role-assumption edges in the report.",
        "graph_only": True,  # handled separately by the graph builder, not a flat action check
    },
]


def evaluate_identity(effective_actions):
    """
    Runs all rules against a single identity's effective action set.
    Returns a list of matched rule dicts (excluding graph_only rules,
    which are evaluated separately by the graph traversal step).
    """
    matches = []
    for rule in RULES:
        if rule.get("graph_only"):
            continue
        groups = rule["required"]
        if all(has_any(effective_actions, group) for group in groups):
            matches.append(rule)
    return matches
