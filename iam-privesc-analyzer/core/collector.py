# Copyright (c) AKID's Global Cybersecurity Tools
# Module: collector.py
# Purpose: Read-only collection of AWS IAM identities and policy documents.
#          Requires only iam:Get*, iam:List*, and sts:GetCallerIdentity — no
#          write permissions are ever used by this tool.

import json
import logging
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("iam_privesc.collector")


class IAMCollector:
    """
    Collects the raw IAM inventory of an AWS account:
      - Users, Groups, Roles
      - Inline + attached managed policy documents
      - Group memberships
      - Role trust policies (who can assume what)

    All calls are strictly read-only IAM API calls.
    """

    def __init__(self, session: boto3.Session = None, profile: str = None, region: str = "us-east-1"):
        if session:
            self.session = session
        elif profile:
            self.session = boto3.Session(profile_name=profile, region_name=region)
        else:
            self.session = boto3.Session(region_name=region)

        self.iam = self.session.client("iam")
        self.sts = self.session.client("sts")

    def whoami(self):
        try:
            ident = self.sts.get_caller_identity()
            return {
                "account": ident.get("Account"),
                "arn": ident.get("Arn"),
                "user_id": ident.get("UserId"),
            }
        except ClientError as e:
            logger.error("Unable to call sts:GetCallerIdentity — check credentials. %s", e)
            raise

    # ---------- Users ----------

    def list_users(self):
        users = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])
        return users

    def get_user_groups(self, username):
        resp = self.iam.list_groups_for_user(UserName=username)
        return [g["GroupName"] for g in resp["Groups"]]

    def get_user_inline_policies(self, username):
        names = self.iam.list_user_policies(UserName=username)["PolicyNames"]
        docs = {}
        for name in names:
            resp = self.iam.get_user_policy(UserName=username, PolicyName=name)
            docs[name] = resp["PolicyDocument"]
        return docs

    def get_user_attached_policies(self, username):
        resp = self.iam.list_attached_user_policies(UserName=username)
        return resp["AttachedPolicies"]  # [{PolicyName, PolicyArn}]

    # ---------- Groups ----------

    def list_groups(self):
        groups = []
        paginator = self.iam.get_paginator("list_groups")
        for page in paginator.paginate():
            groups.extend(page["Groups"])
        return groups

    def get_group_inline_policies(self, group_name):
        names = self.iam.list_group_policies(GroupName=group_name)["PolicyNames"]
        docs = {}
        for name in names:
            resp = self.iam.get_group_policy(GroupName=group_name, PolicyName=name)
            docs[name] = resp["PolicyDocument"]
        return docs

    def get_group_attached_policies(self, group_name):
        resp = self.iam.list_attached_group_policies(GroupName=group_name)
        return resp["AttachedPolicies"]

    # ---------- Roles ----------

    def list_roles(self):
        roles = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page["Roles"])
        return roles

    def get_role_inline_policies(self, role_name):
        names = self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        docs = {}
        for name in names:
            resp = self.iam.get_role_policy(RoleName=role_name, PolicyName=name)
            docs[name] = resp["PolicyDocument"]
        return docs

    def get_role_attached_policies(self, role_name):
        resp = self.iam.list_attached_role_policies(RoleName=role_name)
        return resp["AttachedPolicies"]

    # ---------- Managed policy documents ----------

    def get_managed_policy_document(self, policy_arn):
        """Resolves a managed policy ARN (AWS or customer) to its current policy document."""
        meta = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = meta["DefaultVersionId"]
        version = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return version["PolicyVersion"]["Document"]

    # ---------- Full inventory ----------

    def collect_all(self):
        """
        Builds a full normalized inventory:
        {
          "account": {...},
          "users": [{name, arn, groups, inline_policies, attached_policies(resolved)}],
          "groups": [{name, arn, inline_policies, attached_policies(resolved)}],
          "roles":  [{name, arn, trust_policy, inline_policies, attached_policies(resolved)}]
        }
        """
        logger.info("Collecting caller identity...")
        account_info = self.whoami()

        logger.info("Collecting IAM users...")
        users = []
        for u in self.list_users():
            name = u["UserName"]
            attached = self.get_user_attached_policies(name)
            resolved_attached = {
                a["PolicyName"]: self.get_managed_policy_document(a["PolicyArn"])
                for a in attached
            }
            users.append({
                "name": name,
                "arn": u["Arn"],
                "groups": self.get_user_groups(name),
                "inline_policies": self.get_user_inline_policies(name),
                "attached_policies": resolved_attached,
            })

        logger.info("Collecting IAM groups...")
        groups = []
        for g in self.list_groups():
            name = g["GroupName"]
            attached = self.get_group_attached_policies(name)
            resolved_attached = {
                a["PolicyName"]: self.get_managed_policy_document(a["PolicyArn"])
                for a in attached
            }
            groups.append({
                "name": name,
                "arn": g["Arn"],
                "inline_policies": self.get_group_inline_policies(name),
                "attached_policies": resolved_attached,
            })

        logger.info("Collecting IAM roles...")
        roles = []
        for r in self.list_roles():
            name = r["RoleName"]
            attached = self.get_role_attached_policies(name)
            resolved_attached = {
                a["PolicyName"]: self.get_managed_policy_document(a["PolicyArn"])
                for a in attached
            }
            trust_doc = r.get("AssumeRolePolicyDocument")
            if isinstance(trust_doc, str):
                trust_doc = json.loads(unquote(trust_doc))
            roles.append({
                "name": name,
                "arn": r["Arn"],
                "trust_policy": trust_doc,
                "inline_policies": self.get_role_inline_policies(name),
                "attached_policies": resolved_attached,
            })

        return {
            "account": account_info,
            "users": users,
            "groups": groups,
            "roles": roles,
        }
