#!/usr/bin/env python3
# Copyright (c) AKID's Global Cybersecurity Tools
# Tool: IAM Privilege Escalation Path Analyzer
# Purpose: Read-only defensive audit tool that maps AWS IAM identities
#          (users/roles) and detects chains of permissions that allow
#          privilege escalation to administrator-equivalent access.
#
# Usage:
#   python main.py --profile my-aws-profile --output-dir ./reports
#   python main.py --region us-east-1 --output-dir ./reports   (uses default creds)
#
# Required IAM permissions (all read-only):
#   iam:List*, iam:Get*, sts:GetCallerIdentity

import argparse
import json
import logging
import os
import sys

from core.collector import IAMCollector
from core.graph_builder import build_graph
from core.path_analyzer import find_escalation_paths, summarize
from core.report_generator import generate_json_report, generate_html_report
from rules.escalation_rules import RULES

BANNER = r"""
  ___    _    __  __   ____       _           _
 |_ _|  / \  |  \/  | |  _ \ _ __(_)_   _____| |
  | |  / _ \ | |\/| | | |_) | '__| \ \ / / _ \ |
  | | / ___ \| |  | | |  __/| |  | |\ V /  __/ |
 |___/_/   \_\_|  |_| |_|   |_|  |_| \_/ \___|_|

 IAM Privilege Escalation Path Analyzer
 (c) AKID's Global Cybersecurity Tools
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="IAM Privilege Escalation Path Analyzer — (c) AKID's Global Cybersecurity Tools"
    )
    p.add_argument("--profile", help="AWS named profile to use (optional)")
    p.add_argument("--region", default="us-east-1", help="AWS region for API calls (default: us-east-1)")
    p.add_argument("--output-dir", default="./reports", help="Directory to write reports to")
    p.add_argument("--max-hops", type=int, default=6, help="Max path length to search (default: 6)")
    p.add_argument("--offline-inventory", help="Path to a previously saved inventory JSON, to skip live AWS calls")
    p.add_argument("--save-inventory", help="Path to save the raw collected inventory as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )
    print(BANNER)

    os.makedirs(args.output_dir, exist_ok=True)

    if args.offline_inventory:
        logging.info("Loading offline inventory from %s", args.offline_inventory)
        with open(args.offline_inventory) as f:
            inventory = json.load(f)
    else:
        try:
            collector = IAMCollector(profile=args.profile, region=args.region)
            who = collector.whoami()
            print(f"Authenticated as: {who['arn']}  (Account: {who['account']})\n")
        except Exception as e:
            print(f"ERROR: could not authenticate to AWS — {e}", file=sys.stderr)
            print("Check your AWS credentials/profile and try again.", file=sys.stderr)
            sys.exit(1)

        inventory = collector.collect_all()

        if args.save_inventory:
            with open(args.save_inventory, "w") as f:
                json.dump(inventory, f, indent=2, default=str)
            logging.info("Saved raw inventory to %s", args.save_inventory)

    print(f"Collected: {len(inventory['users'])} users, {len(inventory['groups'])} groups, {len(inventory['roles'])} roles\n")

    logging.info("Building IAM relationship graph...")
    graph, meta = build_graph(inventory)

    logging.info("Searching for escalation paths (max %d hops)...", args.max_hops)
    findings = find_escalation_paths(graph, meta, max_path_length=args.max_hops)
    summary = summarize(findings, meta)

    rules_by_id = {r["id"]: r["title"] for r in RULES}

    json_path = os.path.join(args.output_dir, "iam_privesc_report.json")
    html_path = os.path.join(args.output_dir, "iam_privesc_report.html")

    report = generate_json_report(inventory["account"], summary, findings, rules_by_id, json_path)
    generate_html_report(report, html_path)

    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Total identities analyzed : {summary['total_identities']}")
    print(f"Already admin-equivalent  : {summary['already_admin_count']}")
    print(f"Identities at risk        : {summary['identities_with_escalation_path']}")
    print(f"Total escalation paths    : {summary['total_paths_found']}")
    print(f"  Critical: {summary['findings_by_severity']['critical']}  "
          f"High: {summary['findings_by_severity']['high']}  "
          f"Medium: {summary['findings_by_severity']['medium']}  "
          f"Low: {summary['findings_by_severity']['low']}")
    print()
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


if __name__ == "__main__":
    main()
