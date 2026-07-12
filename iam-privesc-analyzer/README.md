# IAM Privilege Escalation Path Analyzer

**© AKID's Global Cybersecurity Tools**

A read-only defensive security tool that maps AWS IAM identities (users and
roles) and detects chains of permissions that would allow an attacker — or a
low-privileged insider — to escalate to administrator-equivalent access.

It works like [BloodHound](https://github.com/BloodHoundAD/BloodHound) does
for Active Directory attack paths, but applied to AWS IAM: it models
identities, group memberships, role trust relationships, and permission
grants as a graph, then searches that graph for paths ending in full
administrative control.

## Why this tool exists

Misconfigured IAM is one of the most common root causes of cloud breaches.
Individual IAM policies can look harmless in isolation — a user might not
have `AdministratorAccess`, but if they can create a new policy version,
pass a role to Lambda, or assume a role that itself is over-permissioned,
they may have a full escalation path to admin without anyone noticing. This
tool surfaces those hidden paths automatically so they can be remediated
before an attacker (or a compromised credential) finds them first.

## What it does

1. **Collects** IAM users, groups, roles, inline policies, attached managed
   policies, and role trust policies via read-only AWS API calls.
2. **Builds a graph** of identities, group memberships, and role-assumption
   relationships.
3. **Evaluates** each identity's effective permissions against a ruleset of
   21 publicly documented AWS IAM privilege escalation techniques (e.g.
   `iam:PassRole` + `lambda:CreateFunction`, `iam:CreatePolicyVersion`,
   `iam:AttachUserPolicy`, etc.).
4. **Traverses the graph** to find multi-hop paths (e.g. *User → can assume
   → Role → can escalate to → Admin*), not just single-identity risks.
5. **Generates reports** in JSON (machine-readable, for pipelines/SIEM) and
   HTML (dark-themed, readable, for stakeholders).

## What it does NOT do

- It never modifies anything in the AWS account — only `List*`/`Get*` and
  `sts:GetCallerIdentity` calls are used.
- It does not exploit anything. It reports paths; remediation is manual.
- It does not currently model Service Control Policies (SCPs), permission
  boundaries, or fine-grained resource/condition logic — see Limitations.

## Setup

```bash
pip install -r requirements.txt
```

### AWS credentials

Create an IAM user or role for the scanner with **only** the permissions in
`reader_policy.json` (included in this repo) — attach it as a managed
policy or inline policy to whatever identity you'll run the tool as.

Configure credentials normally via `aws configure --profile iam-scanner`,
environment variables, or an instance/role profile.

## Usage

```bash
# Run against your default AWS credentials
python main.py --output-dir ./reports

# Run against a named profile, specific region
python main.py --profile iam-scanner --region us-east-1 --output-dir ./reports

# Save the raw collected inventory (useful for re-analysis without re-hitting AWS)
python main.py --profile iam-scanner --save-inventory inventory.json

# Re-analyze a previously saved inventory without live AWS calls
python main.py --offline-inventory inventory.json --output-dir ./reports
```

Output:
- `reports/iam_privesc_report.json` — full structured findings
- `reports/iam_privesc_report.html` — dashboard-style report

## How the ruleset works

`rules/escalation_rules.py` contains 21 rules (`PE01`–`PE21`) based on the
well-known catalog of AWS IAM privilege escalation methods originally
compiled by security researchers and widely used across the industry (e.g.
by tools like PMapper and Cloudsplaining). Each rule specifies the
action(s) an identity needs — directly or via group membership — to pull
off that specific escalation technique. The `sts:AssumeRole` rule (`PE21`)
is handled separately by the graph traversal, since it depends on trust
policy relationships rather than a flat permission check.

## Project structure

```
iam-privesc-analyzer/
├── main.py                    # CLI entry point
├── core/
│   ├── collector.py           # Read-only AWS IAM data collection
│   ├── permissions.py         # Policy document → effective actions
│   ├── graph_builder.py       # Builds the identity relationship graph
│   ├── path_analyzer.py       # Graph traversal to find escalation paths
│   └── report_generator.py    # JSON + HTML report rendering
├── rules/
│   └── escalation_rules.py    # The 21-technique detection ruleset
├── tests/
│   └── sample_inventory.json  # Synthetic test data (no AWS calls needed)
├── reader_policy.json         # IAM policy to attach to the scanner identity
├── requirements.txt
└── LICENSE.txt
```

## Limitations (be upfront about these in any writeup/demo)

- Does not evaluate SCPs, IAM permission boundaries, or resource-level
  conditions (e.g. `aws:username` scoping) — a rule may flag a permission
  that is actually safely scoped by a condition. Manually verify criticals.
- `NotAction` statements are tracked but not fully logic-evaluated.
- Cross-account trust resolution only matches principals already present
  in the collected inventory (same account) — cross-account role chains to
  external accounts are not currently resolved.
- This is v1 — a solid foundation for AWS. Azure/GCP support would be a
  logical next phase.

## Testing without touching real AWS

```bash
python main.py --offline-inventory tests/sample_inventory.json --output-dir ./reports
```

This runs the full pipeline against synthetic data so you can validate
behavior and demo the tool without any AWS account at all.
