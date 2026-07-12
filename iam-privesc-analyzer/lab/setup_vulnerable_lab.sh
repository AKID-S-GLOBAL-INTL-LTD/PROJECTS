#!/usr/bin/env bash
# Copyright (c) AKID's Global Cybersecurity Tools
# setup_vulnerable_lab.sh
#
# Creates a small, DELIBERATELY over-permissioned IAM environment for
# demoing the IAM Privilege Escalation Path Analyzer. Run only in a
# sandbox/test AWS account you own. Pair with teardown_vulnerable_lab.sh.

set -e
PROFILE="lab-admin"
echo "Using AWS profile: $PROFILE"
ACCOUNT_ID=$(aws sts get-caller-identity --profile $PROFILE --query Account --output text)
echo "Account: $ACCOUNT_ID"
echo

# ---------------------------------------------------------------------
# Scenario 1 (PE01): "dev-intern" — has iam:CreatePolicyVersion.
# Anyone with this can set a new default policy version on ANY managed
# policy, including attaching full "*" permissions to themselves.
# ---------------------------------------------------------------------
echo "[1/3] Creating dev-intern (CreatePolicyVersion escalation)..."
aws iam create-user --user-name dev-intern --profile $PROFILE || true

cat > /tmp/dev-intern-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:CreatePolicyVersion", "iam:ListPolicies", "iam:GetPolicy", "iam:ListPolicyVersions"],
      "Resource": "*"
    }
  ]
}
EOF
aws iam put-user-policy --user-name dev-intern --policy-name self-escalate \
  --policy-document file:///tmp/dev-intern-policy.json --profile $PROFILE

# ---------------------------------------------------------------------
# Scenario 2 (PE14/15): "ci-deploy-user" — has PassRole + Lambda create/invoke.
# Can create a Lambda function, pass it a privileged execution role, and
# run arbitrary code as that role.
# ---------------------------------------------------------------------
echo "[2/3] Creating ci-deploy-user + lambda-exec-role (PassRole+Lambda escalation)..."
aws iam create-user --user-name ci-deploy-user --profile $PROFILE || true

cat > /tmp/ci-deploy-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction"],
      "Resource": "*"
    }
  ]
}
EOF
aws iam put-user-policy --user-name ci-deploy-user --policy-name deploy-perms \
  --policy-document file:///tmp/ci-deploy-policy.json --profile $PROFILE

cat > /tmp/lambda-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
  ]
}
EOF
aws iam create-role --role-name lambda-exec-role \
  --assume-role-policy-document file:///tmp/lambda-trust.json --profile $PROFILE || true
aws iam attach-role-policy --role-name lambda-exec-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile $PROFILE

# ---------------------------------------------------------------------
# Scenario 3 (control group): "readonly-analyst" — genuinely scoped down,
# no escalation path. Included so your demo shows the tool does NOT
# flag identities that are actually fine (avoids false-positive optics).
# ---------------------------------------------------------------------
echo "[3/3] Creating readonly-analyst (clean control identity)..."
aws iam create-user --user-name readonly-analyst --profile $PROFILE || true
aws iam attach-user-policy --user-name readonly-analyst \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --profile $PROFILE

echo
echo "Lab environment created:"
echo "  - dev-intern          -> CreatePolicyVersion escalation path"
echo "  - ci-deploy-user       -> PassRole+Lambda escalation path (via lambda-exec-role)"
echo "  - readonly-analyst     -> clean, no escalation path (control)"
echo
echo "Next: run the analyzer against this account using your READ-ONLY"
echo "iam-scanner profile (not lab-admin):"
echo "  python main.py --profile iam-scanner --output-dir ./reports"
