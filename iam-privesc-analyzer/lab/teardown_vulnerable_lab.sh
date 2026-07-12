#!/usr/bin/env bash
# Copyright (c) AKID's Global Cybersecurity Tools
# teardown_vulnerable_lab.sh
#
# Removes everything created by setup_vulnerable_lab.sh. Run this as soon
# as you're done demoing — do not leave over-permissioned test identities
# active in any AWS account.

set -e
PROFILE="lab-admin"
echo "Tearing down lab environment using profile: $PROFILE"

echo "Removing dev-intern..."
aws iam delete-user-policy --user-name dev-intern --policy-name self-escalate --profile $PROFILE 2>/dev/null || true
aws iam delete-user --user-name dev-intern --profile $PROFILE 2>/dev/null || true

echo "Removing ci-deploy-user..."
aws iam delete-user-policy --user-name ci-deploy-user --policy-name deploy-perms --profile $PROFILE 2>/dev/null || true
aws iam delete-user --user-name ci-deploy-user --profile $PROFILE 2>/dev/null || true

echo "Removing lambda-exec-role..."
aws iam detach-role-policy --role-name lambda-exec-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile $PROFILE 2>/dev/null || true
aws iam delete-role --role-name lambda-exec-role --profile $PROFILE 2>/dev/null || true

echo "Removing readonly-analyst..."
aws iam detach-user-policy --user-name readonly-analyst \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess --profile $PROFILE 2>/dev/null || true
aws iam delete-user --user-name readonly-analyst --profile $PROFILE 2>/dev/null || true

rm -f /tmp/dev-intern-policy.json /tmp/ci-deploy-policy.json /tmp/lambda-trust.json

echo
echo "Lab environment removed. Verify with:"
echo "  aws iam list-users --profile $PROFILE"
