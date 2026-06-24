#!/bin/bash
# =============================================================================
# Remediation: Enforce IMDSv2 on EC2 Instances
# Scenario:    CloudGoat cloud_breach_s3
# Author:      Justin Steele
#
# What this does:
#   - Enforces IMDSv2 (http-tokens=required) on all running EC2 instances
#   - IMDSv2 requires a session-oriented PUT request before metadata can be
#     read, which breaks SSRF-based IMDS attacks entirely
#
# Why this matters:
#   - IMDSv1 allows any HTTP GET to read instance metadata
#   - SSRF vulnerabilities can proxy GET requests → credential theft
#   - IMDSv2 requires a PUT + token, which SSRF can't replicate
#   - This is the single most impactful fix for this attack class
# =============================================================================

set -euo pipefail

REGION="${1:-us-east-1}"

echo "[*] Enforcing IMDSv2 on all running EC2 instances in region: $REGION"
echo ""

# Get all running instance IDs
INSTANCE_IDS=$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId" \
  --output text)

if [ -z "$INSTANCE_IDS" ]; then
  echo "[!] No running instances found in $REGION"
  exit 0
fi

COUNT=0
for INSTANCE_ID in $INSTANCE_IDS; do
  echo "[*] Updating $INSTANCE_ID..."
  aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens required \
    --http-endpoint enabled \
    --region "$REGION" \
    --output text > /dev/null
  echo "[+] $INSTANCE_ID — IMDSv2 enforced"
  COUNT=$((COUNT + 1))
done

echo ""
echo "============================================="
echo " Done. Updated $COUNT instance(s)."
echo "============================================="

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Verifying IMDSv2 status..."
aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].[InstanceId, MetadataOptions.HttpTokens, MetadataOptions.HttpEndpoint]" \
  --output table

# ── Org-Wide Prevention (optional) ───────────────────────────────────────────
echo ""
echo "============================================="
echo " Optional: Enforce IMDSv2 org-wide"
echo "============================================="
echo ""
echo " 1. AWS Config Rule (flags non-compliant instances):"
echo "    aws configservice put-config-rule --config-rule file://imdsv2-config-rule.json"
echo ""
echo " 2. SCP to deny RunInstances without IMDSv2:"
cat << 'SCP'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
SCP
echo ""
echo " Apply the SCP above via AWS Organizations to prevent"
echo " any new instance from launching without IMDSv2."
echo "============================================="
