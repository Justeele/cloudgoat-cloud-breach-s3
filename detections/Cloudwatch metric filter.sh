#!/bin/bash
# =============================================================================
# Detection: S3 Cardholder Data Access via Stolen IAM Credentials
# Scenario:  CloudGoat cloud_breach_s3
# Author:    Justin Steele
#
# What this detects:
#   - S3 GetObject calls on buckets matching "*cardholder*"
#   - Bulk S3 downloads (high ListBucket volume)
#   - IAM role credentials used from an external IP (IMDS theft pattern)
#
# Requirements:
#   - CloudTrail enabled with S3 data events on
#   - CloudWatch Log Group receiving CloudTrail logs
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
LOG_GROUP="/aws/cloudtrail/logs"        # Update to your CloudTrail log group
ALARM_EMAIL="security@yourcompany.com"  # Update to your security team email
REGION="us-east-1"
SNS_TOPIC_NAME="security-alerts"
# ─────────────────────────────────────────────────────────────────────────────

echo "[*] Creating SNS topic for alerts..."
SNS_TOPIC_ARN=$(aws sns create-topic \
  --name "$SNS_TOPIC_NAME" \
  --region "$REGION" \
  --query 'TopicArn' \
  --output text)

aws sns subscribe \
  --topic-arn "$SNS_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint "$ALARM_EMAIL" \
  --region "$REGION"

echo "[+] SNS topic created: $SNS_TOPIC_ARN"
echo "[!] Check $ALARM_EMAIL to confirm the subscription"

# ── Detection 1: Cardholder S3 GetObject ─────────────────────────────────────
echo ""
echo "[*] Creating metric filter: S3 access on cardholder buckets..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "CardholderS3GetObject" \
  --filter-pattern '{ ($.eventName = "GetObject") && ($.requestParameters.bucketName = "*cardholder*") }' \
  --metric-transformations \
    metricName=CardholderS3GetObject,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-CardholderS3Access" \
  --alarm-description "S3 GetObject on cardholder data bucket - possible exfiltration" \
  --metric-name "CardholderS3GetObject" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-CardholderS3Access"

# ── Detection 2: Bulk S3 Enumeration ─────────────────────────────────────────
echo ""
echo "[*] Creating metric filter: Bulk S3 list operations..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "BulkS3ListBucket" \
  --filter-pattern '{ $.eventName = "ListBucket" }' \
  --metric-transformations \
    metricName=S3ListBucketCount,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-BulkS3Enumeration" \
  --alarm-description "High volume S3 ListBucket calls - possible enumeration or exfiltration" \
  --metric-name "S3ListBucketCount" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 20 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-BulkS3Enumeration"

# ── Detection 3: EC2 Instance Credentials Used from External IP ───────────────
echo ""
echo "[*] Creating metric filter: Instance credentials used externally..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IMDSCredentialExternalUse" \
  --filter-pattern '{ ($.userIdentity.type = "AssumedRole") && ($.userIdentity.sessionContext.sessionIssuer.type = "Role") && ($.sourceIPAddress != "*.amazonaws.com") && ($.sourceIPAddress != "169.254.*") }' \
  --metric-transformations \
    metricName=ExternalCredentialUse,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-ExternalIMDSCredentialUse" \
  --alarm-description "IAM role credentials used from external IP - possible IMDS credential theft" \
  --metric-name "ExternalCredentialUse" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-ExternalIMDSCredentialUse"

echo ""
echo "============================================="
echo " Detection setup complete"
echo "============================================="
echo " Alarms created:"
echo "   - ALERT-CardholderS3Access"
echo "   - ALERT-BulkS3Enumeration"
echo "   - ALERT-ExternalIMDSCredentialUse"
echo ""
echo " TIP: GuardDuty catches this attack out of the box."
echo " Enable it with: aws guardduty create-detector --enable"
echo "============================================="
