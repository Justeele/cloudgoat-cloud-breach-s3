# Attack Flow: cloud_breach_s3

## Overview

This diagram shows the full attack chain used in this lab — from the initial SSRF vulnerability to full S3 data exfiltration.

```mermaid
flowchart TD
    A([Attacker]) -->|HTTP request with\nmodified Host header| B

    subgraph EC2 ["EC2 Instance (3.239.172.114)"]
        B[Vulnerable Web App\nSSRF Entry Point]
        B -->|Proxies request to\n169.254.169.254| C[EC2 Metadata Service\nIMDS v1]
        C -->|Returns IAM role name| B
        C -->|Returns temporary credentials\nAccessKeyId + SecretKey + Token| B
    end

    B -->|Credentials returned\nto attacker| A

    A -->|Configures stolen credentials\naws configure --profile stolen| D[AWS CLI\nAttacker Machine]

    D -->|aws s3 ls| E[(S3: cg-cardholder-data-bucket)]
    D -->|aws s3 cp --recursive| E

    E -->|Exfiltrates 3 CSV files\n1,500+ records| A

    style A fill:#dc2626,color:#fff
    style B fill:#f59e0b,color:#fff
    style C fill:#f59e0b,color:#fff
    style D fill:#dc2626,color:#fff
    style E fill:#7c3aed,color:#fff
```

---

## Step-by-Step

| Step | Action | Result |
|------|--------|--------|
| 1 | Send HTTP request to EC2 with `Host: 169.254.169.254` | SSRF triggers, app proxies to IMDS |
| 2 | Query `/latest/meta-data/iam/security-credentials/` | IAM role name returned |
| 3 | Query `/latest/meta-data/iam/security-credentials/<role>` | Temporary AWS credentials returned |
| 4 | Load credentials into local AWS CLI profile | Now acting as the EC2's IAM role |
| 5 | `aws s3 ls` | Cardholder data bucket discovered |
| 6 | `aws s3 cp --recursive` | Full bucket exfiltrated |

---

## Why This Works

Three misconfigurations stacked on top of each other:

1. **IMDSv1 enabled** — No session token required, SSRF can query IMDS directly
2. **Overly permissive IAM role** — WAF role had `s3:GetObject` on sensitive data it never needed
3. **No S3 bucket policy** — Nothing restricted access to the bucket by IP, VPC endpoint, or principal

Remove any one of these and the attack either fails or the blast radius shrinks significantly.

---

## Detection Points

```mermaid
flowchart LR
    A[SSRF Request] -->|App logs| B[WAF / App Logs]
    C[IMDS Query] -->|Not logged by default\nBlind spot| D[❌ No native log]
    E[aws s3 ls / cp\nfrom external IP] -->|CloudTrail| F[GuardDuty Alert\nUnauthorizedAccess:\nIAMUser/InstanceCredentialExfiltration]

    style D fill:#dc2626,color:#fff
    style F fill:#16a34a,color:#fff
```

The credential theft itself (IMDS query) leaves no CloudTrail log — it happens at the instance level. GuardDuty catches the downstream use of the credentials from an external IP.
```
