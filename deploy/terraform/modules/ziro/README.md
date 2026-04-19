# Ziro Terraform Module (AWS ECS Fargate)

Deploys Ziro panel on AWS ECS Fargate with EFS-backed persistent workspace and Secrets-Manager-managed LLM credentials.

## Usage

```hcl
module "ziro" {
  source = "github.com/Xyeino/ziro//deploy/terraform/modules/ziro"

  name        = "ziro-prod"
  llm_model   = "openai/gpt-5.4"
  llm_api_key = var.openai_api_key  # Keep in .tfvars or TF_VAR_ env

  allowed_ingress_cidrs = ["10.0.0.0/16"]  # lock panel access

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

output "panel_security_group" {
  value = module.ziro.security_group_id
}
```

## Required variables

- `llm_model` — e.g. `openai/gpt-5.4`, `xai/grok-4-1-fast-reasoning`
- `llm_api_key` — stored in Secrets Manager, **mark sensitive in your root module**

## What it creates

- ECS Fargate cluster + task + service (1 replica)
- Security group (port 8420 ingress)
- CloudWatch Log Group for panel logs
- Secrets Manager entry for LLM API key
- EFS file system + mount targets for persistent `/workspace` (optional)
- IAM task execution role with read access to the Secrets Manager entry

## DinD note

Fargate doesn't allow privileged containers, so DinD isn't supported in this module. To spawn sandbox containers you need to either:

1. Run panel on EC2 launch type with `aws_ecs_task_definition` using `privileged: true`
2. Use a separate Docker-capable instance and pass `DOCKER_HOST=tcp://<host>:2375` as env
3. Use ECS + Fargate for panel UI only, and route tool execution to a separate compute pool

This module is optimized for option 3 — it runs the panel fine for demo/dev use, but for real scans you'll want to chain it with additional infrastructure for sandbox execution.

## Destroy

```bash
terraform destroy
```

EFS and Secret are removed. Make sure you've downloaded any scan artifacts first.
