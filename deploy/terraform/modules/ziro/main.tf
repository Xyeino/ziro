terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# --------------------------------------------------------------------
# VPC / networking — caller can pass existing VPC or use defaults
# --------------------------------------------------------------------

data "aws_vpc" "default" {
  count   = var.vpc_id == null ? 1 : 0
  default = true
}

locals {
  vpc_id     = var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.default[0].ids
}

data "aws_subnets" "default" {
  count = var.vpc_id == null ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

# --------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------

resource "aws_secretsmanager_secret" "llm_api_key" {
  name        = "${var.name}-llm-api-key"
  description = "Ziro LLM provider API key"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "llm_api_key" {
  secret_id     = aws_secretsmanager_secret.llm_api_key.id
  secret_string = var.llm_api_key
}

# --------------------------------------------------------------------
# Security groups
# --------------------------------------------------------------------

resource "aws_security_group" "ziro" {
  name        = "${var.name}-sg"
  description = "Ziro panel + DinD"
  vpc_id      = local.vpc_id
  tags        = var.tags

  ingress {
    from_port   = 8420
    to_port     = 8420
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
    description = "Panel HTTP"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound to LLM provider + scan targets"
  }
}

# --------------------------------------------------------------------
# EFS — persistent /workspace
# --------------------------------------------------------------------

resource "aws_efs_file_system" "workspace" {
  count          = var.persistence_enabled ? 1 : 0
  creation_token = "${var.name}-workspace"
  encrypted      = true
  tags           = var.tags
}

resource "aws_efs_mount_target" "workspace" {
  for_each        = var.persistence_enabled ? toset(local.subnet_ids) : []
  file_system_id  = aws_efs_file_system.workspace[0].id
  subnet_id       = each.value
  security_groups = [aws_security_group.ziro.id]
}

# --------------------------------------------------------------------
# IAM
# --------------------------------------------------------------------

resource "aws_iam_role" "task_execution" {
  name = "${var.name}-exec"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "exec_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "secrets_read" {
  name = "${var.name}-secrets-read"
  role = aws_iam_role.task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.llm_api_key.arn]
    }]
  })
}

# --------------------------------------------------------------------
# CloudWatch Logs
# --------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ziro" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# --------------------------------------------------------------------
# ECS cluster + task + service
# --------------------------------------------------------------------

resource "aws_ecs_cluster" "ziro" {
  name = var.name
  tags = var.tags
}

resource "aws_ecs_task_definition" "ziro" {
  family                   = var.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task_execution.arn
  tags                     = var.tags

  container_definitions = jsonencode([
    {
      name      = "panel"
      image     = var.image
      essential = true
      command   = ["ziro", "--panel"]
      portMappings = [{
        containerPort = 8420
        protocol      = "tcp"
      }]
      environment = [
        { name = "ZIRO_LLM", value = var.llm_model },
        { name = "ZIRO_SCOPE_ENFORCE", value = "1" },
        { name = "ZIRO_TOOL_FAILURE_BUDGET", value = tostring(var.tool_failure_budget) },
        { name = "ZIRO_CHECKPOINT_INTERVAL", value = tostring(var.checkpoint_interval) },
        { name = "ZIRO_TOOL_CACHE_TTL", value = tostring(var.tool_cache_ttl) },
      ]
      secrets = [{
        name      = "LLM_API_KEY"
        valueFrom = aws_secretsmanager_secret.llm_api_key.arn
      }]
      mountPoints = var.persistence_enabled ? [{
        sourceVolume  = "workspace"
        containerPath = "/workspace"
      }] : []
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ziro.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "panel"
        }
      }
    }
  ])

  dynamic "volume" {
    for_each = var.persistence_enabled ? [1] : []
    content {
      name = "workspace"
      efs_volume_configuration {
        file_system_id = aws_efs_file_system.workspace[0].id
      }
    }
  }
}

data "aws_region" "current" {}

resource "aws_ecs_service" "ziro" {
  name             = var.name
  cluster          = aws_ecs_cluster.ziro.id
  task_definition  = aws_ecs_task_definition.ziro.arn
  desired_count    = 1
  launch_type      = "FARGATE"
  platform_version = "LATEST"
  tags             = var.tags

  network_configuration {
    subnets          = local.subnet_ids
    security_groups  = [aws_security_group.ziro.id]
    assign_public_ip = var.assign_public_ip
  }

  depends_on = [
    aws_iam_role_policy.secrets_read,
  ]
}
