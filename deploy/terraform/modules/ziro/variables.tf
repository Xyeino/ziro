variable "name" {
  type        = string
  description = "Resource prefix name"
  default     = "ziro"
}

variable "image" {
  type        = string
  description = "Ziro Docker image (ghcr.io/xyeino/ziro:latest or your ECR URI)"
  default     = "ghcr.io/xyeino/ziro:latest"
}

variable "llm_model" {
  type        = string
  description = "LLM model identifier (e.g. openai/gpt-5.4)"
}

variable "llm_api_key" {
  type        = string
  sensitive   = true
  description = "API key for LLM provider — stored in Secrets Manager"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID (null = use default VPC)"
  default     = null
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnets for ECS tasks (empty = use default VPC subnets)"
  default     = []
}

variable "allowed_ingress_cidrs" {
  type        = list(string)
  description = "CIDR blocks allowed to reach the panel on port 8420"
  default     = ["0.0.0.0/0"]
}

variable "assign_public_ip" {
  type        = bool
  description = "Assign public IP to Fargate task (needed in public subnets)"
  default     = true
}

variable "task_cpu" {
  type        = string
  description = "Fargate task CPU"
  default     = "2048"
}

variable "task_memory" {
  type        = string
  description = "Fargate task memory MB"
  default     = "8192"
}

variable "persistence_enabled" {
  type        = bool
  description = "Create EFS for persistent /workspace"
  default     = true
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log group retention"
  default     = 30
}

variable "tool_failure_budget" {
  type    = number
  default = 15
}

variable "checkpoint_interval" {
  type    = number
  default = 300
}

variable "tool_cache_ttl" {
  type    = number
  default = 1800
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources"
  default     = {}
}
