output "cluster_arn" {
  value       = aws_ecs_cluster.ziro.arn
  description = "ECS cluster ARN"
}

output "service_name" {
  value       = aws_ecs_service.ziro.name
  description = "ECS service name"
}

output "security_group_id" {
  value       = aws_security_group.ziro.id
  description = "Security group ID for the panel"
}

output "secret_arn" {
  value       = aws_secretsmanager_secret.llm_api_key.arn
  description = "ARN of the LLM API key secret"
}

output "efs_id" {
  value       = var.persistence_enabled ? aws_efs_file_system.workspace[0].id : null
  description = "EFS file system ID (if persistence enabled)"
}

output "log_group" {
  value       = aws_cloudwatch_log_group.ziro.name
  description = "CloudWatch Log Group for panel logs"
}
