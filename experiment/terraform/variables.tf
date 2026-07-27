# experiment/terraform/variables.tf

variable "region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-1"
}

variable "account_id" {
  description = "AWS account ID (used in bucket names)"
  type        = string
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}
