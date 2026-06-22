variable "region" {
  description = "AWS region for the staging environment."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the staging VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for staging public subnets."
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for staging private subnets."
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "availability_zones" {
  description = "AZs to spread subnets across in staging."
  type        = list(string)
  default     = []
}

variable "db_instance_class" {
  description = "RDS instance class for staging."
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB for the staging datastore."
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "Postgres major version for staging."
  type        = string
  default     = "18"
}

variable "db_name" {
  description = "Database name for staging."
  type        = string
  default     = "infra_twin"
}

variable "db_username" {
  description = "DB master username for staging. Supplied at deploy time."
  type        = string
}

variable "db_password_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the staging DB master password."
  type        = string
}

variable "api_image" {
  description = "API container image repository for staging."
  type        = string
}

variable "api_image_tag" {
  description = "API container image tag for staging (injected by CI pipeline)."
  type        = string
}

variable "api_container_port" {
  description = "Port the staging API container listens on."
  type        = number
  default     = 8000
}

variable "api_desired_count" {
  description = "Number of API task replicas in staging."
  type        = number
  default     = 1
}

variable "api_cpu" {
  description = "CPU units for the staging API task."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memory (MiB) for the staging API task."
  type        = number
  default     = 1024
}
