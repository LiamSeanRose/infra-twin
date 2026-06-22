variable "region" {
  description = "AWS region for the production environment."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the production VPC."
  type        = string
  default     = "10.1.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for production public subnets."
  type        = list(string)
  default     = ["10.1.0.0/24", "10.1.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for production private subnets."
  type        = list(string)
  default     = ["10.1.10.0/24", "10.1.11.0/24"]
}

variable "availability_zones" {
  description = "AZs to spread subnets across in production."
  type        = list(string)
  default     = []
}

variable "db_instance_class" {
  description = "RDS instance class for production."
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB for the production datastore."
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "Postgres major version for production."
  type        = string
  default     = "18"
}

variable "db_name" {
  description = "Database name for production."
  type        = string
  default     = "infra_twin"
}

variable "db_username" {
  description = "DB master username for production. Supplied at deploy time."
  type        = string
}

variable "db_password_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the production DB master password."
  type        = string
}

variable "api_image" {
  description = "API container image repository for production."
  type        = string
}

variable "api_image_tag" {
  description = "API container image tag for production (injected by CI pipeline)."
  type        = string
}

variable "api_container_port" {
  description = "Port the production API container listens on."
  type        = number
  default     = 8000
}

variable "api_desired_count" {
  description = "Number of API task replicas in production."
  type        = number
  default     = 2
}

variable "api_cpu" {
  description = "CPU units for the production API task."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memory (MiB) for the production API task."
  type        = number
  default     = 1024
}
