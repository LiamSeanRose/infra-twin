variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "environment" {
  description = "Environment name, e.g. 'staging' or 'prod'. Used in resource naming."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the platform VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)."
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ)."
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "availability_zones" {
  description = "Availability zones to spread subnets across. If empty, subnets use index-based AZ selection."
  type        = list(string)
  default     = []
}

variable "db_instance_class" {
  description = "RDS instance class for the managed Postgres/AGE datastore."
  type        = string
  default     = "db.t3.medium"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB for the managed Postgres/AGE datastore."
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "Postgres major engine version. AGE runs on Postgres 18."
  type        = string
  default     = "18"
}

variable "db_name" {
  description = "Name of the initial database created in the managed Postgres instance."
  type        = string
  default     = "infra_twin"
}

variable "db_username" {
  description = "Master username for the managed Postgres/AGE datastore. Supplied at deploy time — no default."
  type        = string
  # No default: caller must supply. Password value is NEVER a variable; only the secret ARN is.
}

variable "db_password_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret that holds the DB master password. The password VALUE is never stored in HCL."
  type        = string
  # No default: caller must supply the ARN. The actual password is read at apply time from Secrets Manager.
}

variable "api_image" {
  description = "API container image repository (without tag), e.g. '123456789012.dkr.ecr.us-east-1.amazonaws.com/infra-twin-api'. The git-SHA tag is injected at deploy time via api_image_tag."
  type        = string
  # No default: must be supplied at deploy time. Image is built by the root Dockerfile (#31b-i).
}

variable "api_image_tag" {
  description = "API container image tag (e.g. git SHA). Injected by the CI pipeline at deploy time — never hardcoded."
  type        = string
  # No default: must be supplied at deploy time.
}

variable "api_container_port" {
  description = "Port that the API container listens on."
  type        = number
  default     = 8000
}

variable "api_desired_count" {
  description = "Desired number of ECS task replicas for the API service."
  type        = number
  default     = 2
}

variable "api_cpu" {
  description = "CPU units allocated to each API ECS task (1 vCPU = 1024 units)."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memory (MiB) allocated to each API ECS task."
  type        = number
  default     = 1024
}
