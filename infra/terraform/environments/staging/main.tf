terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Placeholder values — replace with real bucket/table names before running apply.
    # No secrets belong here; the backend config is committed as-is.
    bucket         = "infra-twin-tfstate"
    key            = "platform/staging/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "infra-twin-tflock"
    encrypt        = true
  }
}

module "platform" {
  source = "../../modules/platform"

  region      = var.region
  environment = "staging"

  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones

  db_instance_class      = var.db_instance_class
  db_allocated_storage   = var.db_allocated_storage
  db_engine_version      = var.db_engine_version
  db_name                = var.db_name
  db_username            = var.db_username
  db_password_secret_arn = var.db_password_secret_arn

  api_image          = var.api_image
  api_image_tag      = var.api_image_tag
  api_container_port = var.api_container_port
  api_desired_count  = var.api_desired_count
  api_cpu            = var.api_cpu
  api_memory         = var.api_memory
}
