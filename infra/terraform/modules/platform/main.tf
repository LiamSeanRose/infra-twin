provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

# Fetch available AZs in the region for use when var.availability_zones is empty.
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Use the caller-supplied AZ list, or fall back to the first N available AZs.
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(
    data.aws_availability_zones.available.names,
    0,
    max(length(var.public_subnet_cidrs), length(var.private_subnet_cidrs)),
  )

  name_prefix = "infra-twin-${var.environment}"
}

# Fetch the DB password from Secrets Manager at apply time.
# The password VALUE is never stored in any .tf or .tfvars file; only the ARN is referenced.
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = var.db_password_secret_arn
}

# ---------------------------------------------------------------------------
# Network: VPC
# ---------------------------------------------------------------------------

resource "aws_vpc" "platform" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${local.name_prefix}-vpc"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network: Internet gateway
# ---------------------------------------------------------------------------

resource "aws_internet_gateway" "platform" {
  vpc_id = aws_vpc.platform.id

  tags = {
    Name        = "${local.name_prefix}-igw"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network: Public subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.platform.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index % length(local.azs)]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${local.name_prefix}-public-${count.index}"
    Environment = var.environment
    Tier        = "public"
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network: Private subnets
# ---------------------------------------------------------------------------

resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.platform.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index % length(local.azs)]

  tags = {
    Name        = "${local.name_prefix}-private-${count.index}"
    Environment = var.environment
    Tier        = "private"
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Network: Route tables
# ---------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.platform.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.platform.id
  }

  tags = {
    Name        = "${local.name_prefix}-public-rt"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.platform.id

  tags = {
    Name        = "${local.name_prefix}-private-rt"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "api" {
  name        = "${local.name_prefix}-api-sg"
  description = "Security group for the infra-twin API ECS service"
  vpc_id      = aws_vpc.platform.id

  ingress {
    description = "API container port — scoped to VPC CIDR; tighten to an ALB SG once an ALB is introduced"
    from_port   = var.api_container_port
    to_port     = var.api_container_port
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.platform.cidr_block]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${local.name_prefix}-api-sg"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-db-sg"
  description = "Security group for the infra-twin Postgres/AGE managed datastore"
  vpc_id      = aws_vpc.platform.id

  ingress {
    description     = "Postgres from API service"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${local.name_prefix}-db-sg"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ---------------------------------------------------------------------------
# Datastore: managed Postgres + AGE
#
# This is the single PostgreSQL database that the platform connects to at
# runtime via DATABASE_URL and ADMIN_DATABASE_URL. Apache AGE is installed
# as an extension on this instance — not a separate service.
#
# The DB password VALUE is read from Secrets Manager (data source above);
# it is never stored in HCL, .tfvars, or any committed file.
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "platform" {
  name        = "${local.name_prefix}-db-subnet-group"
  description = "Subnet group for the infra-twin Postgres/AGE managed datastore"
  subnet_ids  = aws_subnet.private[*].id

  tags = {
    Name        = "${local.name_prefix}-db-subnet-group"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_db_instance" "platform_postgres_age" {
  identifier        = "${local.name_prefix}-postgres-age"
  engine            = "postgres"
  engine_version    = var.db_engine_version
  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage

  db_name  = var.db_name
  username = var.db_username

  # Password is fetched at apply time from Secrets Manager via the data source above.
  # The password value is NEVER stored in any .tf or .tfvars file.
  password = data.aws_secretsmanager_secret_version.db_password.secret_string

  db_subnet_group_name   = aws_db_subnet_group.platform.name
  vpc_security_group_ids = [aws_security_group.db.id]

  publicly_accessible = false
  multi_az            = var.environment == "prod" ? true : false
  skip_final_snapshot = var.environment == "prod" ? false : true

  # Encryption at rest — must be set before the first apply; cannot be changed in place.
  storage_encrypted = true

  # Automated backups — 7 days for staging, 14 days for prod.
  backup_retention_period = var.environment == "prod" ? 14 : 7

  # Prevent accidental deletion of the production database via Terraform.
  deletion_protection = var.environment == "prod" ? true : false

  # Propagate resource tags to automated snapshots for ownership tracking.
  copy_tags_to_snapshot = true

  tags = {
    Name        = "${local.name_prefix}-postgres-age"
    Environment = var.environment
    ManagedBy   = "terraform"
    Note        = "Apache AGE graph extension runs on this Postgres instance"
  }
}

# ---------------------------------------------------------------------------
# Compute: ECS cluster + task definition + service running the API container
#
# image built by the root Dockerfile (#31b-i)
#
# The container image is referenced only via variables — the repo and tag are
# NEVER hardcoded. The git-SHA tag is injected by the CI pipeline at deploy
# time via the api_image_tag variable.
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "platform" {
  name = "${local.name_prefix}-cluster"

  tags = {
    Name        = "${local.name_prefix}-cluster"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "${local.name_prefix}-ecs-task-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })

  tags = {
    Name        = "${local.name_prefix}-ecs-task-exec-role"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${local.name_prefix}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.api_cpu)
  memory                   = tostring(var.api_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  # image built by the root Dockerfile (#31b-i)
  # The image is referenced as repo:tag where both repo and tag come from variables.
  # The git-SHA tag is supplied by the CI pipeline at deploy time — never hardcoded.
  container_definitions = jsonencode([
    {
      name  = "api"
      image = "${var.api_image}:${var.api_image_tag}"

      portMappings = [
        {
          containerPort = var.api_container_port
          hostPort      = var.api_container_port
          protocol      = "tcp"
        }
      ]

      environment = [
        # DATABASE_URL and ADMIN_DATABASE_URL are injected at runtime from the
        # task's execution environment — they are NEVER hardcoded here.
        {
          name  = "PORT"
          value = tostring(var.api_container_port)
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${local.name_prefix}-api"
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "api"
        }
      }

      essential = true
    }
  ])

  tags = {
    Name        = "${local.name_prefix}-api-task"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_ecs_service" "api" {
  name            = "${local.name_prefix}-api"
  cluster         = aws_ecs_cluster.platform.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_task_execution]

  tags = {
    Name        = "${local.name_prefix}-api-service"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
