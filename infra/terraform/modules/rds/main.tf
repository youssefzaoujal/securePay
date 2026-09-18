# =============================================================================
# RDS Module - SecurePay (PostgreSQL)
# PCI-DSS Req 3: Chiffrement au repos
# =============================================================================

variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "db_password" { type = string }
variable "enable_deletion_protection" { type = bool }

locals {
  identifier = "${var.project}-${var.environment}"
}

# --- Security Group ---
resource "aws_security_group" "rds" {
  name_prefix = "${local.identifier}-rds-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = []  # Rempli par le module EKS
    description     = "PostgreSQL from EKS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.identifier}-rds-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# --- Subnet Group ---
resource "aws_db_subnet_group" "main" {
  name       = local.identifier
  subnet_ids = var.private_subnet_ids
  tags       = { Name = "${local.identifier}-db-subnet-group" }
}

# --- Parameter Group ---
resource "aws_db_parameter_group" "main" {
  family = "postgres15"
  name   = local.identifier

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  tags = { Name = "${local.identifier}-params" }
}

# --- RDS Instance (PCI-DSS: encrypted, Multi-AZ, logging) ---
resource "aws_db_instance" "main" {
  identifier = local.identifier

  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.medium"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true  # PCI-DSS Req 3.4

  db_name  = "securepay"
  username = "securepay"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.main.name

  multi_az               = var.environment == "production"  # HA en production
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  skip_final_snapshot  = var.environment != "production"
  deletion_protection  = var.enable_deletion_protection

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name        = local.identifier
    Environment = var.environment
  }
}

# --- ElastiCache Redis ---
resource "aws_security_group" "redis" {
  name_prefix = "${local.identifier}-redis-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = []
    description     = "Redis from EKS"
  }

  tags = { Name = "${local.identifier}-redis-sg" }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = local.identifier
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_cluster" "main" {
  cluster_id      = local.identifier
  engine          = "redis"
  engine_version  = "7.0"
  node_type       = "cache.t3.medium"
  num_cache_nodes = 1
  port            = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = { Name = local.identifier }
}

# --- Outputs ---
output "rds_endpoint" { value = aws_db_instance.main.endpoint }
output "rds_port" { value = aws_db_instance.main.port }
output "redis_endpoint" { value = aws_elasticache_cluster.main.cache_nodes[0].address }
output "redis_port" { value = aws_elasticache_cluster.main.port }
output "rds_security_group_id" { value = aws_security_group.rds.id }
output "redis_security_group_id" { value = aws_security_group.redis.id }
