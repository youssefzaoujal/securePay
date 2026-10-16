# =============================================================================
# SecurePay - Terraform Configuration (AWS)
# Phase 5: Infrastructure as Code
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.68"
    }
  }

  # Backend distant (décommenter en production)
  # backend "s3" {
  #   bucket = "securepay-terraform-state"
  #   key    = "terraform.tfstate"
  #   region = "eu-west-1"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SecurePay"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# --- Variables ---
variable "aws_region" {
  default = "eu-west-1"
}

variable "environment" {
  default = "dev"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "db_password" {
  sensitive = true
}

# --- VPC ---
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "securepay-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "securepay-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "securepay-public-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "securepay-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Name = "securepay-private-b" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "securepay-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "securepay-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags          = { Name = "securepay-nat" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "securepay-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "securepay-private-rt" }
}

# --- RDS PostgreSQL (PCI-DSS Req 3: chiffrement au repos) ---
resource "aws_db_subnet_group" "main" {
  name       = "securepay-db"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { Name = "securepay-db-subnet-group" }
}

resource "aws_security_group" "rds" {
  name_prefix = "securepay-rds-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "securepay-rds-sg" }
}

resource "aws_db_instance" "main" {
  identifier     = "securepay-db"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.medium"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true  # PCI-DSS Req 3

  db_name  = "securepay"
  username = "securepay"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az               = true
  backup_retention_period = 7
  skip_final_snapshot    = var.environment != "production"
  deletion_protection    = var.environment == "production"

  tags = { Name = "securepay-db" }
}

# --- ElastiCache Redis ---
resource "aws_security_group" "redis" {
  name_prefix = "securepay-redis-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "securepay-redis-sg" }
}

resource "aws_elasticache_cluster" "main" {
  cluster_id      = "securepay-redis"
  engine          = "redis"
  engine_version  = "7.0"
  node_type       = "cache.t3.medium"
  num_cache_nodes = 1
  port            = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = { Name = "securepay-redis" }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "securepay-redis"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

# --- EKS Cluster ---
resource "aws_eks_cluster" "main" {
  name     = "securepay-${var.environment}"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public_a.id,
      aws_subnet.public_b.id,
      aws_subnet.private_a.id,
      aws_subnet.private_b.id,
    ]
  }

  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }

  tags = { Name = "securepay-eks" }
}

resource "aws_kms_key" "eks" {
  description = "SecurePay EKS Secrets Encryption"
}

resource "aws_iam_role" "eks" {
  name = "securepay-eks-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_policy" {
  role       = aws_iam_role.eks.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# --- S3 pour logs ---
resource "aws_s3_bucket" "logs" {
  bucket = "securepay-logs-${var.environment}"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# --- Outputs ---
output "vpc_id" { value = aws_vpc.main.id }
output "rds_endpoint" { value = aws_db_instance.main.endpoint }
output "redis_endpoint" { value = aws_elasticache_cluster.main.cache_nodes[0].address }
output "eks_cluster_name" { value = aws_eks_cluster.main.name }
output "logs_bucket" { value = aws_s3_bucket.logs.bucket }
